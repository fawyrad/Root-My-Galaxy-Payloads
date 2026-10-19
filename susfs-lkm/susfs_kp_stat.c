// SPDX-License-Identifier: GPL-2.0-only
/*
 * susfs_kp_stat.c - the stat family and the dirent rewrite, from kretprobes.
 *
 * Upstream reaches both from a sys_call_table wrapper (susfs_fp_hook): it replaces the table entry,
 * calls the original and post-processes at the wrapper's tail.  That needs a write into the syscall
 * table, which this project's devices refuse - the same refusal that made our lsm_hook.c a kprobe
 * implementation.  So the post-processing runs from a kretprobe on the syscall's own entry function
 * instead, which needs no text patch.
 *
 * ## Why not a sys_exit tracepoint
 *
 * The first version of this file registered one.  It compiled, it loaded, and it did nothing: this
 * kernel has no `syscalls` tracepoint group at all - `/sys/kernel/debug/tracing/events/syscalls`
 * does not exist, so neither `sys_enter` nor `sys_exit` is ever called and `register_trace_sys_exit`
 * arms a tracepoint nothing fires.  Measured on the SM-S938U1 this project's devices are built for;
 * kprobes on the same kernel do work, which is what this module's lsm_hook.c and KernelSU's own
 * setresuid hook rely on.  A kretprobe also costs more - a trap per call rather than a tracepoint -
 * which is why upstream went the other way on GKI; here it is the only mechanism that runs.
 *
 * ## How the number reaches the return handler
 *
 * Not through `ri->rp`: this kernel's `struct kretprobe_instance` has no such member (measured as a
 * compile error on the first attempt), and a layout that differs from the one upstream's kernels use
 * is not something to depend on.  Each syscall gets its own entry handler, which stamps its number
 * (and ABI) into the instance data before capturing the argument registers; the return handler reads
 * them from there.  One handler pair per syscall, no struct walk.
 *
 * ## What makes it work without touching upstream's logic
 *
 *   1. susfs_kstat_post() reads only the buffer argument - args[1] for fstat and getdents64, args[2]
 *      for newfstatat and the compat fstatat64, args[4] for statx (see its own number switch).  The
 *      entry handler copies all six argument registers before the call runs, so the buffer pointer is
 *      captured while it is still a pointer.
 *   2. The listing answer is a byte count, and the return handler hands a shorter one back through
 *      the syscall's return register.  That is exactly what the wrapper does with its `out`.
 *   3. A kretprobe cannot pre-empt the call, so sus_dirent.c's filldir prefilter (which answers
 *      getdents without the kernel ever writing the caller's buffer) stays with the wrapper path.
 *      Here the post-hoc rewrite runs.  The two tells that rewrite leaves - the d_ino = 0 placeholder
 *      and the scrub a PROT_NONE race can fault - are only reachable through the module's own /proc
 *      nodes, and this build does not create those (susfs_expose_proc is compiled to false).
 *
 * Armed only when the wrapper path installed nothing (kstat_hooks_armed == 0).  On a kernel where the
 * table write lands, the wrappers are the cheaper answer and this layer stays off, so no call is ever
 * post-processed twice.
 *
 * ## The one native entry this kernel does not expose
 *
 * Native `fstat` (80) is not covered, and not for want of a probe: this kernel's kallsyms carries no
 * `__arm64_sys_fstat`, `__se_sys_fstat`, `__do_sys_fstat` or `ksys_fstat` at all - read out of
 * /proc/kallsyms (395,915 lines) on the device - while `__arm64_sys_newfstatat`, `__arm64_sys_statx`
 * and `__arm64_sys_getdents64` are all there.  A probe cannot attach to a symbol that does not exist,
 * and the alternative entry points (`vfs_fstat`, `cp_new_stat`) are either filled with a kernel
 * `struct kstat` that the syscall later copies, or inlined; hooking those would need a second spoof
 * implementation, not a second probe.  So an `fstat`-only caller is not spoofed here; `stat`, `ls`,
 * `find` and everything else that goes through newfstatat or statx is.
 *
 * ## The AArch32 entries
 *
 * These exist under their own names and are probed with the same capture: `__arm64_sys_stat64`,
 * `lstat64`, `fstat64` and `fstatat64` (195/196/197/327), and `__arm64_compat_sys_newstat`,
 * `newlstat`, `newfstat` and `getdents` (106/107/108/141).  AArch32 `statx` (397) and `getdents64`
 * (217) need no entry of their own: upstream's own notes record that both map to the native bodies
 * with the same struct layouts, so the native probes above already see those calls.
 *
 * Not exercised: no 32-bit app process was available on the device this was measured on, so these
 * probes were confirmed to register (they appear in /sys/kernel/debug/kprobes/list) but nothing has
 * watched them post-process a call.  Their argument convention is the same pt_regs wrapper as the
 * native entries, which is what makes the shared capture correct rather than a guess.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <asm/syscall.h>
#include <asm/unistd.h>	/* __NR_newfstatat, __NR_fstat, __NR_statx, __NR_getdents64 */

#include "susfs.h"
#include "susfs_log.h"

/*
 * The post-processing, exported by the sed in the build: upstream defines it `static` because only
 * its wrapper tails call it.  Declared with the same __nocfi as the definition - it is reached from a
 * kretprobe, which is not a CFI-instrumented call site.
 */
__nocfi void susfs_kstat_post(long nr, bool compat, const unsigned long *args, long ret, long *out);

/* The wrapper path's armed count, also exported by that sed: 0 means nothing of upstream's own
 * install path is in place, which is when this layer takes over. */
extern int kstat_hooks_armed;

/* One instance's worth: the number this call is, the ABI it came from, and the arguments as they were
 * on entry. */
struct kp_stat_args {
	long nr;
	bool compat;
	unsigned long a[6];
};

static bool kp_armed;

/*
 * Captured before the call runs: the return value lands in regs->regs[0], so reading the argument
 * registers afterwards would hand the spoofers the return value in place of the first argument.
 *
 * The arguments are NOT in the kprobe's own `regs`.  On arm64 a syscall entry function has one
 * parameter - `const struct pt_regs *regs` - so on entry x0 holds the address of the syscall's pt_regs
 * and the caller's arguments are inside that struct.  Reading them from `regs` itself (the first
 * version of this file did) hands back the pointer as the first argument and whatever the wrapper left
 * in x1..x5 as the rest; the stat rewrite then writes into the wrong address and the dirent filter
 * fails its first uaccess, which is exactly the log this was diagnosed from: `dirent rewrite stopped at
 * 0/88 bytes (returned 88)`.
 *
 * `syscall_get_arguments()` gets that struct so the tree's own ABI rules (orig_x0 and the rest) apply
 * to the real arguments rather than to a guess about the register layout.
 */
#define KP_ENTRY(_fn, _nr, _compat)						\
	static int _fn(struct kretprobe_instance *ri, struct pt_regs *regs)	\
	{									\
		struct kp_stat_args *args = (struct kp_stat_args *)ri->data;	\
		struct pt_regs *sys = (struct pt_regs *)regs->regs[0];		\
										\
		args->nr = (_nr);						\
		args->compat = (_compat);					\
		syscall_get_arguments(current, sys, args->a);			\
		return 0;							\
	}

KP_ENTRY(kp_entry_newfstatat, __NR_newfstatat, false)
KP_ENTRY(kp_entry_statx, __NR_statx, false)
KP_ENTRY(kp_entry_getdents64, __NR_getdents64, false)
KP_ENTRY(kp_entry_stat64, 195, true)
KP_ENTRY(kp_entry_lstat64, 196, true)
KP_ENTRY(kp_entry_fstat64, 197, true)
KP_ENTRY(kp_entry_fstatat64, 327, true)
KP_ENTRY(kp_entry_newstat, 106, true)
KP_ENTRY(kp_entry_newlstat, 107, true)
KP_ENTRY(kp_entry_newfstat, 108, true)
KP_ENTRY(kp_entry_getdents, 141, true)

static int kp_stat_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kp_stat_args *args = (struct kp_stat_args *)ri->data;
	long ret;
	long out;

	if (!READ_ONCE(kp_armed))
		return 0;

	ret = regs_return_value(regs);
	out = ret;
	susfs_kstat_post(args->nr, args->compat, args->a, ret, &out);
	/* The buffer rewrites leave the return value alone; only a listing filter shortens it. */
	if (out != ret)
		syscall_set_return_value(current, regs, 0, out);
	return 0;
}

#define KP_STAT(_sym, _entry)					\
	{							\
		.kp.symbol_name = _sym,				\
		.entry_handler = _entry,			\
		.handler = kp_stat_return,			\
		.data_size = sizeof(struct kp_stat_args),	\
	}

static struct kretprobe kp_stat_probes[] = {
	/* The native three.  `__arm64_sys_fstat` is deliberately absent: this kernel does not carry it -
	 * see the header.  A probe entry for a symbol that does not exist would only log a failure. */
	KP_STAT("__arm64_sys_newfstatat", kp_entry_newfstatat),
	KP_STAT("__arm64_sys_statx", kp_entry_statx),
	KP_STAT("__arm64_sys_getdents64", kp_entry_getdents64),
	/* AArch32, stat64 family. */
	KP_STAT("__arm64_sys_stat64", kp_entry_stat64),
	KP_STAT("__arm64_sys_lstat64", kp_entry_lstat64),
	KP_STAT("__arm64_sys_fstat64", kp_entry_fstat64),
	KP_STAT("__arm64_sys_fstatat64", kp_entry_fstatat64),
	/* AArch32, the old stat family and getdents. */
	KP_STAT("__arm64_compat_sys_newstat", kp_entry_newstat),
	KP_STAT("__arm64_compat_sys_newlstat", kp_entry_newlstat),
	KP_STAT("__arm64_compat_sys_newfstat", kp_entry_newfstat),
	KP_STAT("__arm64_compat_sys_getdents", kp_entry_getdents),
};

/* The only proof a probe may be unregistered: a failed registration can leave address state behind
 * (susfs_kprobe.h records the reset rule), and unregistering a probe that never armed is worse than
 * one that stays armed. */
static bool kp_stat_registered[ARRAY_SIZE(kp_stat_probes)];

int susfs_kp_stat_init(void)
{
	unsigned int i;
	unsigned int armed = 0;
	int rc;

	/* The wrapper path is the cheaper one and is already handling these numbers: do nothing. */
	if (kstat_hooks_armed != 0) {
		SUSFS_LOGI("kp_stat: %d wrapper(s) armed, kretprobes not needed\n", kstat_hooks_armed);
		return 0;
	}

	kp_armed = true;
	for (i = 0; i < ARRAY_SIZE(kp_stat_probes); i++) {
		rc = register_kretprobe(&kp_stat_probes[i]);
		if (rc) {
			pr_warn("kp_stat: %s: register_kretprobe failed %d - that entry keeps answering the kernel's own way\n",
				kp_stat_probes[i].kp.symbol_name, rc);
			continue;
		}
		kp_stat_registered[i] = true;
		armed++;
	}

	if (!armed) {
		kp_armed = false;
		pr_warn("kp_stat: no kretprobe could be registered - the stat family and the dirent rewrite stay off\n");
		return -ENOENT;
	}

	SUSFS_LOGI("kp_stat: armed on %u of %u kretprobe(s) (stat family + dirent rewrite), no table entry touched\n",
		   armed, (unsigned int)ARRAY_SIZE(kp_stat_probes));
	return 0;
}

void susfs_kp_stat_exit(void)
{
	unsigned int i;

	if (!kp_armed)
		return;

	kp_armed = false;
	for (i = 0; i < ARRAY_SIZE(kp_stat_probes); i++) {
		if (!kp_stat_registered[i])
			continue;
		unregister_kretprobe(&kp_stat_probes[i]);
		kp_stat_registered[i] = false;
	}
	SUSFS_LOGI("kp_stat: disarmed\n");
}
