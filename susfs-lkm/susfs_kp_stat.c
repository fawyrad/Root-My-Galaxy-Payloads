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
 * into the instance data before capturing the argument registers; the return handler reads the number
 * from there.  One handler pair per syscall, no struct walk.
 *
 * ## What makes it work without touching upstream's logic
 *
 *   1. susfs_kstat_post() reads only the buffer argument - args[1] for fstat and getdents64, args[2]
 *      for newfstatat, args[4] for statx (see its own number switch).  The entry handler copies all
 *      six argument registers before the call runs, so the buffer pointer is captured while it is
 *      still a pointer.
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
 * Native numbers only.  The compat numbers are handled by the wrappers' own compat entries on kernels
 * where those install; the devices this layer exists for run 64-bit app processes, and a compat
 * kretprobe needs a symbol (`__arm_compat_sys_*`) whose naming differs per tree.  A 32-bit caller
 * therefore gets no spoofing here rather than a guess.
 *
 * ## Measured on the device (2026-10-19, SM-S938U1, 6.6.127)
 *
 * Armed: three of the four probes - `__arm64_sys_newfstatat`, `__arm64_sys_statx` and
 * `__arm64_sys_getdents64` appear in `/sys/kernel/debug/kprobes/list` with the return flag.  With a
 * static sus_kstat rule on a root-owned file, uid 10359 read the spoofed size (123456789) while root
 * read the real 6; with a sus_path rule on one name in a two-file directory, uid 10359's `ls` showed
 * only the other name and `cat` of the hidden one answered ENOENT, while root saw both.  Before the
 * pt_regs fix the same tests showed the real size and the full listing, with `sus_path: dirent
 * rewrite stopped at 0/N bytes (returned N)` in the ring - the filter running against a garbage
 * buffer.
 *
 * Not covered, measured: `__arm64_sys_fstat` does not register - it is absent from the kprobe list and
 * its per-probe warning is the only trace of it.  `fstat` is therefore not spoofed here; newfstatat
 * and statx are, which is what `stat` and `ls` use.  Whether the symbol exists under another name
 * could not be settled: /proc/kallsyms was denied to the shell and read as empty from the root session
 * the probe list was taken in.
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

/* One instance's worth: the number this call is, and the arguments as they were on entry. */
struct kp_stat_args {
	long nr;
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
#define KP_ENTRY(_fn, _nr)							\
	static int _fn(struct kretprobe_instance *ri, struct pt_regs *regs)	\
	{									\
		struct kp_stat_args *args = (struct kp_stat_args *)ri->data;	\
		struct pt_regs *sys = (struct pt_regs *)regs->regs[0];		\
										\
		args->nr = (_nr);						\
		syscall_get_arguments(current, sys, args->a);			\
		return 0;							\
	}

KP_ENTRY(kp_entry_newfstatat, __NR_newfstatat)
KP_ENTRY(kp_entry_fstat, __NR_fstat)
KP_ENTRY(kp_entry_statx, __NR_statx)
KP_ENTRY(kp_entry_getdents64, __NR_getdents64)

static int kp_stat_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kp_stat_args *args = (struct kp_stat_args *)ri->data;
	long ret;
	long out;

	if (!READ_ONCE(kp_armed))
		return 0;

	ret = regs_return_value(regs);
	out = ret;
	susfs_kstat_post(args->nr, false, args->a, ret, &out);
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
	KP_STAT("__arm64_sys_newfstatat", kp_entry_newfstatat),
	KP_STAT("__arm64_sys_fstat", kp_entry_fstat),
	KP_STAT("__arm64_sys_statx", kp_entry_statx),
	KP_STAT("__arm64_sys_getdents64", kp_entry_getdents64),
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

	SUSFS_LOGI("kp_stat: armed on %u kretprobe(s) (stat family + dirent rewrite), no table entry touched\n",
		   armed);
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
