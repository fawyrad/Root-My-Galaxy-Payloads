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
 * does not exist, so neither `sys_enter` nor `sys_exit` is ever called, and `register_trace_sys_exit`
 * either fails or arms a tracepoint nothing fires.  Measured on the SM-S938U1 this project's devices
 * are built for; kprobes on the same kernel do work (this module's lsm_hook.c and KernelSU's own
 * setresuid hook both use them).  A kretprobe also costs more - a trap per call rather than a
 * tracepoint - which is why upstream moved the other way on GKI; here it is the only mechanism that
 * runs.
 *
 * ## What makes it work without touching upstream's logic
 *
 *   1. susfs_kstat_post() reads only the buffer argument - args[1] for fstat and getdents64, args[2]
 *      for newfstatat and the compat fstatat64, args[4] for statx (see its own number switch).  The
 *      entry handler copies all six argument registers before the call runs, so the buffer pointer is
 *      captured while it is still a pointer.
 *   2. The listing answer is a byte count, and the return handler can hand a shorter one back through
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

struct kp_stat_args {
	unsigned long a[6];
};

struct kp_stat_probe {
	struct kretprobe rp;
	long nr;		/* the number susfs_kstat_post() is told this call is */
	const char *why;	/* for the log when it cannot be registered */
	bool registered;	/* the only proof it may be unregistered: a failed registration can leave
				 * .addr behind (susfs_kprobe.h notes the reset rule), and unregistering
				 * a probe that never armed is worse than a probe that stays armed. */
};

static bool kp_armed;

/* Captured before the call runs: the return value lands in regs->regs[0], so reading the argument
 * registers afterwards would hand the spoofers the return value in place of the first argument. */
static int kp_stat_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kp_stat_args *args = (struct kp_stat_args *)ri->data;

	syscall_get_arguments(current, regs, args->a);
	return 0;
}

static int kp_stat_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kp_stat_probe *p = container_of(ri->rp, struct kp_stat_probe, rp);
	struct kp_stat_args *args = (struct kp_stat_args *)ri->data;
	long ret;
	long out;

	if (!READ_ONCE(kp_armed))
		return 0;

	ret = regs_return_value(regs);
	out = ret;
	susfs_kstat_post(p->nr, false, args->a, ret, &out);
	/* The buffer rewrites leave the return value alone; only a listing filter shortens it. */
	if (out != ret)
		syscall_set_return_value(current, regs, 0, out);
	return 0;
}

#define KP_STAT(_nr, _sym)						\
	{								\
		.rp = {							\
			.kp.symbol_name = _sym,				\
			.entry_handler = kp_stat_entry,			\
			.handler = kp_stat_return,			\
			.data_size = sizeof(struct kp_stat_args),	\
		},							\
		.nr = _nr,						\
		.why = _sym,						\
	}

static struct kp_stat_probe kp_stat_probes[] = {
	KP_STAT(__NR_newfstatat, "__arm64_sys_newfstatat"),
	KP_STAT(__NR_fstat, "__arm64_sys_fstat"),
	KP_STAT(__NR_statx, "__arm64_sys_statx"),
	KP_STAT(__NR_getdents64, "__arm64_sys_getdents64"),
};

static unsigned int kp_stat_registered;

int susfs_kp_stat_init(void)
{
	unsigned int i;
	int rc;

	/* The wrapper path is the cheaper one and is already handling these numbers: do nothing. */
	if (kstat_hooks_armed != 0) {
		SUSFS_LOGI("kp_stat: %d wrapper(s) armed, kretprobes not needed\n", kstat_hooks_armed);
		return 0;
	}

	kp_armed = true;
	for (i = 0; i < ARRAY_SIZE(kp_stat_probes); i++) {
		struct kp_stat_probe *p = &kp_stat_probes[i];

		rc = register_kretprobe(&p->rp);
		if (rc) {
			pr_warn("kp_stat: %s: register_kretprobe failed %d - that entry keeps answering the kernel's own way\n",
				p->why, rc);
			continue;
		}
		p->registered = true;
		kp_stat_registered++;
	}

	if (!kp_stat_registered) {
		kp_armed = false;
		pr_warn("kp_stat: no kretprobe could be registered - the stat family and the dirent rewrite stay off\n");
		return -ENOENT;
	}

	SUSFS_LOGI("kp_stat: armed on %u kretprobe(s) (stat family + dirent rewrite), no table entry touched\n",
		   kp_stat_registered);
	return 0;
}

void susfs_kp_stat_exit(void)
{
	unsigned int i;

	if (!kp_armed)
		return;

	kp_armed = false;
	for (i = 0; i < ARRAY_SIZE(kp_stat_probes); i++) {
		struct kp_stat_probe *p = &kp_stat_probes[i];

		if (!p->registered)
			continue;
		unregister_kretprobe(&p->rp);
		p->registered = false;
	}
	SUSFS_LOGI("kp_stat: disarmed (%u were armed)\n", kp_stat_registered);
	kp_stat_registered = 0;
}
