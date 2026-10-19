// SPDX-License-Identifier: GPL-2.0-only
/*
 * susfs_tp_stat.c - the stat family and the dirent rewrite, from a sys_exit tracepoint.
 *
 * Upstream reaches both from a sys_call_table wrapper (susfs_fp_hook): it replaces the table entry,
 * calls the original and post-processes at the wrapper's tail.  That needs a write into the syscall
 * table, which this project's devices refuse - the same refusal that made our lsm_hook.c a kprobe
 * implementation.  So the post-processing runs from a sys_exit tracepoint instead, which needs no
 * text patch at all.
 *
 * Three things make that possible without touching upstream's logic:
 *
 *   1. susfs_kstat_post() reads only the buffer argument - args[1] for fstat and getdents64,
 *      args[2] for newfstatat and the compat fstatat64, args[4] for statx (see its own number
 *      switch).  None of those is argument 0, and argument 0 is the only register the kernel
 *      overwrites on the way out (the return value lands in regs->regs[0]), so every argument the
 *      post-processing needs is still in the pt_regs at sys_exit.
 *   2. The listing answer is a byte count, and the tracepoint can hand a shorter one back through
 *      syscall_set_return_value().  That is exactly what the wrapper does with its `out`.
 *   3. What a tracepoint cannot do is pre-empt a call, so sus_dirent.c's filldir prefilter (which
 *      answers getdents without the kernel ever writing the caller's buffer) stays with the
 *      wrapper path.  Here the post-hoc rewrite runs instead.  The two tells that rewrite leaves -
 *      the d_ino = 0 placeholder and the scrub a PROT_NONE race can fault - are only reachable
 *      through the module's own /proc nodes, and this build does not create those
 *      (susfs_expose_proc is compiled to false), so nothing is left to probe.
 *
 * Armed only when the wrapper path installed nothing (kstat_hooks_armed == 0).  On a kernel where
 * the table write lands, the wrappers are the cheaper answer - no tracepoint, no per-syscall test -
 * and this layer stays off, so no call is ever post-processed twice.  On this project's devices all
 * thirteen entries fail, which is the case this file exists for.
 *
 * The cost is the one upstream measured and rejected for GKI: a registered sys_exit tracepoint is
 * called for every syscall (+25..31 ns, 126 vs 151 ns in susfs_kstat.c's own note).  The gate below
 * is the first thing the handler does, so the work after it is paid only by the numbers listed.
 */

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/tracepoint.h>
#include <linux/compat.h>
#include <asm/syscall.h>
#include <asm/unistd.h>	/* __NR_newfstatat, __NR_fstat, __NR_statx, __NR_getdents64 */
#include <trace/events/syscalls.h>

#include "susfs.h"
#include "susfs_log.h"

/*
 * The post-processing, exported by the sed in the build: upstream defines it `static` because only
 * its wrapper tails call it.  Declared with the same __nocfi as the definition - it is reached from
 * a tracepoint, which is not a CFI-instrumented call site, and the attribute is what keeps the two
 * declarations the same function to the compiler.
 */
__nocfi void susfs_kstat_post(long nr, bool compat, const unsigned long *args, long ret, long *out);

/* The wrapper path's armed count, also exported by that sed: 0 means nothing of upstream's own
 * install path is in place, which is when this layer takes over. */
extern int kstat_hooks_armed;

static int susfs_tp_armed;

/*
 * The numbers this layer has anything to say about: the stat family upstream lists in kstat_hooks[],
 * and the three listing numbers its dirent rewrite rides.
 *
 * The native ones come from the build's own UAPI.  The AArch32 ones are fixed by
 * arch/arm/tools/syscall.tbl and are spelled out because an arm64 tree has no macro for them - the
 * same choice, and the same numbers, as upstream's own block in susfs_kstat.c (106/107/108 stat
 * family, 195/196/197 stat64 family, 327 fstatat64, 397 statx).  They are kernel ABI and cannot
 * move; a number that somehow stopped matching would only cost one unprocessed call, because
 * susfs_kstat_post() re-decides by number and returns for anything it does not know.
 */
#define TP_COMPAT_STAT_NR	106
#define TP_COMPAT_LSTAT_NR	107
#define TP_COMPAT_FSTAT_NR	108
#define TP_COMPAT_STAT64_NR	195
#define TP_COMPAT_LSTAT64_NR	196
#define TP_COMPAT_FSTAT64_NR	197
#define TP_COMPAT_FSTATAT64_NR	327
#define TP_COMPAT_STATX_NR	397

/* Whether this number is one the post-processing below has a use for.  First thing the handler
 * does, so everything else is paid only by these calls. */
static bool susfs_tp_wanted(long nr, bool compat)
{
	if (compat) {
		switch (nr) {
		case TP_COMPAT_STAT_NR:
		case TP_COMPAT_LSTAT_NR:
		case TP_COMPAT_FSTAT_NR:
		case TP_COMPAT_STAT64_NR:
		case TP_COMPAT_LSTAT64_NR:
		case TP_COMPAT_FSTAT64_NR:
		case TP_COMPAT_FSTATAT64_NR:
		case TP_COMPAT_STATX_NR:
		case SUS_NR_GETDENTS64_COMPAT:
		case SUS_NR_GETDENTS_COMPAT:
			return true;
		}
		return false;
	}

	switch (nr) {
	case __NR_newfstatat:
	case __NR_fstat:
	case __NR_statx:
	case __NR_getdents64:
		return true;
	}
	return false;
}

/*
 * sys_exit: the call has run, the caller's buffer holds whatever the kernel wrote, and the return
 * value is in regs->regs[0].  susfs_kstat_post() rewrites the buffer in place, or answers a shorter
 * count for a listing, which is the one thing that has to go back through the return value.
 */
static void susfs_tp_sys_exit(void *ignore, struct pt_regs *regs, long ret)
{
	unsigned long args[6];
	long nr;
	long out = ret;

	(void)ignore;

	if (!READ_ONCE(susfs_tp_armed))
		return;

	nr = syscall_get_nr(current, regs);
	if (nr < 0)
		return;

	if (!susfs_tp_wanted(nr, is_compat_task()))
		return;

	/* syscall_get_arguments() asks for a non-const regs it only reads; the cast is what that
	 * difference costs, and nothing here writes to it. */
	syscall_get_arguments(current, (struct pt_regs *)regs, args);

	susfs_kstat_post(nr, is_compat_task(), args, ret, &out);
	if (out != ret)
		syscall_set_return_value(current, regs, 0, out);
}

int susfs_tp_stat_init(void)
{
	int rc;

	/* The wrapper path is the cheaper one and is already handling these numbers: do nothing. */
	if (kstat_hooks_armed != 0) {
		SUSFS_LOGI("tp_stat: %d wrapper(s) armed, tracepoint not needed\n", kstat_hooks_armed);
		return 0;
	}

	rc = register_trace_sys_exit(susfs_tp_sys_exit, NULL);
	if (rc) {
		pr_warn("tp_stat: register_trace_sys_exit failed %d - the stat family and the dirent rewrite stay off\n", rc);
		return rc;
	}

	susfs_tp_armed = 1;
	SUSFS_LOGI("tp_stat: armed on sys_exit (stat family + dirent rewrite), no table entry touched\n");
	return 0;
}

void susfs_tp_stat_exit(void)
{
	if (!susfs_tp_armed)
		return;

	susfs_tp_armed = 0;
	unregister_trace_sys_exit(susfs_tp_sys_exit, NULL);
	tracepoint_synchronize_unregister();
	SUSFS_LOGI("tp_stat: disarmed\n");
}
