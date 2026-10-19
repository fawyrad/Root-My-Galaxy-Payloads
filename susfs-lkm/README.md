# susfs-lkm

This repository's replacement for the susfs module's LSM install layer, built as the `samsung` variant
of the susfs tier. One file, and it exists for one reason.

## Why it exists

Upstream installs its LSM hooks by writing a `struct security_hook_list` into `security_hook_heads` (or
into the `selinux_hooks[]` slot it found by symbol identity) - memory that is `__lsm_ro_after_init`, so
read-only after boot. It makes that write land by translating the address to a physical one, mapping it
through a fixmap and storing through `copy_to_kernel_nofault` under `stop_machine`.

On Samsung's kernel that write does not land. Measured on an SM-S938U1 (`6.6.127-android15-8-...-4k`,
SELinux enforcing, `CONFIG_MODULE_FORCE_LOAD=n`), loading the published `stable` module:

```
susfs_guard_lkm: init v2.3.0-gki
susfs_guard_lkm: symbol_resolver: kprobe bootstrap (1 = usable): ...
susfs_guard_lkm: ksu_umount_gate: resolved ksu_uid_should_umount at ffffffc07cc798b4
susfs_guard_lkm: lsm_hook: inode_getattr: list head found by identity at offset 0x1c8
susfs_guard_lkm: lsm_hook: failed to insert inode_getattr at the head of its list: -14
susfs_guard_lkm: sus_path: getattr hook failed -14 - nothing would be hidden, refusing to load
```

`-14` is `EFAULT` out of that read-only write. The module refused to load, which is its contract and
why the phone was left untouched. All three upstream lines install their hooks the same way, so none of
them can arm on this kernel.

## What this repository does instead

`lsm_hook.c` here keeps upstream's API exactly - `ksu_lsm_hook_init()`, `ksu_lsm_hook_exit()`,
`ksu_register_lsm_hook()`, `ksu_unregister_lsm_hook()`, and the `KSU_LSM_HOOK_INSERT` declaration
`sus_path.c` writes - and changes only how a declared hook is installed: a kretprobe on the SELinux
implementation of that member (`selinux_inode_getattr` and its twelve siblings), whose return it may
change.

It is faithful to what the insert path could do. Upstream's own contract for those hooks is that the
replacement runs before every registered LSM, must not call any original, and can only **add a denial**.
A kretprobe does exactly that: the SELinux implementation runs and its answer stands; only where it
allowed is the declared replacement called, with the arguments captured on entry, and a non-zero answer
of its own replaces the 0.

This is the same technique this project's KernelSU delta already relies on for Samsung:
`CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT` makes the text patcher refuse instead of writing,
`ksu_syscall_table_hook()` returns errors instead of pretending, and the features that need a hook use
kprobes/kretprobes (`samsung_defex.c` on `task_defex_enforce`, the AVC spoof on `slow_avc_audit`).

## What is verified, and what is not

- **Verified here:** upstream's API and the call sites (`sus_path.c` uses only `KSU_LSM_HOOK_INSERT`
  declarations and `ksu_register_lsm_hook()`/`ksu_unregister_lsm_hook()`), the SELinux symbol names
  against upstream's own per-KMI build check (which greps exactly `selinux_<member>` for all thirteen),
  and the reason for the failure above, read out of the module's own log.
- **Compiles:** the `samsung` variant is built by the `SUSFS LKM` workflow for every KMI it publishes,
  from 2026-10-11 onward.
- **Not verified:** that it arms and hides on a device. No run has been read for its arming lines yet.
- **Refused by design:** replace-shaped hooks (which need the read-only write), and members with no
  known SELinux implementation (a hook that installs and does nothing is worse than one that says so).

## The control nodes are not created

Upstream's `/proc/susfs_*` nodes are an optional mirror of the supercall interface: created by default,
hidden per caller at run time. Hiding is an answer rather than an absence, and the node stays openable
through `open(..., O_PATH)` while `stat` answers ENOENT - two subsystems describing one object
differently, which a clean kernel cannot do. That is what the public detectors read (O_PATH/fstat,
readlinkat on the pinned fd, and the getdents64 buffer during a uaccess race), and upstream's own O_PATH
denial replaces `sys_call_table` entries - a write this project's devices refuse.

So the `samsung` variant does not create them: the build compiles `susfs_expose_proc` to `false`, and
the workflow fails if upstream moves that default rather than shipping the nodes silently. Control stays
with the supercall, which is the interface the manager and this project's tools use. Turning them back
on is a one-line change plus a rebuild, for anyone who needs the file interface.

## Provenance and licence

The hook bodies and the feature logic are upstream's, unmodified and built from the pinned commit
recorded per variant in the feed; the control-node default above is this repository's change. This file
is ours, replaces theirs in the checkout, and stays under the same licence: GPL-2.0-only, as everything
served from `susfs/` is.
