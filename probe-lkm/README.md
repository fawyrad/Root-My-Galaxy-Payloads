# probe-lkm

One module, built to answer the two questions in
[inforcqb/susfs4ksu-lkm#80](https://github.com/inforcqb/susfs4ksu-lkm/issues/80) on a device
where the susfs insert path returns `-EFAULT` instead of writing its hook head.

## What it does, in the order it does it

```
rkp_probe: selinux_hooks=... target=...
rkp_probe: test 1 read <target>: ret=? value=?
rkp_probe: <target> -> phys ...
rkp_probe: test 2 write .data (<addr>): ret=? readback=? expected=?
rkp_probe: test 3 write <target> (same bytes it holds): ret=?
```

1. **Read `selinux_hooks + 0x1c8`** with `copy_from_kernel_nofault()`. `0x1c8` is the offset the
   insert log named. `ret=0` means the address is reachable; the value printed is what the hook
   list holds there.
2. **Write this module's own `.data`** through the same path the insert path uses -
   `phys_from_virt()` -> `set_fixmap_offset(FIX_TEXT_POKE0, phy)` -> `copy_to_kernel_nofault()`.
   This is an address the kernel certainly permits writing, so it separates the two candidates:
   `ret=0` with the readback equal to `expected` means the path is fine and the hook-list page is
   what is protected on this kernel; `ret=-14` here means the fixmap path itself is refused.
3. **Write the failing address with the bytes it already holds.** The hooked word is read first and
   written back unchanged, so this reports the errno for that exact address without modifying
   anything - the reading is the return code, not a change in memory.

The module takes no lock and needs no other service; unloading it prints one line and nothing else
is touched.

## Build

```
.github/workflows/probe-lkm.yml, dispatched with a KMI (android15-6.6 by default)
```

It builds in the same DDK image the susfs modules are built in, keeps `.symtab` (the loader
rewrites it) and drops the debug info, and checks two things before uploading: `selinux_hooks` is
an undefined symbol - that is what the loader resolves - and no cache-flush helper is imported, so
a build against the wrong kernel tree cannot leave the pipeline looking successful.

## Load

`selinux_hooks` is a local kernel symbol that is not exported, so plain `insmod` cannot resolve it.
Use the loader that carries the susfs module, which resolves names from `/proc/kallsyms` and
rewrites the vermagic:

```
susfs_insmod -v rkp_probe-<kmi>.ko > probe.log
dmesg | grep rkp_probe
```

Prefixing the run with `dmesg -c` makes the three lines the only ones in the ring.

## What a reading means

| test | result | reading |
| --- | --- | --- |
| 1 | `ret=0` | the address is reachable; the object is where the walk says it is |
| 1 | `ret=-14` | the read itself is refused, which points below the page tables |
| 2 | `ret=0`, readback = expected | the fixmap path works here, so the hook-list page is protected specifically |
| 2 | `ret=-14` | the fixmap path is unusable on this kernel, not just that page |
| 3 | `ret=-14` | the store into the hook page is refused, as the insert log showed |
