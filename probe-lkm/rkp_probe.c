// SPDX-License-Identifier: GPL-2.0-only
/*
 * rkp_probe - the two tests in inforcqb/susfs4ksu-lkm#80, as a module.
 *
 * The insert path in that project writes an LSM hook head through
 *   phys_from_virt() -> set_fixmap_offset(FIX_TEXT_POKE0, phy) -> copy_to_kernel_nofault()
 * and on an SM-S938U1 that store returns -EFAULT where it succeeds on the eight GKI variants.
 * A page-table-walk failure returns -ENOENT instead, so the errno says the store was refused
 * rather than the address being unreachable - this module separates the two readings directly:
 *
 *  1. read selinux_hooks + 0x1c8 with copy_from_kernel_nofault(): reachable, or not;
 *  2. write this module's own .data through the same fixmap path: if that lands, the path works
 *     and the hook-list page is what this kernel protects; if it fails too, the path itself is
 *     unusable here and the answer lies in arm64 set_fixmap()/__set_fixmap().
 *
 * The failing address is then attempted the same way with the bytes it already holds, so the
 * errno is the only thing that changes; nothing in the hook list is modified either way.
 *
 * phys_from_virt() below is the walk from that project's kernel/patch_memory.c (GPL-2.0-only,
 * Copyright (C) 2023 bmax121), copied so the probe measures the same path rather than a
 * lookalike.
 *
 * Build: .github/workflows/probe-lkm.yml. Load: the same loader that carries the susfs module,
 * because `selinux_hooks` is a local kernel symbol that has to be resolved from /proc/kallsyms:
 *
 *   susfs_insmod -v rkp_probe-<kmi>.ko > probe.log
 *   dmesg | grep rkp_probe
 */

#ifdef __aarch64__

#include <linux/module.h>
#include <linux/init.h>
#include <linux/uaccess.h>
#include <linux/ptrace.h>
#include <asm/fixmap.h>
#include <asm/pgtable.h>
#include <asm-generic/fixmap.h>

/* A local symbol in security/selinux/hooks.c: not exported, so it is resolved by name from
 * /proc/kallsyms by the loader that puts this module in. */
extern unsigned char selinux_hooks[];

/* The offset the insert log named, relative to that array. */
#define PROBE_HOOK_OFFSET   0x1c8

/* A known-writable address: this module's own .data. */
static u64 probe_value = 0x1122334455667788ULL;

unsigned long phys_from_virt(unsigned long addr, int *err)
{
    struct mm_struct *mm = &init_mm;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    *err = 0;

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        goto fail;

    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        goto fail;
#if defined(p4d_leaf)
    if (p4d_leaf(*p4d))
        return __p4d_to_phys(*p4d) + (addr & ~P4D_MASK);
#endif

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud))
        goto fail;
#if defined(pud_leaf)
    if (pud_leaf(*pud))
        return __pud_to_phys(*pud) + (addr & ~PUD_MASK);
#endif

    pmd = pmd_offset(pud, addr);
#if defined(pmd_leaf)
    if (pmd_leaf(*pmd))
        return __pmd_to_phys(*pmd) + (addr & ~PMD_MASK);
#endif
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        goto fail;

    pte = pte_offset_kernel(pmd, addr);
    if (!pte || !pte_present(*pte))
        goto fail;

    return __pte_to_phys(*pte) + (addr & ~PAGE_MASK);

fail:
    *err = -ENOENT;
    return 0;
}

/* One store through the fixmap, exactly as the insert path does it. */
static int fixmap_store(void *dst, const void *src, size_t len)
{
    unsigned long phy;
    int phy_err;
    void *map;
    int ret;

    phy = phys_from_virt((unsigned long)dst, &phy_err);
    if (phy_err) {
        pr_err("rkp_probe: no physical address for 0x%lx (walk failed)\n", (unsigned long)dst);
        return phy_err;
    }
    pr_info("rkp_probe: 0x%lx -> phys 0x%lx\n", (unsigned long)dst, phy);

    map = (void *)set_fixmap_offset(FIX_TEXT_POKE0, phy);
    ret = (int)copy_to_kernel_nofault(map, src, len);
    clear_fixmap(FIX_TEXT_POKE0);
    return ret;
}

static int __init rkp_probe_init(void)
{
    unsigned long target = (unsigned long)selinux_hooks + PROBE_HOOK_OFFSET;
    u64 readback = 0;
    u64 before = 0;
    int ret;

    pr_info("rkp_probe: selinux_hooks=0x%lx target=0x%lx\n",
            (unsigned long)selinux_hooks, target);

    /* 1. is the address reachable at all */
    ret = (int)copy_from_kernel_nofault(&before, (void *)target, sizeof(before));
    pr_info("rkp_probe: test 1 read 0x%lx: ret=%d value=0x%llx\n",
            target, ret, (unsigned long long)before);

    /* 2. is the fixmap path usable on an address this kernel certainly allows writing */
    probe_value = 0x1122334455667788ULL;
    {
        u64 want = 0x8877665544332211ULL;
        ret = fixmap_store(&probe_value, &want, sizeof(want));
        readback = probe_value;
        pr_info("rkp_probe: test 2 write .data (0x%lx): ret=%d readback=0x%llx expected=0x%llx\n",
                (unsigned long)&probe_value, ret,
                (unsigned long long)readback, (unsigned long long)want);
    }

    /* 3. the failing address, with the bytes it already holds */
    ret = fixmap_store((void *)target, &before, sizeof(before));
    pr_info("rkp_probe: test 3 write 0x%lx (same bytes it holds): ret=%d\n", target, ret);

    pr_info("rkp_probe: done - ret 0 on tests 2 and 3 means the path is fine and the hook page "
            "is what this kernel protects; -14 on test 2 means the fixmap path itself is refused\n");
    return 0;
}

static void __exit rkp_probe_exit(void)
{
    pr_info("rkp_probe: unloaded\n");
}

module_init(rkp_probe_init);
module_exit(rkp_probe_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("rushiranpise");
MODULE_DESCRIPTION("issue 80: read the hook list, and write through the fixmap path, on Samsung");

#endif /* __aarch64__ */
