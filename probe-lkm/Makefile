# The DDK image sets KDIR and the workflow builds with
#   make -C "$KDIR" M="$PWD/probe-lkm" ARCH=arm64 CC=clang LLVM=1 LLVM_IAS=1 modules
# the same way the susfs module is built, so this file only has to name the object.
#
# No cache-flush helper is used here at all, which is deliberate: one released 5.10 artifact of
# the module this probes imported `dcache_clean_inval_poc` and could not load anywhere, and that
# class of mistake is avoided by not touching the flush path in a diagnostic.
obj-m += rkp_probe.o

ccflags-y += -Wno-strict-prototypes -Wno-int-conversion -Wno-missing-prototypes
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function
