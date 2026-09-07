/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Check that BT/BTS/BTR/BTC leave the non-CF arithmetic flags alone.
 *
 * The SDM calls OF/SF/AF/PF "undefined" after a bit-test, but real hardware
 * (and therefore KVM) leaves them exactly as the preceding arithmetic op set
 * them.  Guests do rely on that: OpenVMS x86-64, whose MACRO-32 compiler emits
 *
 *      dec  %reg          ; set the arithmetic flags
 *      bt   $n, %flagsreg ; restore a saved carry into CF
 *      lahf               ; save the flag byte -- which includes AF
 *      jcc  ...
 *
 * breaks if AF or OF is not carried across the BT.
 *
 * The oracle here needs no external reference: run a flag-setting
 * instruction alone and record the flags, then run the same instruction
 * followed by a bit test, and require CF to be the tested bit and every
 * other flag to be unchanged.  The flags are read back with LAHF and SETO,
 * as in the sequence above.
 *
 * Regression test for QEMU's gen_bt_flags(), which switched cc_op to
 * CC_OP_SAR* when the flag-setting op was in the same TB.  compute_all_sar*()
 * then reported AF as 0 and derived OF from the shift formula (src1 ^ dst),
 * so both came out wrong.  Because the translator resets cc_op to
 * CC_OP_DYNAMIC at every TB boundary, -one-insn-per-tb hid the bug, so each
 * case keeps the arithmetic and the bit test in one straight-line block.
 */
#include <minilib.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define CC_C    0x0001
#define CC_P    0x0004
#define CC_A    0x0010
#define CC_Z    0x0040
#define CC_S    0x0080
#define CC_O    0x0800

/*
 * Run INSNS, then return the arithmetic flags.  %[v] is the operand of the
 * flag-setting instruction, the bit string is in %[s] and in memory at %[m],
 * and %[z] is a zero bit offset for the register-offset forms.  Bit 0 of
 * the bit string is always the one tested.  %[v] is early-clobber because
 * it is written before %[z] is read, so the two must not share a register.
 */
#define FLAGS_AFTER(insns)                                              \
    unsigned long mem = s, ax;                                          \
                                                                        \
    asm volatile(insns "\n\t"                                           \
                 "lahf\n\t"                                             \
                 "seto %%al"                                            \
                 : "=&a"(ax), [v] "+&r"(v), [s] "+r"(s), [m] "+m"(mem)  \
                 : [z] "r"(0UL)                                         \
                 : "cc");                                               \
    return ((ax >> 8) & (CC_S | CC_Z | CC_A | CC_P | CC_C)) |           \
           ((ax & 1) ? CC_O : 0)

/* NAME_ref runs OP alone, NAME_bt runs OP followed by BT in the same TB */
#define CASE(name, op, bt)                                              \
    static unsigned long name##_ref(unsigned long v, unsigned long s)   \
    {                                                                   \
        FLAGS_AFTER(op);                                                \
    }                                                                   \
    static unsigned long name##_bt(unsigned long v, unsigned long s)    \
    {                                                                   \
        FLAGS_AFTER(op "\n\t" bt);                                      \
    }

/* every bit-test form after the same arithmetic op ... */
CASE(bt_imm_reg,  "decl %k[v]",     "btl $0, %k[s]")
CASE(bt_reg_reg,  "decl %k[v]",     "btq %[z], %[s]")
CASE(bt_imm_mem,  "decl %k[v]",     "btw $0, %[m]")
CASE(bt_reg_mem,  "decl %k[v]",     "btl %k[z], %[m]")
CASE(bts,         "decl %k[v]",     "btsl $0, %k[s]")
CASE(btr,         "decl %k[v]",     "btrq %[z], %[s]")
CASE(btc,         "decl %k[v]",     "btcw $0, %w[s]")
CASE(bts_mem,     "decl %k[v]",     "btsq $0, %[m]")

/* ... and BT after each kind of flag-setting op and operand size */
CASE(inc,         "incl %k[v]",     "btl $0, %k[s]")
CASE(add,         "addl $1, %k[v]", "btl $0, %k[s]")
CASE(sub,         "subl $1, %k[v]", "btl $0, %k[s]")
CASE(neg,         "negl %k[v]",     "btl $0, %k[s]")
CASE(and,         "andl $0x7f, %k[v]", "btl $0, %k[s]")
CASE(shl,         "shll $1, %k[v]", "btl $0, %k[s]")
CASE(decw,        "decw %w[v]",     "btl $0, %k[s]")
CASE(decq,        "decq %[v]",      "btl $0, %k[s]")

#define ENTRY(name) { #name, name##_ref, name##_bt }

static const struct {
    const char *name;
    unsigned long (*ref)(unsigned long v, unsigned long s);
    unsigned long (*bt)(unsigned long v, unsigned long s);
} cases[] = {
    ENTRY(bt_imm_reg), ENTRY(bt_reg_reg), ENTRY(bt_imm_mem),
    ENTRY(bt_reg_mem), ENTRY(bts), ENTRY(btr), ENTRY(btc), ENTRY(bts_mem),
    ENTRY(inc), ENTRY(add), ENTRY(sub), ENTRY(neg), ENTRY(and), ENTRY(shl),
    ENTRY(decw), ENTRY(decq),
};

/* operands chosen to make the ops above produce every AF/ZF/SF/OF mix */
static const unsigned long vals[] = {
    0x0, 0x1, 0xf, 0x10, 0x100, 0x7fff, 0x8000, 0x12345678,
    0x7fffffff, 0x80000000, 0xffffffff, 0x8000000000000000,
};

/* bit strings with bit 0 clear and set, and with the other bits varied */
static const unsigned long srcs[] = { 0x0, 0x1, ~0x1UL, ~0x0UL };

int main(void)
{
    int failures = 0;
    int total = 0;

    for (unsigned c = 0; c < ARRAY_SIZE(cases); c++) {
        int bad = 0;

        for (unsigned i = 0; i < ARRAY_SIZE(vals); i++) {
            for (unsigned j = 0; j < ARRAY_SIZE(srcs); j++) {
                unsigned long v = vals[i];
                unsigned long s = srcs[j];
                unsigned long cf = (s & 1) ? CC_C : 0;
                unsigned long want = (cases[c].ref(v, s) & ~CC_C) | cf;
                unsigned long got = cases[c].bt(v, s);

                total++;
                if (got == want) {
                    continue;
                }
                if (!bad) {
                    ml_printf("FAIL %s: v=0x%lx s=0x%lx: flags 0x%lx,"
                              " expected 0x%lx\n",
                              cases[c].name, v, s, got, want);
                    if ((got ^ want) & CC_A) {
                        ml_printf("     AF differs (BT must not change AF)\n");
                    }
                    if ((got ^ want) & CC_O) {
                        ml_printf("     OF differs (BT must not change OF)\n");
                    }
                }
                bad++;
            }
        }
        if (bad) {
            ml_printf("FAIL %s: %d of %d combinations\n", cases[c].name,
                      bad, (int)(ARRAY_SIZE(vals) * ARRAY_SIZE(srcs)));
            failures += bad;
        }
    }

    if (failures) {
        ml_printf("bt-flags: %d of %d combinations failed\n", failures, total);
        return 1;
    }
    ml_printf("bt-flags: OK - %d combinations, BT/BTS/BTR/BTC preserve"
              " OF/SF/ZF/AF/PF\n", total);
    return 0;
}
