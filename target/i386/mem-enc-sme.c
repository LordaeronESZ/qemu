/*
 * AMD SME adaptation for the generic memory-encryption engine (x86 side).
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/cputlb.h"
#include "system/memory-encryption.h"
#include "mem-enc-sme.h"

#ifdef CONFIG_MEM_ENCRYPTION

static uint64_t sme_c_bit_mask(X86CPU *cpu)
{
    return 1ULL << cpu->sme_c_bit;
}

/*
 * Key resolver installed on the engine when the SME CPU property is on:
 * an access that went through a C-bit mapping decrypts with the owner
 * key; everything else sees the raw backing.
 */
static uint32_t x86_sme_resolve_key(MemoryEncryptionEngine *eng,
                                    CPUState *cs, hwaddr paddr,
                                    MemTxAttrs attrs)
{
    X86CPU *cpu = X86_CPU(cs);

    if (!attrs.encrypted) {
        return MEM_ENC_KEY_NONE;
    }
    if (!(cpu->env.msr_syscfg & MSR_AMD64_SYSCFG_MEM_ENCRYPT)) {
        return MEM_ENC_KEY_NONE;
    }
    return mem_enc_owner_key_id(eng);
}

void x86_sme_fill_adjust(CPUState *cs, hwaddr *paddr, MemTxAttrs *attrs)
{
    X86CPU *cpu = X86_CPU(cs);

    if (!cpu->sme) {
        return;
    }
    if (*paddr & sme_c_bit_mask(cpu)) {
        *paddr &= ~sme_c_bit_mask(cpu);
        attrs->encrypted = 1;
    }
}

void x86_sme_cpu_realize(CPUState *cs)
{
    MemoryEncryptionEngine *eng = mem_enc_get();

    if (eng) {
        mem_enc_set_key_resolver(eng, x86_sme_resolve_key);
    }
}

void x86_sme_clflush(CPUState *cs, vaddr addr)
{
    X86CPU *cpu = X86_CPU(cs);
    MemoryEncryptionEngine *eng = mem_enc_get();
    RAMBlock *block;
    ram_addr_t page_off;
    hwaddr paddr;

    if (!eng || !cpu->sme) {
        return;
    }

    paddr = cpu_get_phys_page_debug(cs, addr & TARGET_PAGE_MASK);
    if (paddr == -1) {
        return;
    }
    paddr &= ~sme_c_bit_mask(cpu);

    if (!mem_enc_paddr_to_page(paddr, &block, &page_off)) {
        return;
    }
    mem_enc_flush_and_invalidate(eng, block, page_off,
                                 qemu_target_page_size());
    /* Drop any TLB entry whose addend pointed into a now-freed work page. */
    tlb_flush_page(cs, addr & TARGET_PAGE_MASK);
}

#endif /* CONFIG_MEM_ENCRYPTION */

