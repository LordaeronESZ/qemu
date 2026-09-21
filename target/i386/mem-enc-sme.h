/*
 * AMD SME adaptation for the generic memory-encryption engine.
 * 
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef QEMU_I386_MEM_ENC_SME_H
#define QEMU_I386_MEM_ENC_SME_H

#include "exec/hwaddr.h"
#include "exec/memattrs.h"
#include "exec/mmu-access-type.h"
#include "hw/core/cpu.h"

/*
 * TLB-fill hook: if @paddr carries the C-bit, strip it and mark @attrs
 * encrypted. Additionally, a data-store fill of an encrypted mapping
 * lazily moves the page into the encrypted domain.
 */
void x86_sme_fill_adjust(CPUState *cs, hwaddr *paddr, MemTxAttrs *attrs);

/* Install the SME key resolver on the active engine. */
void x86_sme_cpu_realize(CPUState *cs);

/*
 * Flush and invalidate the engine page, and flush the QEMU TLB page so
 * no stale addend survives.
 */
void x86_sme_clflush(CPUState *cs, vaddr addr);

#endif /* QEMU_I386_MEM_ENC_SME_H */
