/*
 * QEMU x86 SEV-style memory-encryption simulation.
 *
 * A ConfidentialGuestSupport (X86ConfidentialGuest) layer that drives the
 * generic MemoryEncryptionEngine with AMD-SEV semantics: the guest selects
 * encryption via the C-bit (a high guest-physical-address bit), and the
 * per-VM ASID selects the key. This is the arch-specific integration on top of
 * the arch-independent engine; it does not (yet) implement the full SEV
 * launch/attestation flow, only the in-memory encryption behaviour.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef TARGET_I386_SEV_SIM_H
#define TARGET_I386_SEV_SIM_H

#include "exec/hwaddr.h"

#define TYPE_X86_SEV_SIM "x86-sev-sim"

/* True if the SEV-simulation confidential guest is active. */
bool x86_sev_sim_active(void);

/* The C-bit mask (1 << cbitpos), or 0 if SEV-sim is inactive. */
uint64_t x86_sev_sim_cbit_mask(void);

/* Values reported in CPUID leaf 0x8000001f, or 0 when inactive. */
uint32_t x86_sev_sim_cbit_position(void);
uint32_t x86_sev_sim_reduced_phys_bits(void);

#endif /* TARGET_I386_SEV_SIM_H */
