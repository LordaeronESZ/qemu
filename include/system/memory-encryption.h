/*
 * QEMU Generic Memory Encryption - the "encryption IP core" engine
 *
 * An architecture-independent, pure-software memory-encryption engine. It
 * models a tweakable block cipher sitting on the memory bus: the backing RAM of
 * "managed" pages holds ciphertext, and accesses are decrypted/encrypted
 * according to an access-specific key id. With the correct key a reader sees
 * plaintext; with the wrong key it sees garbage -- matching AMD SEV semantics.
 *
 * The engine is deliberately NOT a QOM type: it is reusable machinery, attached
 * to a VM purely by activating a process-wide singleton (see mem_enc_get()).
 * This keeps the encryption mechanism -- a PMP-style simulator feature -- fully
 * independent of the confidential-guest (CGS) abstraction and of any particular
 * target architecture. A CGS subclass is reserved for a future SEV-semantics
 * layer that would own an engine and add C-bit/ASID/attestation behaviour.
 *
 * This provides no real confidentiality; it is a simulation facility for
 * developing and testing confidential-computing software on TCG.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef QEMU_MEMORY_ENCRYPTION_H
#define QEMU_MEMORY_ENCRYPTION_H

#include "qapi/error.h"
#include "exec/hwaddr.h"
#include "exec/memattrs.h"
#include "system/ramblock.h"
#include "system/memory.h"
#include "hw/core/cpu.h"

/*
 * Special key id meaning "no key": an external/unencrypted view that observes
 * the raw ciphertext backing (like a host without the guest's ASID).
 */
#define MEM_ENC_KEY_NONE 0u

typedef struct MemoryEncryptionEngine MemoryEncryptionEngine;

/* ----------------------------------------------------------------------- */
/* Singleton                                                                */
/* ----------------------------------------------------------------------- */

/* The active engine, or NULL when no encryption core is configured. */
MemoryEncryptionEngine *mem_enc_get(void);

/* ----------------------------------------------------------------------- */
/* Engine lifecycle (called by the -object wrapper's complete hook)         */
/* ----------------------------------------------------------------------- */

MemoryEncryptionEngine *mem_enc_engine_new(const char *cipher_name,
                                           uint32_t owner_key_id);
void mem_enc_engine_free(MemoryEncryptionEngine *eng);

/*
 * Publish @eng as the active singleton. The CPU hot-path and (future) flatview
 * hooks observe it via mem_enc_get(). Called from the owning -object wrapper's
 * UserCreatable.complete hook, which runs during command-line parsing -- before
 * machine init or CPU execution, so the singleton is set in time.
 */
void mem_enc_engine_activate(MemoryEncryptionEngine *eng);

/* ----------------------------------------------------------------------- */
/* Key management                                                           */
/* ----------------------------------------------------------------------- */

int  mem_enc_set_key(MemoryEncryptionEngine *eng, uint32_t key_id,
                     const uint8_t *key, size_t keylen, Error **errp);
bool mem_enc_has_key(MemoryEncryptionEngine *eng, uint32_t key_id);

/*
 * Install an arch-specific key resolver. Given a CPU access to @paddr, it
 * returns the applicable key id (or MEM_ENC_KEY_NONE). NULL => the default
 * resolver, which returns the owner key id.
 */
void mem_enc_set_key_resolver(MemoryEncryptionEngine *eng,
                              uint32_t (*resolve)(MemoryEncryptionEngine *,
                                                  CPUState *, hwaddr,
                                                  MemTxAttrs));

/* ----------------------------------------------------------------------- */
/* Page management                                                          */
/* ----------------------------------------------------------------------- */

bool mem_enc_page_managed(MemoryEncryptionEngine *eng, RAMBlock *block,
                          ram_addr_t offset);

/*
 * Mark [@offset, @offset + @len) managed and encrypt its current plaintext
 * contents into the ciphertext backing. This is the SEV launch-update
 * transition: afterwards block->host holds ciphertext for the range.
 */
int  mem_enc_mark_managed(MemoryEncryptionEngine *eng, RAMBlock *block,
                          ram_addr_t offset, size_t len, Error **errp);

/* ----------------------------------------------------------------------- */
/* Low-level buffer transforms (tweak derived from @offset)                 */
/* ----------------------------------------------------------------------- */

int  mem_enc_encrypt_buf(MemoryEncryptionEngine *eng, RAMBlock *block,
                         ram_addr_t offset, const void *plain, void *cipher,
                         size_t len, uint32_t key_id, Error **errp);
int  mem_enc_decrypt_buf(MemoryEncryptionEngine *eng, RAMBlock *block,
                         ram_addr_t offset, const void *cipher, void *plain,
                         size_t len, uint32_t key_id, Error **errp);

/* ----------------------------------------------------------------------- */
/* CPU hot path (called from accel/tcg/cputlb.c)                            */
/* ----------------------------------------------------------------------- */

/*
 * Returns the addend the TLB entry should use for this access. For a managed
 * page this points at a decrypted plaintext working page; for an unmanaged page
 * (or no key) it returns @addend unchanged.
 */
uintptr_t mem_enc_translate(MemoryEncryptionEngine *eng, CPUState *cs,
                            MemoryRegionSection *section, hwaddr paddr,
                            hwaddr xlat, MemTxAttrs attrs, uintptr_t addend);

/* ----------------------------------------------------------------------- */
/* External (DMA/flatview) path. @key_id == MEM_ENC_KEY_NONE => raw cipher. */
/* ----------------------------------------------------------------------- */

int  mem_enc_read(MemoryEncryptionEngine *eng, RAMBlock *block,
                  ram_addr_t offset, void *dst, size_t len, uint32_t key_id,
                  Error **errp);
int  mem_enc_write(MemoryEncryptionEngine *eng, RAMBlock *block,
                   ram_addr_t offset, const void *src, size_t len,
                   uint32_t key_id, Error **errp);

/* Write back dirty working pages in the range to the backing store. */
void mem_enc_flush(MemoryEncryptionEngine *eng, RAMBlock *block,
                   ram_addr_t offset, size_t len);

/*
 * Drop working pages overlapping the range, so the next CPU access re-decrypts
 * the (possibly altered) ciphertext backing. Used after an external/DMA write.
 */
void mem_enc_invalidate(MemoryEncryptionEngine *eng, RAMBlock *block,
                        ram_addr_t offset, size_t len);

/* Stats for QMP. */
void mem_enc_get_stats(MemoryEncryptionEngine *eng, uint64_t *managed_pages,
                       uint64_t *working_pages, const char **cipher_name);

/* The owner key id (used to encrypt managed pages / as the default key). */
uint32_t mem_enc_owner_key_id(MemoryEncryptionEngine *eng);

#endif /* QEMU_MEMORY_ENCRYPTION_H */
