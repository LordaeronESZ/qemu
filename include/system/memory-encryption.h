/*
 * QEMU Generic Memory Encryption - arch-independent engine interface
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
 * the raw ciphertext backing (such as DMA access).
 */
#define MEM_ENC_KEY_NONE 0u

typedef struct MemoryEncryptionEngine MemoryEncryptionEngine;

/* The active engine, or NULL when no encryption core is configured. */
MemoryEncryptionEngine *mem_enc_get(void);

/* Engine lifecycle (called by the -object wrapper's complete hook) */
MemoryEncryptionEngine *mem_enc_engine_new(const char *cipher_name,
                                           uint32_t owner_key_id);

void mem_enc_engine_free(MemoryEncryptionEngine *eng);

void mem_enc_engine_activate(MemoryEncryptionEngine *eng);

int mem_enc_set_key(MemoryEncryptionEngine *eng, uint32_t key_id,
                    const uint8_t *key, size_t keylen, Error **errp);

bool mem_enc_has_key(MemoryEncryptionEngine *eng, uint32_t key_id);

void mem_enc_set_key_resolver(MemoryEncryptionEngine *eng,
                              uint32_t (*resolve)(MemoryEncryptionEngine *,
                                                  CPUState *, hwaddr,
                                                  MemTxAttrs));

bool mem_enc_page_managed(MemoryEncryptionEngine *eng, RAMBlock *block,
                          ram_addr_t offset);

int mem_enc_mark_managed(MemoryEncryptionEngine *eng, RAMBlock *block,
                         ram_addr_t offset, size_t len, Error **errp);

/*
 * Returns the addend the TLB entry should use for this access. For a managed
 * page this points at a decrypted plaintext working page; for an unmanaged page
 * (or no key) it returns @addend unchanged.
 */
uintptr_t mem_enc_translate(MemoryEncryptionEngine *eng, CPUState *cs,
                            MemoryRegionSection *section, hwaddr paddr,
                            hwaddr xlat, MemTxAttrs attrs, uintptr_t addend);

int mem_enc_read(MemoryEncryptionEngine *eng, RAMBlock *block,
                 ram_addr_t offset, void *dst, size_t len, uint32_t key_id,
                 Error **errp);

int mem_enc_write(MemoryEncryptionEngine *eng, RAMBlock *block,
                  ram_addr_t offset, const void *src, size_t len,
                  uint32_t key_id, Error **errp);

void mem_enc_flush(MemoryEncryptionEngine *eng, RAMBlock *block,
                   ram_addr_t offset, size_t len);

void mem_enc_invalidate(MemoryEncryptionEngine *eng, RAMBlock *block,
                        ram_addr_t offset, size_t len);

void mem_enc_flush_and_invalidate_all(MemoryEncryptionEngine *eng);

void mem_enc_get_stats(MemoryEncryptionEngine *eng, uint64_t *managed_pages,
                       uint64_t *working_pages, const char **cipher_name);

uint32_t mem_enc_owner_key_id(MemoryEncryptionEngine *eng);

#endif /* QEMU_MEMORY_ENCRYPTION_H */
