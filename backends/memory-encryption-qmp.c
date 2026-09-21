/*
 * QEMU Generic Memory Encryption - QMP command handlers
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"

#include "qapi/error.h"
#include "qapi/qapi-commands-memory-encryption.h"
#include "exec/cpu-common.h"
#include "exec/memattrs.h"
#include "exec/target_page.h"
#include "system/address-spaces.h"
#include "system/memory.h"
#include "system/memory-encryption.h"

/*
 * Resolve a physical address to the backing RAMBlock and
 * the absolute ram_addr of the start of the containing page. Returns NULL
 * if @phys does not map to RAM.
 *
 * NOTE: the engine currently indexes a RAMBlock's per-page state by absolute
 * ram_addr, which is correct for blocks whose base offset is 0 (the typical
 * main system RAM). Non-zero-offset blocks (e.g. highmem) are a known M1
 * limitation to be addressed by making the indexing block-relative.
 */
static RAMBlock *phys_to_ram_block(hwaddr phys, ram_addr_t *ram_addr_out)
{
    hwaddr xlat, len = 1;
    MemoryRegion *mr;

    mr = address_space_translate(&address_space_memory, phys, &xlat, &len,
                                 false, MEMTXATTRS_UNSPECIFIED);
    if (!mr || !mr->ram_block) {
        return NULL;
    }
    *ram_addr_out = memory_region_get_ram_addr(mr) + xlat;
    return mr->ram_block;
}

static char *hexstr(const void *buf, size_t len)
{
    const uint8_t *b = buf;
    char *s = g_malloc(len * 2 + 1);
    size_t i;

    for (i = 0; i < len; i++) {
        snprintf(s + 2 * i, 3, "%02x", b[i]);
    }
    return s;
}

MemoryEncryptionInfo *qmp_query_memory_encryption(Error **errp)
{
    MemoryEncryptionEngine *eng = mem_enc_get();
    MemoryEncryptionInfo *info = g_new0(MemoryEncryptionInfo, 1);
    uint64_t managed = 0, working = 0;
    const char *cipher = NULL;

    info->enabled = false;

    if (!eng) {
        return info;
    }

    mem_enc_get_stats(eng, &managed, &working, &cipher);

    info->enabled = true;
    info->cipher = g_strdup(cipher ? cipher : "unknown");
    info->has_owner_key_id = true;
    info->owner_key_id = mem_enc_owner_key_id(eng);
    info->has_managed_pages = true;
    info->managed_pages = managed;
    info->has_working_pages = true;
    info->working_pages = working;

    return info;
}

MemoryEncryptionPage *qmp_memory_encryption_dump_page(uint64_t phys,
                                                      Error **errp)
{
    MemoryEncryptionEngine *eng = mem_enc_get();
    size_t psz = qemu_target_page_size();
    MemoryEncryptionPage *page;
    RAMBlock *block;
    ram_addr_t ram_addr;
    g_autofree uint8_t *plain = NULL;
    g_autofree uint8_t *cipher = NULL;

    if (!eng) {
        error_setg(errp, "memory encryption is not enabled");
        return NULL;
    }
    if (phys % psz) {
        error_setg(errp, "phys must be page-aligned (%u bytes)",
                   (unsigned)psz);
        return NULL;
    }

    block = phys_to_ram_block(phys, &ram_addr);
    if (!block) {
        error_setg(errp, "phys 0x%" PRIx64 " is not backed by RAM", phys);
        return NULL;
    }

    plain = g_malloc(psz);
    cipher = g_malloc(psz);

    /* The ciphertext view is what an external reader sees: the raw backing. */
    cpu_physical_memory_read(phys, cipher, psz);

    /*
     * The plaintext view is what the guest CPU sees: decrypted with the owner
     * key for managed pages, raw for unmanaged pages.
     */
    if (mem_enc_read_auto(eng, phys, block, ram_addr, plain, psz,
                          errp) < 0) {
        return NULL;
    }

    page = g_new0(MemoryEncryptionPage, 1);
    page->phys = phys;
    page->managed = mem_enc_page_managed(eng, block, ram_addr);
    page->plaintext_hex = hexstr(plain, psz);
    page->ciphertext_hex = hexstr(cipher, psz);
    return page;
}

void qmp_memory_encryption_mark_managed(uint64_t phys, uint64_t size,
                                        Error **errp)
{
    MemoryEncryptionEngine *eng = mem_enc_get();
    size_t psz = qemu_target_page_size();
    RAMBlock *block;
    ram_addr_t ram_addr;

    if (!eng) {
        error_setg(errp, "memory encryption is not enabled");
        return;
    }
    if (phys % psz || size % psz || size == 0) {
        error_setg(errp, "phys and size must be non-zero multiples of the "
                   "page size (%u bytes)", (unsigned)psz);
        return;
    }

    block = phys_to_ram_block(phys, &ram_addr);
    if (!block) {
        error_setg(errp, "phys 0x%" PRIx64 " is not backed by RAM", phys);
        return;
    }
    if (ram_addr + size > block->max_length) {
        error_setg(errp, "range crosses past the end of its RAMBlock");
        return;
    }

    mem_enc_mark_managed(eng, block, ram_addr, size, errp);
}
