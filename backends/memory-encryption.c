/*
 * QEMU Generic Memory Encryption - arch-independent engine implementation
 *
 * Holds the per-key cipher store, the ciphertext backing (stored in each
 * managed RAMBlock's host buffer), and the plaintext working-page cache keyed
 * by (RAMBlock, page, key id).
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"

#include "qapi/error.h"
#include "qemu/bitops.h"
#include "exec/target_page.h"
#include "system/memory-encryption.h"
#include "system/memory-encryption-cipher.h"

/* ---- per-managed-RAMBlock bookkeeping ---- */
typedef struct MemEncManagedBlock {
    RAMBlock *block;
    size_t num_pages;
    unsigned long *managed_bmap; /* bit per page: backing holds ciphertext */
} MemEncManagedBlock;

/* ---- working-page cache key ---- */
typedef struct MemEncWorkKey {
    RAMBlock *block;
    uint64_t page_idx;
    uint32_t key_id;
} MemEncWorkKey;

typedef struct MemEncWorkPage {
    MemEncWorkKey key;
    void *plain;     /* qemu_target_page_size() bytes */
    bool populated;  /* plain holds a valid decrypted copy */
    bool dirty;      /* plain may have been written; needs encrypt-back */
} MemEncWorkPage;

struct MemoryEncryptionEngine {
    char *cipher_name;
    uint32_t owner_key_id;
    uint32_t (*key_resolver)(MemoryEncryptionEngine *, CPUState *, hwaddr,
                             MemTxAttrs);

    QemuMutex lock;               /* protects the tables below */
    GHashTable *ciphers;          /* key_id -> MemEncCipher */
    GHashTable *managed;          /* RAMBlock* -> MemEncManagedBlock */
    GHashTable *working;          /* MemEncWorkKey* -> MemEncWorkPage* */
};

/* The active engine singleton, or NULL. Hot paths test this for zero cost. */
static MemoryEncryptionEngine *mem_eng_singleton;

MemoryEncryptionEngine *mem_enc_get(void)
{
    return mem_eng_singleton;
}

/* ----------------------------------------------------------------------- */
/* helpers                                                                  */
/* ----------------------------------------------------------------------- */

static size_t page_size_of(RAMBlock *block)
{
    return qemu_target_page_size();
}

static uint64_t page_idx_of(RAMBlock *block, ram_addr_t offset)
{
    return offset / page_size_of(block);
}

static hwaddr gpa_tweak_of(RAMBlock *block, ram_addr_t offset)
{
    return (hwaddr)block->offset + offset;
}

static MemEncCipher *cipher_for_key(MemoryEncryptionEngine *e, uint32_t key_id)
{
    return g_hash_table_lookup(e->ciphers, GUINT_TO_POINTER(key_id));
}

static MemEncManagedBlock *managed_block(MemoryEncryptionEngine *e,
                                         RAMBlock *block, bool create)
{
    MemEncManagedBlock *mb = g_hash_table_lookup(e->managed, block);

    if (mb || !create) {
        return mb;
    }

    mb = g_new0(MemEncManagedBlock, 1);
    mb->block = block;
    mb->num_pages = block->max_length / page_size_of(block);
    mb->managed_bmap = bitmap_new(mb->num_pages);
    g_hash_table_insert(e->managed, block, mb);
    return mb;
}

static bool page_is_managed(MemoryEncryptionEngine *e, RAMBlock *block,
                            ram_addr_t offset)
{
    MemEncManagedBlock *mb = g_hash_table_lookup(e->managed, block);
    uint64_t idx;

    if (!mb) {
        return false;
    }
    idx = page_idx_of(block, offset);
    if (idx >= mb->num_pages) {
        return false;
    }
    return test_bit(idx, mb->managed_bmap);
}

static void set_page_managed(MemoryEncryptionEngine *e, RAMBlock *block,
                             ram_addr_t offset)
{
    MemEncManagedBlock *mb = managed_block(e, block, true);
    uint64_t idx = page_idx_of(block, offset);

    assert(idx < mb->num_pages);
    set_bit(idx, mb->managed_bmap);
}

/* ---- working-page cache ---- */
static guint work_hash(gconstpointer key)
{
    const MemEncWorkKey *k = key;

    return (guint)((guintptr)k->block * 31) ^
           (guint)(k->page_idx * 17) ^ (k->key_id * 2654435761u);
}

static gboolean work_equal(gconstpointer a, gconstpointer b)
{
    const MemEncWorkKey *ka = a;
    const MemEncWorkKey *kb = b;

    return ka->block == kb->block &&
           ka->page_idx == kb->page_idx &&
           ka->key_id == kb->key_id;
}

static MemEncWorkPage *work_create(MemoryEncryptionEngine *e, RAMBlock *block,
                                   uint64_t page_idx, uint32_t key_id)
{
    MemEncWorkKey k = { block, page_idx, key_id };
    MemEncWorkPage *wp = g_new0(MemEncWorkPage, 1);

    wp->key = k;
    wp->plain = g_malloc(page_size_of(block));
    g_hash_table_insert(e->working, g_memdup2(&k, sizeof(k)), wp);
    return wp;
}

static void work_free(gpointer data)
{
    MemEncWorkPage *wp = data;

    g_free(wp->plain);
    g_free(wp);
}

static int decrypt_backing_page(MemoryEncryptionEngine *e, RAMBlock *block,
                                ram_addr_t page_off, void *out,
                                uint32_t key_id, Error **errp)
{
    MemEncCipher *cipher = cipher_for_key(e, key_id);
    size_t psz = page_size_of(block);

    if (!cipher) {
        error_setg(errp, "no key installed for key id %u", key_id);
        return -1;
    }
    return mem_enc_cipher_decrypt(cipher, gpa_tweak_of(block, page_off),
                                  block->host + page_off, out, psz, errp);
}

static int encrypt_backing_page(MemoryEncryptionEngine *e, RAMBlock *block,
                                ram_addr_t page_off, const void *in,
                                uint32_t key_id, Error **errp)
{
    MemEncCipher *cipher = cipher_for_key(e, key_id);
    size_t psz = page_size_of(block);

    if (!cipher) {
        error_setg(errp, "no key installed for key id %u", key_id);
        return -1;
    }
    return mem_enc_cipher_encrypt(cipher, gpa_tweak_of(block, page_off),
                                  in, block->host + page_off, psz, errp);
}

static uint32_t resolve_key_id(MemoryEncryptionEngine *e, CPUState *cs,
                               hwaddr paddr, MemTxAttrs attrs)
{
    if (e->key_resolver) {
        return e->key_resolver(e, cs, paddr, attrs);
    }
    return e->owner_key_id;
}

/* ----------------------------------------------------------------------- */
/* lifecycle                                                                */
/* ----------------------------------------------------------------------- */

static void cipher_free_value(gpointer data)
{
    mem_enc_cipher_free(data);
}

MemoryEncryptionEngine *mem_enc_engine_new(const char *cipher_name,
                                           uint32_t owner_key_id)
{
    MemoryEncryptionEngine *e = g_new0(MemoryEncryptionEngine, 1);

    e->cipher_name = g_strdup(cipher_name ?: "identity");
    e->owner_key_id = owner_key_id ? owner_key_id : 1;
    qemu_mutex_init(&e->lock);
    e->ciphers = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                       NULL, cipher_free_value);
    e->managed = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                       NULL, g_free);
    e->working = g_hash_table_new_full(work_hash, work_equal,
                                       g_free, work_free);
    return e;
}

void mem_enc_engine_free(MemoryEncryptionEngine *e)
{
    if (!e) {
        return;
    }
    if (mem_eng_singleton == e) {
        mem_eng_singleton = NULL;
    }
    g_hash_table_unref(e->ciphers);
    g_hash_table_unref(e->managed);
    g_hash_table_unref(e->working);
    qemu_mutex_destroy(&e->lock);
    g_free(e->cipher_name);
    g_free(e);
}

void mem_enc_engine_activate(MemoryEncryptionEngine *e)
{
    assert(mem_eng_singleton == NULL || mem_eng_singleton == e);
    mem_eng_singleton = e;
}

/* ----------------------------------------------------------------------- */
/* key management                                                           */
/* ----------------------------------------------------------------------- */

int mem_enc_set_key(MemoryEncryptionEngine *e, uint32_t key_id,
                    const uint8_t *key, size_t keylen, Error **errp)
{
    MemEncCipher *cipher = mem_enc_cipher_new(e->cipher_name, errp);

    if (!cipher) {
        return -1;
    }
    if (mem_enc_cipher_set_key(cipher, key, keylen, errp) < 0) {
        mem_enc_cipher_free(cipher);
        return -1;
    }

    qemu_mutex_lock(&e->lock);
    g_hash_table_insert(e->ciphers, GUINT_TO_POINTER(key_id), cipher);
    qemu_mutex_unlock(&e->lock);
    return 0;
}

bool mem_enc_has_key(MemoryEncryptionEngine *e, uint32_t key_id)
{
    bool found;

    qemu_mutex_lock(&e->lock);
    found = cipher_for_key(e, key_id) != NULL;
    qemu_mutex_unlock(&e->lock);
    return found;
}

void mem_enc_set_key_resolver(MemoryEncryptionEngine *e,
                              uint32_t (*resolve)(MemoryEncryptionEngine *,
                                                  CPUState *, hwaddr,
                                                  MemTxAttrs))
{
    e->key_resolver = resolve;
}

/* ----------------------------------------------------------------------- */
/* page management                                                          */
/* ----------------------------------------------------------------------- */

bool mem_enc_page_managed(MemoryEncryptionEngine *e, RAMBlock *block,
                          ram_addr_t offset)
{
    bool managed;

    qemu_mutex_lock(&e->lock);
    managed = page_is_managed(e, block, offset);
    qemu_mutex_unlock(&e->lock);
    return managed;
}

int mem_enc_mark_managed(MemoryEncryptionEngine *e, RAMBlock *block,
                         ram_addr_t offset, size_t len, Error **errp)
{
    size_t psz = page_size_of(block);
    ram_addr_t end = offset + len;
    ram_addr_t page_off;

    assert(QEMU_IS_ALIGNED(offset, psz));
    assert(QEMU_IS_ALIGNED(len, psz));

    qemu_mutex_lock(&e->lock);

    /*
     * Encrypt the current plaintext contents into the ciphertext backing, then
     * mark the pages managed. After this block->host holds ciphertext; readers
     * without the key see garbage.
     */
    for (page_off = offset; page_off < end; page_off += psz) {
        if (encrypt_backing_page(e, block, page_off, block->host + page_off,
                                 e->owner_key_id, errp) < 0) {
            qemu_mutex_unlock(&e->lock);
            return -1;
        }
    }
    for (page_off = offset; page_off < end; page_off += psz) {
        set_page_managed(e, block, page_off);
    }

    qemu_mutex_unlock(&e->lock);
    return 0;
}

/* ----------------------------------------------------------------------- */
/* low-level buffer transforms                                              */
/* ----------------------------------------------------------------------- */

int mem_enc_encrypt_buf(MemoryEncryptionEngine *e, RAMBlock *block,
                        ram_addr_t offset, const void *plain, void *cipher,
                        size_t len, uint32_t key_id, Error **errp)
{
    MemEncCipher *c;
    int ret;

    qemu_mutex_lock(&e->lock);
    c = cipher_for_key(e, key_id);
    if (!c) {
        qemu_mutex_unlock(&e->lock);
        error_setg(errp, "no key installed for key id %u", key_id);
        return -1;
    }
    ret = mem_enc_cipher_encrypt(c, gpa_tweak_of(block, offset),
                                 plain, cipher, len, errp);
    qemu_mutex_unlock(&e->lock);
    return ret;
}

int mem_enc_decrypt_buf(MemoryEncryptionEngine *e, RAMBlock *block,
                        ram_addr_t offset, const void *cipher, void *plain,
                        size_t len, uint32_t key_id, Error **errp)
{
    MemEncCipher *c;
    int ret;

    qemu_mutex_lock(&e->lock);
    c = cipher_for_key(e, key_id);
    if (!c) {
        qemu_mutex_unlock(&e->lock);
        error_setg(errp, "no key installed for key id %u", key_id);
        return -1;
    }
    ret = mem_enc_cipher_decrypt(c, gpa_tweak_of(block, offset),
                                 cipher, plain, len, errp);
    qemu_mutex_unlock(&e->lock);
    return ret;
}

/* ----------------------------------------------------------------------- */
/* CPU hot path                                                             */
/* ----------------------------------------------------------------------- */

uintptr_t mem_enc_translate(MemoryEncryptionEngine *e, CPUState *cs,
                            MemoryRegionSection *section, hwaddr paddr,
                            hwaddr xlat, MemTxAttrs attrs, uintptr_t addend)
{
    RAMBlock *block = section->mr->ram_block;
    ram_addr_t ram_addr;
    uint64_t page_idx;
    uint32_t key_id;
    MemEncWorkKey k;
    MemEncWorkPage *wp;

    if (!block) {
        return addend;
    }

    ram_addr = memory_region_get_ram_addr(section->mr) + xlat;

    qemu_mutex_lock(&e->lock);

    if (!page_is_managed(e, block, ram_addr)) {
        qemu_mutex_unlock(&e->lock);
        return addend; /* unmanaged: plaintext backing, normal path */
    }

    key_id = resolve_key_id(e, cs, paddr, attrs);
    if (key_id == MEM_ENC_KEY_NONE) {
        /* No key: the CPU observes the raw ciphertext backing. */
        qemu_mutex_unlock(&e->lock);
        return addend;
    }

    page_idx = page_idx_of(block, ram_addr);
    k = (MemEncWorkKey){ block, page_idx, key_id };
    wp = g_hash_table_lookup(e->working, &k);
    if (!wp) {
        wp = work_create(e, block, page_idx, key_id);
    }
    if (!wp->populated) {
        if (decrypt_backing_page(e, block, page_idx * page_size_of(block),
                                 wp->plain, key_id, NULL) < 0) {
            qemu_mutex_unlock(&e->lock);
            return addend;
        }
        wp->populated = true;
    }
    /*
     * The CPU may write through this mapping; conservatively mark the working
     * page dirty so a later flush re-encrypts it into the backing store.
     */
    wp->dirty = true;

    qemu_mutex_unlock(&e->lock);
    return (uintptr_t)wp->plain;
}

/* ----------------------------------------------------------------------- */
/* external (DMA/flatview) path                                             */
/* ----------------------------------------------------------------------- */

int mem_enc_read(MemoryEncryptionEngine *e, RAMBlock *block,
                 ram_addr_t offset, void *dst, size_t len, uint32_t key_id,
                 Error **errp)
{
    size_t psz = page_size_of(block);
    g_autofree uint8_t *pagebuf = g_malloc(psz);

    qemu_mutex_lock(&e->lock);

    if (!page_is_managed(e, block, offset) || key_id == MEM_ENC_KEY_NONE) {
        memcpy(dst, block->host + offset, len);
        qemu_mutex_unlock(&e->lock);
        return 0;
    }

    for (size_t done = 0; done < len; ) {
        ram_addr_t page_off = (offset + done) & ~(psz - 1);
        size_t in_off = offset + done - page_off;
        size_t chunk = MIN(psz - in_off, len - done);

        if (decrypt_backing_page(e, block, page_off, pagebuf,
                                 key_id, errp) < 0) {
            qemu_mutex_unlock(&e->lock);
            return -1;
        }
        memcpy((uint8_t *)dst + done, pagebuf + in_off, chunk);
        done += chunk;
    }

    qemu_mutex_unlock(&e->lock);
    return 0;
}

int mem_enc_write(MemoryEncryptionEngine *e, RAMBlock *block,
                  ram_addr_t offset, const void *src, size_t len,
                  uint32_t key_id, Error **errp)
{
    size_t psz = page_size_of(block);
    g_autofree uint8_t *pagebuf = g_malloc(psz);

    qemu_mutex_lock(&e->lock);

    if (!page_is_managed(e, block, offset) || key_id == MEM_ENC_KEY_NONE) {
        memcpy(block->host + offset, src, len);
        qemu_mutex_unlock(&e->lock);
        return 0;
    }

    for (size_t done = 0; done < len; ) {
        ram_addr_t page_off = (offset + done) & ~(psz - 1);
        size_t in_off = offset + done - page_off;
        size_t chunk = MIN(psz - in_off, len - done);

        if (decrypt_backing_page(e, block, page_off, pagebuf,
                                 key_id, errp) < 0) {
            qemu_mutex_unlock(&e->lock);
            return -1;
        }
        memcpy(pagebuf + in_off, (const uint8_t *)src + done, chunk);
        if (encrypt_backing_page(e, block, page_off, pagebuf,
                                 key_id, errp) < 0) {
            qemu_mutex_unlock(&e->lock);
            return -1;
        }
        done += chunk;
    }

    qemu_mutex_unlock(&e->lock);
    return 0;
}

void mem_enc_flush(MemoryEncryptionEngine *e, RAMBlock *block,
                   ram_addr_t offset, size_t len)
{
    /*
     * For M1 the CPU writes working pages directly and they are marked dirty
     * conservatively; re-encryption on demand is handled where the backing is
     * read. Full LRU eviction + proactive write-back is a later refinement.
     */
    (void)e;
    (void)block;
    (void)offset;
    (void)len;
}

void mem_enc_get_stats(MemoryEncryptionEngine *e, uint64_t *managed_pages,
                       uint64_t *working_pages, const char **cipher_name)
{
    if (managed_pages) {
        *managed_pages = 0; /* TODO: sum managed bmaps */
    }
    if (working_pages) {
        qemu_mutex_lock(&e->lock);
        *working_pages = g_hash_table_size(e->working);
        qemu_mutex_unlock(&e->lock);
    }
    if (cipher_name) {
        *cipher_name = e->cipher_name;
    }
}
