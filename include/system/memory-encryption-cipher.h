/*
 * QEMU Generic Memory Encryption - cipher backend interface
 *
 * This describes the pluggable tweakable block cipher used by the generic
 * memory-encryption core to transform page contents. The tweak is derived from
 * the guest physical address of the page, so identical plaintext on two
 * different pages yields different ciphertext (matching AMD SEV behaviour).
 *
 * This is a pure-software simulation facility. It provides no real
 * confidentiality: the host can observe plaintext RAM by design. It exists to
 * let confidential-computing software stacks be developed and tested on TCG
 * without dedicated encryption hardware.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef QEMU_MEMORY_ENCRYPTION_CIPHER_H
#define QEMU_MEMORY_ENCRYPTION_CIPHER_H

#include "qapi/error.h"
#include "exec/hwaddr.h"

typedef struct MemEncCipher MemEncCipher;

typedef struct MemEncCipherOps {
    const char *name;

    /*
     * Install the key. For AES-256-XTS this is the 64-byte (2 x 32) key as
     * required by the XTS key-length rule.
     */
    int (*set_key)(MemEncCipher *c, const uint8_t *key, size_t keylen,
                   Error **errp);

    /*
     * Encrypt/decrypt @len bytes that reside at guest physical address @gpa.
     * @len must be a multiple of the cipher's block size; for a full page @gpa
     * should be page-aligned. @in and @out may alias.
     */
    int (*encrypt)(MemEncCipher *c, hwaddr gpa,
                   const void *in, void *out, size_t len, Error **errp);
    int (*decrypt)(MemEncCipher *c, hwaddr gpa,
                   const void *in, void *out, size_t len, Error **errp);

    void (*free)(MemEncCipher *c);
} MemEncCipherOps;

struct MemEncCipher {
    const MemEncCipherOps *ops;
};

static inline int mem_enc_cipher_set_key(MemEncCipher *c, const uint8_t *key,
                                         size_t keylen, Error **errp)
{
    return c->ops->set_key(c, key, keylen, errp);
}

static inline int mem_enc_cipher_encrypt(MemEncCipher *c, hwaddr gpa,
                                         const void *in, void *out, size_t len,
                                         Error **errp)
{
    return c->ops->encrypt(c, gpa, in, out, len, errp);
}

static inline int mem_enc_cipher_decrypt(MemEncCipher *c, hwaddr gpa,
                                         const void *in, void *out, size_t len,
                                         Error **errp)
{
    return c->ops->decrypt(c, gpa, in, out, len, errp);
}

static inline void mem_enc_cipher_free(MemEncCipher *c)
{
    if (c) {
        c->ops->free(c);
    }
}

/*
 * Constructors. The identity cipher is a trivial, reversible XOR intended for
 * fast testing; the aes-xts cipher is the realistic implementation backed by
 * QEMU's crypto/ subsystem.
 */
MemEncCipher *mem_enc_cipher_identity_new(void);
MemEncCipher *mem_enc_cipher_aes_xts_new(void);

/*
 * Look up a cipher constructor by the name exposed in -object/QMP.
 * Returns NULL (with @errp set) for an unknown name.
 */
MemEncCipher *mem_enc_cipher_new(const char *name, Error **errp);

#endif /* QEMU_MEMORY_ENCRYPTION_CIPHER_H */
