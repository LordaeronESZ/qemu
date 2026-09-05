/*
 * QEMU Generic Memory Encryption - cipher backend interface
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

    int (*set_key)(MemEncCipher *c, const uint8_t *key, size_t keylen,
                   Error **errp);

    int (*encrypt)(MemEncCipher *c, hwaddr phys,
                   const void *in, void *out, size_t len, Error **errp);

    int (*decrypt)(MemEncCipher *c, hwaddr phys,
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

static inline int mem_enc_cipher_encrypt(MemEncCipher *c, hwaddr phys,
                                         const void *in, void *out, size_t len,
                                         Error **errp)
{
    return c->ops->encrypt(c, phys, in, out, len, errp);
}

static inline int mem_enc_cipher_decrypt(MemEncCipher *c, hwaddr phys,
                                         const void *in, void *out, size_t len,
                                         Error **errp)
{
    return c->ops->decrypt(c, phys, in, out, len, errp);
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
