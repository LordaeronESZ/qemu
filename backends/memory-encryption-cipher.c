/*
 * QEMU Generic Memory Encryption - cipher backends
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"

#include "qapi/error.h"
#include "system/memory-encryption-cipher.h"

/*
 * Identity cipher
 *
 * A cryptographically trivial but faithful stand-in for the real mechanism:
 * each byte is XORed with a key byte selected by (gpa + offset). The transform
 * is reversible, key-dependent and address-dependent, so it reproduces the
 * observable behaviour we need for testing -- in particular, decrypting with
 * the wrong key yields garbage, exactly like a real tweakable cipher would.
 */

#define MEM_ENC_IDENTITY_KEYLEN 32

typedef struct MemEncIdentityCipher {
    MemEncCipher parent;
    uint8_t key[MEM_ENC_IDENTITY_KEYLEN];
    size_t keylen;
} MemEncIdentityCipher;

static int identity_set_key(MemEncCipher *c, const uint8_t *key, size_t keylen,
                            Error **errp)
{
    MemEncIdentityCipher *id = (MemEncIdentityCipher *)c;

    if (keylen == 0 || keylen > sizeof(id->key)) {
        error_setg(errp, "identity cipher: invalid key length %zu", keylen);
        return -1;
    }

    memcpy(id->key, key, keylen);
    id->keylen = keylen;
    return 0;
}

static void identity_xform(MemEncCipher *c, hwaddr gpa,
                           const void *in, void *out, size_t len)
{
    MemEncIdentityCipher *id = (MemEncIdentityCipher *)c;
    const uint8_t *src = in;
    uint8_t *dst = out;
    size_t i;

    for (i = 0; i < len; i++) {
        dst[i] = src[i] ^ id->key[(gpa + i) % id->keylen];
    }
}

static int identity_encrypt(MemEncCipher *c, hwaddr gpa,
                            const void *in, void *out, size_t len,
                            Error **errp)
{
    identity_xform(c, gpa, in, out, len);
    return 0;
}

static int identity_decrypt(MemEncCipher *c, hwaddr gpa,
                            const void *in, void *out, size_t len,
                            Error **errp)
{
    identity_xform(c, gpa, in, out, len);
    return 0;
}

static void identity_free(MemEncCipher *c)
{
    g_free(c);
}

static const MemEncCipherOps identity_ops = {
    .name = "identity",
    .set_key = identity_set_key,
    .encrypt = identity_encrypt,
    .decrypt = identity_decrypt,
    .free = identity_free,
};

MemEncCipher *mem_enc_cipher_identity_new(void)
{
    MemEncIdentityCipher *id = g_new0(MemEncIdentityCipher, 1);
    static const uint8_t default_key[MEM_ENC_IDENTITY_KEYLEN] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    };

    id->parent.ops = &identity_ops;
    memcpy(id->key, default_key, sizeof(default_key));
    id->keylen = sizeof(default_key);
    return &id->parent;
}

/*
 * AES-256-XTS
 *
 * Wired to QEMU's crypto/ subsystem in a later milestone. For now provide a
 * placeholder so the cipher-name property and the factory are well defined.
 */
MemEncCipher *mem_enc_cipher_aes_xts_new(void)
{
    return NULL;
}

MemEncCipher *mem_enc_cipher_new(const char *name, Error **errp)
{
    if (g_str_equal(name, "identity")) {
        return mem_enc_cipher_identity_new();
    }
    if (g_str_equal(name, "aes-256-xts")) {
        MemEncCipher *c = mem_enc_cipher_aes_xts_new();
        if (!c) {
            error_setg(errp, "cipher '%s' is not implemented in this build",
                       name);
        }
        return c;
    }

    error_setg(errp, "unknown memory-encryption cipher '%s'", name);
    return NULL;
}
