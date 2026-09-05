/*
 * QEMU Generic Memory Encryption - cipher backends
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"

#include "qapi/error.h"
#include "qemu/bswap.h"
#include "crypto/cipher.h"
#include "system/memory-encryption-cipher.h"

/*
 * Identity cipher
 *
 * A cryptographically trivial but faithful stand-in for the real mechanism:
 * each byte is XORed with a key byte selected by (phys + offset). The transform
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

static void identity_xform(MemEncCipher *c, hwaddr phys,
                           const void *in, void *out, size_t len)
{
    MemEncIdentityCipher *id = (MemEncIdentityCipher *)c;
    const uint8_t *src = in;
    uint8_t *dst = out;
    size_t i;

    for (i = 0; i < len; i++) {
        dst[i] = src[i] ^ id->key[(phys + i) % id->keylen];
    }
}

static int identity_encrypt(MemEncCipher *c, hwaddr phys,
                            const void *in, void *out, size_t len,
                            Error **errp)
{
    identity_xform(c, phys, in, out, len);
    return 0;
}

static int identity_decrypt(MemEncCipher *c, hwaddr phys,
                            const void *in, void *out, size_t len,
                            Error **errp)
{
    identity_xform(c, phys, in, out, len);
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
 * AES-256-XTS, wired to QEMU's crypto/ subsystem (QCryptoCipher).
 *
 * This is the realistic tweakable cipher used for memory encryption (the same
 * mode AMD SEV uses). XTS encrypts a "data unit" under a tweak (the data-unit
 * number); here each managed page is one data unit, and the tweak is derived
 * from the page's physical (guest-machine) address, so identical plaintext on two pages
 * yields different ciphertext.
 *
 * Requires a crypto backend (nettle/gcrypt/gnutls) compiled into QEMU. If no
 * backend is present, set_key reports a clear error so the object fails to
 * realise rather than silently producing no encryption.
 */
#define MEM_ENC_AES_XTS_KEYLEN 64   /* 2 x 32-byte AES-256 keys */

typedef struct MemEncAesXtsCipher {
    MemEncCipher parent;
    QCryptoCipher *cipher;     /* created lazily in set_key */
} MemEncAesXtsCipher;

static int aes_xts_set_key(MemEncCipher *c, const uint8_t *key, size_t keylen,
                           Error **errp)
{
    MemEncAesXtsCipher *a = (MemEncAesXtsCipher *)c;
    QCryptoCipher *qc;

    if (!qcrypto_cipher_supports(QCRYPTO_CIPHER_ALGO_AES_256,
                                 QCRYPTO_CIPHER_MODE_XTS)) {
        error_setg(errp, "AES-256-XTS requires a crypto backend "
                   "(nettle, gcrypt or gnutls); rebuild QEMU with one enabled");
        return -1;
    }
    if (keylen != MEM_ENC_AES_XTS_KEYLEN) {
        error_setg(errp, "AES-256-XTS requires a %d-byte (2x32) key, got %zu",
                   MEM_ENC_AES_XTS_KEYLEN, keylen);
        return -1;
    }

    qc = qcrypto_cipher_new(QCRYPTO_CIPHER_ALGO_AES_256,
                            QCRYPTO_CIPHER_MODE_XTS, key, keylen, errp);
    if (!qc) {
        return -1;
    }
    qcrypto_cipher_free(a->cipher);
    a->cipher = qc;
    return 0;
}

/* Build the 16-byte XTS tweak (data-unit number) from the page phys. */
static void aes_xts_tweak(hwaddr phys, uint8_t tweak[16])
{
    memset(tweak, 0, 16);
    stq_le_p(tweak, (uint64_t)phys);
}

static int aes_xts_encrypt(MemEncCipher *c, hwaddr phys, const void *in,
                           void *out, size_t len, Error **errp)
{
    MemEncAesXtsCipher *a = (MemEncAesXtsCipher *)c;
    uint8_t tweak[16];

    if (!a->cipher) {
        error_setg(errp, "AES-256-XTS cipher has no key set");
        return -1;
    }
    aes_xts_tweak(phys, tweak);
    if (qcrypto_cipher_setiv(a->cipher, tweak, sizeof(tweak), errp) < 0) {
        return -1;
    }
    return qcrypto_cipher_encrypt(a->cipher, in, out, len, errp);
}

static int aes_xts_decrypt(MemEncCipher *c, hwaddr phys, const void *in,
                           void *out, size_t len, Error **errp)
{
    MemEncAesXtsCipher *a = (MemEncAesXtsCipher *)c;
    uint8_t tweak[16];

    if (!a->cipher) {
        error_setg(errp, "AES-256-XTS cipher has no key set");
        return -1;
    }
    aes_xts_tweak(phys, tweak);
    if (qcrypto_cipher_setiv(a->cipher, tweak, sizeof(tweak), errp) < 0) {
        return -1;
    }
    return qcrypto_cipher_decrypt(a->cipher, in, out, len, errp);
}

static void aes_xts_free(MemEncCipher *c)
{
    MemEncAesXtsCipher *a = (MemEncAesXtsCipher *)c;

    qcrypto_cipher_free(a->cipher);
    g_free(c);
}

static const MemEncCipherOps aes_xts_ops = {
    .name = "aes-256-xts",
    .set_key = aes_xts_set_key,
    .encrypt = aes_xts_encrypt,
    .decrypt = aes_xts_decrypt,
    .free = aes_xts_free,
};

MemEncCipher *mem_enc_cipher_aes_xts_new(void)
{
    MemEncAesXtsCipher *a = g_new0(MemEncAesXtsCipher, 1);

    a->parent.ops = &aes_xts_ops;
    return &a->parent;
}

MemEncCipher *mem_enc_cipher_new(const char *name, Error **errp)
{
    if (g_str_equal(name, "identity")) {
        return mem_enc_cipher_identity_new();
    }
    if (g_str_equal(name, "aes-256-xts")) {
        return mem_enc_cipher_aes_xts_new();
    }

    error_setg(errp, "unknown memory-encryption cipher '%s'", name);
    return NULL;
}
