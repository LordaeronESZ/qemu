/*
 * QEMU Generic Memory Encryption - cipher mechanism unit tests
 *
 * These tests prove the core property the whole framework rests on: the same
 * ciphertext decrypts to plaintext with the correct key and to garbage with the
 * wrong key.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"

#include "qapi/error.h"
#include "system/memory-encryption-cipher.h"

#define PAGE 4096

static MemEncCipher *make_identity_cipher(const uint8_t *key, size_t keylen)
{
    MemEncCipher *c = mem_enc_cipher_identity_new();

    g_assert(mem_enc_cipher_set_key(c, key, keylen, &error_abort) == 0);
    return c;
}

/*
 * The defining behaviour: decrypting with the correct key yields plaintext,
 * decrypting the same ciphertext with a different key yields garbage.
 */
static void test_wrong_key_yields_garbage(void)
{
    static const uint8_t key_a[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    static const uint8_t key_b[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const hwaddr phys = 0x100000;
    g_autofree uint8_t *plain = g_malloc(PAGE);
    g_autofree uint8_t *cipher = g_malloc(PAGE);
    g_autofree uint8_t *decoded_ok = g_malloc(PAGE);
    g_autofree uint8_t *decoded_wrong = g_malloc(PAGE);
    MemEncCipher *a = make_identity_cipher(key_a, sizeof(key_a));
    MemEncCipher *b = make_identity_cipher(key_b, sizeof(key_b));

    /* Distinct, non-trivial plaintext. */
    for (int i = 0; i < PAGE; i++) {
        plain[i] = (uint8_t)(i * 31 + 7);
    }

    /* Encrypt with key A. */
    g_assert(mem_enc_cipher_encrypt(a, phys, plain, cipher, PAGE,
                                    &error_abort) == 0);

    /* Ciphertext must differ from plaintext. */
    g_assert(memcmp(plain, cipher, PAGE) != 0);

    /* Correct key decrypts back to plaintext. */
    g_assert(mem_enc_cipher_decrypt(a, phys, cipher, decoded_ok, PAGE,
                                    &error_abort) == 0);
    g_assert(memcmp(plain, decoded_ok, PAGE) == 0);

    /* Wrong key decrypts to garbage (differs from plaintext). */
    g_assert(mem_enc_cipher_decrypt(b, phys, cipher, decoded_wrong, PAGE,
                                    &error_abort) == 0);
    g_assert(memcmp(plain, decoded_wrong, PAGE) != 0);

    mem_enc_cipher_free(a);
    mem_enc_cipher_free(b);
}

/* Round-trip correctness for a couple of addresses. */
static void test_roundtrip(void)
{
    static const uint8_t key[16] = { 0x01, 0x23, 0x45, 0x67, 0x89 };
    g_autofree uint8_t *plain = g_malloc(PAGE);
    g_autofree uint8_t *cipher = g_malloc(PAGE);
    g_autofree uint8_t *back = g_malloc(PAGE);
    MemEncCipher *c = make_identity_cipher(key, sizeof(key));
    hwaddr phys_addrs[] = { 0, 0x1000, 0x1ffff000 };

    for (size_t s = 0; s < ARRAY_SIZE(phys_addrs); s++) {
        for (int i = 0; i < PAGE; i++) {
            plain[i] = (uint8_t)(i + s);
        }
        g_assert(mem_enc_cipher_encrypt(c, phys_addrs[s], plain, cipher, PAGE,
                                        &error_abort) == 0);
        g_assert(memcmp(plain, cipher, PAGE) != 0);
        g_assert(mem_enc_cipher_decrypt(c, phys_addrs[s], cipher, back, PAGE,
                                        &error_abort) == 0);
        g_assert(memcmp(plain, back, PAGE) == 0);
    }

    mem_enc_cipher_free(c);
}

/*
 * Address-dependence: the same plaintext at two addresses yields two different
 * ciphertexts (the tweak that derived from address).
 */
static void test_address_dependence(void)
{
    static const uint8_t key[16] = {
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    };
    g_autofree uint8_t *plain = g_malloc(PAGE);
    g_autofree uint8_t *c0 = g_malloc(PAGE);
    g_autofree uint8_t *c1 = g_malloc(PAGE);
    MemEncCipher *c = make_identity_cipher(key, sizeof(key));

    memset(plain, 0x5a, PAGE);
    g_assert(mem_enc_cipher_encrypt(c, 0x1000, plain, c0, PAGE,
                                    &error_abort) == 0);
    g_assert(mem_enc_cipher_encrypt(c, 0x1001, plain, c1, PAGE,
                                    &error_abort) == 0);
    g_assert(memcmp(c0, c1, PAGE) != 0);

    mem_enc_cipher_free(c);
}

/* AES-256-XTS test, same to identity test. */
static void test_aes_256_xts(void)
{
    uint8_t key_a[64], key_b[64];
    const hwaddr phys = 0x100000;
    g_autofree uint8_t *plain = g_malloc(PAGE);
    g_autofree uint8_t *cipher = g_malloc(PAGE);
    g_autofree uint8_t *dec_ok = g_malloc(PAGE);
    g_autofree uint8_t *dec_wrong = g_malloc(PAGE);
    g_autofree uint8_t *cipher2 = g_malloc(PAGE);
    MemEncCipher *a, *b;
    Error *err = NULL;

    for (int i = 0; i < 64; i++) {
        key_a[i] = (uint8_t)i;
        key_b[i] = (uint8_t)(0xc0 ^ i);
    }

    a = mem_enc_cipher_new("aes-256-xts", &err);
    g_assert(a != NULL);
    if (mem_enc_cipher_set_key(a, key_a, sizeof(key_a), &err) < 0) {
        g_test_skip("AES-256-XTS needs a crypto backend (none in this build)");
        error_free(err);
        mem_enc_cipher_free(a);
        return;
    }

    b = mem_enc_cipher_new("aes-256-xts", &error_abort);
    g_assert(mem_enc_cipher_set_key(b, key_b, sizeof(key_b),
                                    &error_abort) == 0);

    for (int i = 0; i < PAGE; i++) {
        plain[i] = (uint8_t)(i * 7 + 3);
    }

    /* Encrypt with A. */
    g_assert(mem_enc_cipher_encrypt(a, phys, plain, cipher, PAGE,
                                    &error_abort) == 0);
    g_assert(memcmp(plain, cipher, PAGE) != 0);

    /* Correct key round-trips to plaintext. */
    g_assert(mem_enc_cipher_decrypt(a, phys, cipher, dec_ok, PAGE,
                                    &error_abort) == 0);
    g_assert(memcmp(plain, dec_ok, PAGE) == 0);

    /* Wrong key yields garbage. */
    g_assert(mem_enc_cipher_decrypt(b, phys, cipher, dec_wrong, PAGE,
                                    &error_abort) == 0);
    g_assert(memcmp(plain, dec_wrong, PAGE) != 0);

    /* Distinct page addresses yield distinct ciphertext (tweak from phys). */
    g_assert(mem_enc_cipher_encrypt(a, phys + PAGE, plain, cipher2, PAGE,
                                    &error_abort) == 0);
    g_assert(memcmp(cipher, cipher2, PAGE) != 0);

    mem_enc_cipher_free(a);
    mem_enc_cipher_free(b);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/memory-encryption/cipher/wrong-key-garbage",
                    test_wrong_key_yields_garbage);
    g_test_add_func("/memory-encryption/cipher/roundtrip", test_roundtrip);
    g_test_add_func("/memory-encryption/cipher/address-dependence",
                    test_address_dependence);
    g_test_add_func("/memory-encryption/cipher/aes-256-xts",
                    test_aes_256_xts);

    return g_test_run();
}
