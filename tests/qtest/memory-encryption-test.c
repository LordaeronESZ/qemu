/*
 * QEMU Generic Memory Encryption
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "libqtest.h"
#include "qobject/qdict.h"

#define TARGET_PHYS  0x8000     /* the page the payload writes to */
#define EXPECT_HEX   "efbe"     /* 0xBEEF, little-endian, at offset 0 */
#define FLAG_PHYS    0x9000     /* unmanaged page holding the read-back flag */
#define FLAG_HEX     "3412"     /* 0x1234, little-endian, at offset 0 */

/*
 * Real-mode boot sector (loaded at 0x7c00 by SeaBIOS, DS=0):
 *   mov ax, 0            ; b8 00 00
 *   mov ds, ax           ; 8e d8
 *   mov ax, 0xBEEF       ; b8 ef be
 *   mov [0x8000], ax     ; a3 00 80
 *   wbinvd               ; 0f 09   (flush before observers)
 *   mov ax, [0x8000]     ; a1 00 80  (re-read through a fresh TLB entry)
 *   cmp ax, 0xBEEF       ; 3d ef be
 *   jne 1f               ; 75 06
 *   mov word [0x9000], 0x1234  ; c7 06 00 90 34 12  (flag: read-back OK)
 * 1: hlt                 ; f4
 *   jmp $                ; eb fe
 */
static uint8_t boot_sector[512] = {
    [0x00] = 0xb8, 0x00, 0x00,
    [0x03] = 0x8e, 0xd8,
    [0x05] = 0xb8, 0xef, 0xbe,
    [0x08] = 0xa3, 0x00, 0x80,
    [0x0b] = 0x0f, 0x09,
    [0x0d] = 0xa1, 0x00, 0x80,
    [0x10] = 0x3d, 0xef, 0xbe,
    [0x13] = 0x75, 0x06,
    [0x15] = 0xc7, 0x06, 0x00, 0x90, 0x34, 0x12,
    [0x1b] = 0xf4,
    [0x1c] = 0xeb, 0xfe,
    [0x1fe] = 0x55, 0xaa,
};

static gchar *disk_path;

static void make_disk(void)
{
    g_autofree uint8_t *buf = g_malloc0(0x7e000);  /* floppy minimum */
    int fd;

    memcpy(buf, boot_sector, sizeof(boot_sector));

    disk_path = g_strdup_printf("%s/mem-enc-boot-XXXXXX", g_get_tmp_dir());
    fd = mkstemp(disk_path);
    g_assert_cmpint(fd, >=, 0);
    g_assert_cmpint(write(fd, buf, 0x7e000), ==, 0x7e000);
    close(fd);
}

/*
 * Read the target page through the flatview path; output its plaintext and
 * ciphertext hex views and the managed flag.
 */
static void dump_page(QTestState *s, uint64_t phys, gchar **plain,
                      gchar **cipher, bool *managed)
{
    QDict *resp = qtest_qmp(s,
                            "{ 'execute': 'memory-encryption-dump-page',"
                            "  'arguments': { 'phys': %" PRId64 " } }",
                            phys);
    QDict *ret = qdict_get_qdict(resp, "return");

    g_assert_nonnull(ret);
    if (plain) {
        *plain = g_strdup(qdict_get_str(ret, "plaintext-hex"));
    }
    if (cipher) {
        *cipher = g_strdup(qdict_get_str(ret, "ciphertext-hex"));
    }
    if (managed) {
        *managed = qdict_get_bool(ret, "managed");
    }
    qobject_unref(resp);
}

static void test_cpu_write_then_dma_read(void)
{
    QTestState *s;
    gchar *args, *final_plain = NULL, *final_cipher = NULL;
    int i;

    make_disk();

    args = g_strdup_printf(
        "-accel tcg -machine pc -S -display none -serial null "
        "-object memory-encryption-core-generic,id=mec0,"
        "cipher=identity,key=0102030405060708090a0b0c0d0e0f10 "
        "-fda %s", disk_path);
    s = qtest_init(args);
    g_free(args);

    /*
     * Mark the target page managed before the guest touches it, so the guest's
     * write goes through the TLB/translate path and dirties a working page.
     */
    qobject_unref(qtest_qmp(s,
                            "{ 'execute': 'memory-encryption-mark-managed',"
                            "  'arguments': { 'phys': %" PRId64 ","
                            "                  'size': 4096 } }",
                            (uint64_t)TARGET_PHYS));

    /* Let the guest boot and run the payload. */
    qobject_unref(qtest_qmp(s, "{ 'execute': 'cont' }"));

    /*
     * Poll dump-page until the guest's write is visible in the decrypted
     * plaintext view. The payload executes WBINVD after the store, which
     * writes the dirty working page back into the ciphertext backing.
     */
    for (i = 0; i < 300; i++) {
        g_autofree gchar *plain = NULL;
        bool managed = false;

        dump_page(s, TARGET_PHYS, &plain, &final_cipher, &managed);
        g_assert(managed);
        if (g_str_has_prefix(plain, EXPECT_HEX)) {
            break;
        }
        g_usleep(100000);
    }
    g_assert_cmpint(i, <, 300);   /* the guest's write must become visible */

    /*
     * Final confirmation: the plaintext shows 0xBEEF and the
     * ciphertext view differs.
     */
    dump_page(s, TARGET_PHYS, &final_plain, NULL, NULL);
    g_assert(g_str_has_prefix(final_plain, EXPECT_HEX));
    g_assert_cmpstr(final_plain, !=, final_cipher);

    /*
     * The payload re-reads the managed page after WBINVD (a fresh TLB entry
     * and a fresh working page) and raises a flag at 0x9000 if it read the
     * value back.
     */
    for (i = 0; i < 300; i++) {
        g_autofree gchar *flag = NULL;

        dump_page(s, FLAG_PHYS, &flag, NULL, NULL);
        if (g_str_has_prefix(flag, FLAG_HEX)) {
            break;
        }
        g_usleep(100000);
    }
    g_assert_cmpint(i, <, 300);   /* the guest's post-WBINVD read-back worked */

    g_free(final_plain);
    g_free(final_cipher);
    qtest_quit(s);
    unlink(disk_path);
    g_free(disk_path);
    disk_path = NULL;
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    if (g_str_equal(qtest_get_arch(), "i386") ||
        g_str_equal(qtest_get_arch(), "x86_64")) {
        qtest_add_func("/memory-encryption/dma-coherency",
                       test_cpu_write_then_dma_read);
    }

    return g_test_run();
}
