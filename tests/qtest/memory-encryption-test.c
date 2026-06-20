/*
 * QEMU Generic Memory Encryption - flatview/DMA coherency qtest.
 *
 * Verifies that the flatview (DMA/monitor/migration) path stays coherent with
 * the CPU's decrypted working-page cache:
 *
 *   1. a page is marked managed (its backing holds ciphertext),
 *   2. a tiny real-mode payload is booted and writes 0xBEEF to that page via
 *      the CPU -- this goes through the TLB/translate path, dirtying the
 *      decrypted working page,
 *   3. memory-encryption-dump-page reads the page through the flatview path,
 *      which must flush the dirty working page back into the backing first.
 *
 * The test passes only if the flushed plaintext reflects 0xBEEF (proving the
 * flush happened); without the flush the backing would be stale and the
 * decrypted view would not show the guest's write.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "libqtest.h"
#include "qobject/qdict.h"

#define TARGET_GPA   0x8000     /* the page the payload writes to */
#define EXPECT_HEX   "efbe"     /* 0xBEEF, little-endian, at offset 0 */

/*
 * Real-mode boot sector (loaded at 0x7c00 by SeaBIOS, DS=0):
 *   mov ax, 0          ; b8 00 00
 *   mov ds, ax         ; 8e d8
 *   mov ax, 0xBEEF     ; b8 ef be
 *   mov [0x8000], ax   ; a3 00 80
 *   hlt                 ; f4
 *   jmp $               ; eb fe
 */
static uint8_t boot_sector[512] = {
    [0x00] = 0xb8, 0x00, 0x00,
    [0x03] = 0x8e, 0xd8,
    [0x05] = 0xb8, 0xef, 0xbe,
    [0x08] = 0xa3, 0x00, 0x80,
    [0x0b] = 0xf4,
    [0x0c] = 0xeb, 0xfe,
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
static void dump_page(QTestState *s, gchar **plain, gchar **cipher,
                      bool *managed)
{
    QDict *resp = qtest_qmp(s,
                            "{ 'execute': 'memory-encryption-dump-page',"
                            "  'arguments': { 'gpa': %" PRId64 " } }",
                            (uint64_t)TARGET_GPA);
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
                            "  'arguments': { 'gpa': %" PRId64 ","
                            "                  'size': 4096 } }",
                            (uint64_t)TARGET_GPA));

    /* Let the guest boot and run the payload. */
    qobject_unref(qtest_qmp(s, "{ 'execute': 'cont' }"));

    /*
     * Poll dump-page (a flatview read, which flushes) until the guest's write
     * is visible in the decrypted plaintext view. Boot on TCG can take a couple
     * of seconds.
     */
    for (i = 0; i < 300; i++) {       /* up to ~30 s */
        g_autofree gchar *plain = NULL;
        bool managed = false;

        dump_page(s, &plain, &final_cipher, &managed);
        g_assert(managed);
        if (g_str_has_prefix(plain, EXPECT_HEX)) {
            break;
        }
        g_usleep(100000);
    }
    g_assert_cmpint(i, <, 300);   /* the guest's write must become visible */

    /*
     * Final confirmation: the plaintext shows 0xBEEF (flush worked) and the
     * external ciphertext view differs (encryption is real).
     */
    dump_page(s, &final_plain, NULL, NULL);
    g_assert(g_str_has_prefix(final_plain, EXPECT_HEX));
    g_assert_cmpstr(final_plain, !=, final_cipher);

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
