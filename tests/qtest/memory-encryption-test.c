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

static void make_disk(const uint8_t sector[512])
{
    g_autofree uint8_t *buf = g_malloc0(0x7e000);  /* floppy minimum */
    int fd;

    memcpy(buf, sector, 512);

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
static void dump_page_at(QTestState *s, uint64_t gpa, gchar **plain,
                         gchar **cipher, bool *managed)
{
    QDict *resp = qtest_qmp(s,
                            "{ 'execute': 'memory-encryption-dump-page',"
                            "  'arguments': { 'gpa': %" PRId64 " } }", gpa);
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

    make_disk(boot_sector);

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

        dump_page_at(s, TARGET_GPA, &plain, &final_cipher, &managed);
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
    dump_page_at(s, TARGET_GPA, &final_plain, NULL, NULL);
    g_assert(g_str_has_prefix(final_plain, EXPECT_HEX));
    g_assert_cmpstr(final_plain, !=, final_cipher);

    g_free(final_plain);
    g_free(final_cipher);
    qtest_quit(s);
    unlink(disk_path);
    g_free(disk_path);
    disk_path = NULL;
}

/*
 * Boot sector that reads CPUID leaf 0x8000001f and stores EAX/EBX (low 16
 * bits each) at 0x9000, so the test can confirm the guest observes SEV:
 *   xor ax, ax            ; 31 c0
 *   mov ds, ax            ; 8e d8
 *   mov eax, 0x8000001f   ; 66 b8 1f 00 00 80
 *   cpuid                 ; 0f a2
 *   mov [0x9000], ax      ; a3 00 90
 *   mov [0x9002], bx      ; 89 1e 02 90
 *   hlt                   ; f4
 *   jmp $                 ; eb fe
 * With SEV advertised: EAX[1]=1 (SEV), EBX[5:0]=cbitpos, EBX[11:6]=reduced.
 */
static uint8_t cpuid_boot_sector[512] = {
    [0x00] = 0x31, 0xc0,
    [0x02] = 0x8e, 0xd8,
    [0x04] = 0x66, 0xb8, 0x1f, 0x00, 0x00, 0x80,
    [0x0a] = 0x0f, 0xa2,
    [0x0c] = 0xa3, 0x00, 0x90,
    [0x0f] = 0x89, 0x1e, 0x02, 0x90,
    [0x13] = 0xf4,
    [0x14] = 0xeb, 0xfe,
    [0x1fe] = 0x55, 0xaa,
};

/*
 * Verify that the x86-sev-sim machine-memory-encryption config makes the guest
 * observe SEV in CPUID leaf 0x8000001f, with the configured C-bit position.
 * x86-sev-sim is a plain -object (no confidential-guest-support): it activates
 * the encryption engine as a machine-hardware property.
 */
static void test_sev_sim_cpuid(void)
{
    QTestState *s;
    gchar *args;
    int i;

    make_disk(cpuid_boot_sector);

    args = g_strdup_printf(
        "-accel tcg -machine pc -S "
        "-display none -serial null "
        "-cpu qemu64,xlevel=0x8000001f "
        "-object x86-sev-sim,id=sim0,cipher=identity,"
        "key=0102030405060708090a0b0c0d0e0f10,cbitpos=51,"
        "reduced-phys-bits=1 "
        "-fda %s", disk_path);
    s = qtest_init(args);
    g_free(args);

    qobject_unref(qtest_qmp(s, "{ 'execute': 'cont' }"));

    /*
     * Poll the page the payload writes (0x9000, unmanaged -> plaintext) until
     * the CPUID result lands. EAX=0x0002 (SEV), EBX=51|(1<<6)=0x0073 ->
     * little-endian bytes 02 00 73 00.
     */
    for (i = 0; i < 300; i++) {
        g_autofree gchar *plain = NULL;

        dump_page_at(s, 0x9000, &plain, NULL, NULL);
        if (g_str_has_prefix(plain, "02007300")) {
            break;
        }
        g_usleep(100000);
    }
    g_assert_cmpint(i, <, 300);   /* the CPUID result must appear */

    qtest_quit(s);
    unlink(disk_path);
    g_free(disk_path);
    disk_path = NULL;
}

/*
 * Boot sector that enables PAE paging with the C-bit (bit 51) set in a page
 * directory entry, then writes 0xBEEF through it. With x86-sev-sim,cbitpos=51
 * and phys-bits=52, bit 51 is the SEV C-bit: the page walk produces a
 * guest-physical address with bit 51 set, x86_cpu_tlb_fill strips it, and the
 * engine serves the access as private/encrypted. This is the faithful
 * end-to-end exercise of the C-bit path (strip C-bit, set attrs.mem_enc,
 * resolve owner key, auto-manage, translate, flush) as a real SEV guest would.
 *
 * PAE paging is unavoidable: any C-bit <= 31 collides with the high BIOS-ROM
 * alias at 0xFFFE0000 (bit 31 set), which crashes boot before the payload runs.
 * Bit 51 needs paging to represent, and phys-bits=52 so it is not a reserved
 * PDE bit. The real-mode prologue writes 0x1234 to 0x8000 as a liveness marker.
 * The C-bit target is VA/PA 0x200000 (PD[1], a 2 MB page whose PDE has bit 51
 * set); PD[0] is a plaintext identity 2 MB page. Tables: PDPT @ 0x70000,
 * PD @ 0x71000.
 *
 * The bytes below are the gas-assembled (.code16/.code32) output of:
 *   cli ; xor %ax,%ax ; mov %ax,%ds
 *   mov $0x1234,%ax ; mov %ax,0x8000           # liveness marker
 *   mov $0x7000,%ax ; mov %ax,%es ; xor %di,%di ; xor %eax,%eax
 *   mov $0x800,%cx ; cld ; rep stosl           # zero 0x70000..0x71fff
 *   movl $0x00071001,%es:0                      # PDPT[0] = PD | P
 *   movl $0x00000083,%es:0x1000 ; movl $0,%es:0x1004    # PD[0] identity
 *   movl $0x00200083,%es:0x1008 ; movl $0x00080000,%es:0x100c   # PD[1] +Cbit
 *   lgdt gdtdesc
 *   mov $0x70000,%eax ; mov %eax,%cr3           # CR3 = PDPT
 *   mov %cr4,%eax ; or $0x20,%eax ; mov %eax,%cr4       # CR4.PAE
 *   mov %cr0,%eax ; or $0x80000001,%eax ; mov %eax,%cr0 # PE | PG
 *   ljmp $0x08,$pm32                            # 32-bit, paging on
 *   mov $0x10,%eax ; mov %eax,%ds ; mov %eax,%es
 *   mov $0xBEEF,%eax ; mov %eax,0x200000        # C-bit access
 *   hlt ; jmp $
 *   GDT: null | flat code (0x00cf9a000000ffff) | flat data (0x00cf920000ffff)
 */
static uint8_t cbit_boot_sector[512] = {
    /* 0x00 */ 0xfa, 0x31, 0xc0, 0x8e, 0xd8, 0xb8, 0x34, 0x12,
    /* 0x08 */ 0xa3, 0x00, 0x80, 0xb8, 0x00, 0x70, 0x8e, 0xc0,
    /* 0x10 */ 0x31, 0xff, 0x66, 0x31, 0xc0, 0xb9, 0x00, 0x08,
    /* 0x18 */ 0xfc, 0x66, 0xf3, 0xab, 0x26, 0x66, 0xc7, 0x06,
    /* 0x20 */ 0x00, 0x00, 0x01, 0x10, 0x07, 0x00, 0x26, 0x66,
    /* 0x28 */ 0xc7, 0x06, 0x00, 0x10, 0x83, 0x00, 0x00, 0x00,
    /* 0x30 */ 0x26, 0x66, 0xc7, 0x06, 0x04, 0x10, 0x00, 0x00,
    /* 0x38 */ 0x00, 0x00, 0x26, 0x66, 0xc7, 0x06, 0x08, 0x10,
    /* 0x40 */ 0x83, 0x00, 0x20, 0x00, 0x26, 0x66, 0xc7, 0x06,
    /* 0x48 */ 0x0c, 0x10, 0x00, 0x00, 0x08, 0x00, 0x0f, 0x01,
    /* 0x50 */ 0x16, 0xa8, 0x7c, 0x66, 0xb8, 0x00, 0x00, 0x07,
    /* 0x58 */ 0x00, 0x0f, 0x22, 0xd8, 0x0f, 0x20, 0xe0, 0x66,
    /* 0x60 */ 0x83, 0xc8, 0x20, 0x0f, 0x22, 0xe0, 0x0f, 0x20,
    /* 0x68 */ 0xc0, 0x66, 0x0d, 0x01, 0x00, 0x00, 0x80, 0x0f,
    /* 0x70 */ 0x22, 0xc0, 0x66, 0xea, 0x7a, 0x7c, 0x00, 0x00,
    /* 0x78 */ 0x08, 0x00, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x8e,
    /* 0x80 */ 0xd8, 0x8e, 0xc0, 0xb8, 0xef, 0xbe, 0x00, 0x00,
    /* 0x88 */ 0xa3, 0x00, 0x00, 0x20, 0x00, 0xf4, 0xeb, 0xfe,
    /* 0x90 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 0x98 */ 0xff, 0xff, 0x00, 0x00, 0x00, 0x9a, 0xcf, 0x00,
    /* 0xa0 */ 0xff, 0xff, 0x00, 0x00, 0x00, 0x92, 0xcf, 0x00,
    /* 0xa8 */ 0x17, 0x00, 0x90, 0x7c, 0x00, 0x00, 0x00, 0x00,
    [0x1fe] = 0x55, 0xaa,
};

/*
 * Verify the SEV C-bit makes a page encrypted end-to-end, *without* the host
 * pre-marking it managed. A PAE-paging guest writes 0xBEEF through a C-bit
 * page-directory entry (bit 51); the engine must auto-manage the page so the
 * C-bit is self-sufficient -- the guest (owner key) sees plaintext 0xBEEF
 * while an external flatview reader (no key) sees ciphertext. phys-bits=52 is
 * required so bit 51 is a valid (non-reserved) PDE bit, as on SEV hardware.
 */
static void test_sev_sim_cbit_encryption(void)
{
    QTestState *s;
    gchar *args, *marker = NULL, *final_plain = NULL, *final_cipher = NULL;
    bool managed = false;
    int i;

    make_disk(cbit_boot_sector);

    args = g_strdup_printf(
        "-accel tcg -machine pc -S "
        "-display none -serial null "
        "-cpu qemu64,phys-bits=52 "
        "-object x86-sev-sim,id=sim0,cipher=identity,"
        "key=0102030405060708090a0b0c0d0e0f10,cbitpos=51,"
        "reduced-phys-bits=1 "
        "-fda %s", disk_path);
    s = qtest_init(args);
    g_free(args);

    /*
     * Intentionally NOT calling memory-encryption-mark-managed: the C-bit must
     * claim the page as encrypted on its own (auto-manage).
     */
    qobject_unref(qtest_qmp(s, "{ 'execute': 'cont' }"));

    /*
     * First confirm the boot sector ran at all: its real-mode prologue writes
     * 0x1234 (LE: 34 12) to 0x8000. If this never appears, the boot sector did
     * not execute -- not a C-bit problem.
     */
    for (i = 0; i < 300; i++) {
        g_autofree gchar *m = NULL;

        dump_page_at(s, 0x8000, &m, NULL, NULL);
        if (g_str_has_prefix(m, "3412")) {
            marker = g_strdup(m);
            break;
        }
        g_usleep(100000);
    }
    g_assert_cmpint(i, <, 300);            /* boot sector must run */
    g_free(marker);

    /*
     * Poll the C-bit target page (gpa 0x200000, after bit-51 strip) until
     * the guest's 0xBEEF write is visible in the decrypted view. dump-page
     * reads via the flatview path, which flushes the dirty working page first.
     */
    for (i = 0; i < 300; i++) {
        g_autofree gchar *plain = NULL;

        dump_page_at(s, 0x200000, &plain, &final_cipher, NULL);
        if (g_str_has_prefix(plain, "efbe0000")) {
            break;
        }
        g_usleep(100000);
    }
    g_assert_cmpint(i, <, 300);   /* the guest's write must become visible */

    /* Final confirmation: auto-manage ran, plaintext reflects the write. */
    dump_page_at(s, 0x200000, &final_plain, &final_cipher, &managed);
    /* The page is managed though we never called mark-managed. */
    g_assert(managed);
    g_assert(g_str_has_prefix(final_plain, "efbe0000"));
    g_assert_cmpstr(final_plain, !=, final_cipher);  /* encryption is real */

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
        qtest_add_func("/memory-encryption/sev-sim-cpuid",
                       test_sev_sim_cpuid);
        qtest_add_func("/memory-encryption/sev-sim-cbit",
                       test_sev_sim_cbit_encryption);
    }

    return g_test_run();
}
