/*
 * QEMU AMD SME CPU visibility qtest
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "libqtest.h"
#include "qobject/qdict.h"
#include "qemu/bitops.h"

/* Results page */
#define RESULTS     0x9000
#define MAGIC       0x600df00d

/* Offsets within the results page. */
#define R_MAXLEAF   0x00    /* CPUID 0x80000000 EAX */
#define R_EAX_1F    0x04    /* CPUID 0x8000001f EAX */
#define R_EBX_1F    0x08    /* CPUID 0x8000001f EBX */
#define R_ECX_1F    0x0c    /* CPUID 0x8000001f ECX */
#define R_EDX_1F    0x10    /* CPUID 0x8000001f EDX */
#define R_ECX_CPUID1 0x14   /* CPUID 1 ECX (bit31 = hypervisor) */
#define R_SYSCFG_LO 0x18    /* MSR 0xc0010010 EDX:EAX */
#define R_SYSCFG_HI 0x1c
#define R_SEV_LO    0x20    /* MSR 0xc0010131 EDX:EAX */
#define R_SEV_HI    0x24
#define R_MAGIC     0x28

/*
 * Real-mode boot sector (loaded at 0x7c00 by SeaBIOS, DS=0, CPL=0).
 * Opcodes cross-checked against GNU as (.code16gcc).
 *   mov ax, 0                      b8 00 00
 *   mov ds, ax                     8e d8
 *   mov eax, 0x80000000            66 b8 00 00 00 80
 *   cpuid                          0f a2
 *   mov [0x9000], eax              66 a3 00 90
 *   mov eax, 0x8000001f            66 b8 1f 00 00 80
 *   xor ecx, ecx                   66 31 c9
 *   cpuid                          0f a2
 *   mov [0x9004], eax              66 a3 04 90
 *   mov [0x9008], ebx              66 89 1e 08 90
 *   mov [0x900c], ecx              66 89 0e 0c 90
 *   mov [0x9010], edx              66 89 16 10 90
 *   mov eax, 1                     66 b8 01 00 00 00
 *   cpuid                          0f a2
 *   mov [0x9014], ecx              66 89 0e 14 90
 *   mov ecx, 0xc0010010            66 b9 10 00 01 c0
 *   rdmsr                          0f 32
 *   mov [0x9018], eax              66 a3 18 90
 *   mov [0x901c], edx              66 89 16 1c 90
 *   mov ecx, 0xc0010131            66 b9 31 01 01 c0
 *   rdmsr                          0f 32
 *   mov [0x9020], eax              66 a3 20 90
 *   mov [0x9024], edx              66 89 16 24 90
 *   mov dword [0x9028], 0x600df00d 66 c7 06 28 90 0d f0 0d 60
 *   hlt                            f4
 *   jmp $                          eb fe
 */
static uint8_t boot_sector[512] = {
    [0x00] = 0xb8, 0x00, 0x00,
    [0x03] = 0x8e, 0xd8,
    [0x05] = 0x66, 0xb8, 0x00, 0x00, 0x00, 0x80,
    [0x0b] = 0x0f, 0xa2,
    [0x0d] = 0x66, 0xa3, 0x00, 0x90,
    [0x11] = 0x66, 0xb8, 0x1f, 0x00, 0x00, 0x80,
    [0x17] = 0x66, 0x31, 0xc9,
    [0x1a] = 0x0f, 0xa2,
    [0x1c] = 0x66, 0xa3, 0x04, 0x90,
    [0x20] = 0x66, 0x89, 0x1e, 0x08, 0x90,
    [0x25] = 0x66, 0x89, 0x0e, 0x0c, 0x90,
    [0x2a] = 0x66, 0x89, 0x16, 0x10, 0x90,
    [0x2f] = 0x66, 0xb8, 0x01, 0x00, 0x00, 0x00,
    [0x35] = 0x0f, 0xa2,
    [0x37] = 0x66, 0x89, 0x0e, 0x14, 0x90,
    [0x3c] = 0x66, 0xb9, 0x10, 0x00, 0x01, 0xc0,
    [0x42] = 0x0f, 0x32,
    [0x44] = 0x66, 0xa3, 0x18, 0x90,
    [0x48] = 0x66, 0x89, 0x16, 0x1c, 0x90,
    [0x4d] = 0x66, 0xb9, 0x31, 0x01, 0x01, 0xc0,
    [0x53] = 0x0f, 0x32,
    [0x55] = 0x66, 0xa3, 0x20, 0x90,
    [0x59] = 0x66, 0x89, 0x16, 0x24, 0x90,
    [0x5e] = 0x66, 0xc7, 0x06, 0x28, 0x90, 0x0d, 0xf0, 0x0d, 0x60,
    [0x67] = 0xf4,
    [0x68] = 0xeb, 0xfe,
    [0x1fe] = 0x55, 0xaa,
};

static gchar *disk_path;

static void make_disk(void)
{
    g_autofree uint8_t *buf = g_malloc0(0x7e000);  /* floppy minimum */
    int fd;

    memcpy(buf, boot_sector, sizeof(boot_sector));

    disk_path = g_strdup_printf("%s/sme-cpuid-boot-XXXXXX", g_get_tmp_dir());
    fd = mkstemp(disk_path);
    g_assert_cmpint(fd, >=, 0);
    g_assert_cmpint(write(fd, buf, 0x7e000), ==, 0x7e000);
    close(fd);
}

/* Boot the payload with the given -cpu suffix and wait for the magic. */
static QTestState *run_payload(const char *cpu_args)
{
    QTestState *s;
    gchar *args;
    int i;

    make_disk();
    args = g_strdup_printf(
        "-accel tcg -machine pc -m 128M -display none -serial null "
        "-cpu %s -fda %s", cpu_args, disk_path);
    s = qtest_init(args);
    g_free(args);

    for (i = 0; i < 300; i++) {
        if (qtest_readl(s, RESULTS + R_MAGIC) == MAGIC) {
            return s;
        }
        g_usleep(100000);
    }
    g_assert_not_reached();  /* payload never completed */
    return NULL;
}

static void cleanup(QTestState *s)
{
    qtest_quit(s);
    unlink(disk_path);
    g_free(disk_path);
    disk_path = NULL;
}

/* -hypervisor means reset hypervisor bit of CPU */
static void test_sme_enabled(void)
{
    QTestState *s = run_payload("max,phys-bits=48,-hypervisor,sme=on");

    /* Leaf 0x8000001f: EAX bit0 (SME), EBX[5:0]=47 C-bit, EBX bit31 set. */
    g_assert_cmphex(qtest_readl(s, RESULTS + R_EAX_1F), ==, 0x1);
    g_assert_cmphex(qtest_readl(s, RESULTS + R_EBX_1F), ==, (47 | BIT(31)));
    g_assert_cmphex(qtest_readl(s, RESULTS + R_ECX_1F), ==, 0);
    g_assert_cmphex(qtest_readl(s, RESULTS + R_EDX_1F), ==, 0);
    /* Max extended leaf must cover 0x8000001f. */
    g_assert(qtest_readl(s, RESULTS + R_MAXLEAF) >= 0x8000001f);
    /* Hypervisor CPUID bit must be clear for the kernel to enable SME. */
    g_assert_cmphex(qtest_readl(s, RESULTS + R_ECX_CPUID1) & BIT(31), ==, 0);
    /* SYSCFG.MemEncryptEn (bit 23) preset; SEV MSR reads 0 (SME path). */
    g_assert_cmphex(qtest_readl(s, RESULTS + R_SYSCFG_LO), ==, BIT(23));
    g_assert_cmphex(qtest_readl(s, RESULTS + R_SYSCFG_HI), ==, 0);
    g_assert_cmphex(qtest_readl(s, RESULTS + R_SEV_LO), ==, 0);
    g_assert_cmphex(qtest_readl(s, RESULTS + R_SEV_HI), ==, 0);

    cleanup(s);
}

static void test_sme_disabled(void)
{
    QTestState *s = run_payload("max,phys-bits=48,-hypervisor");

    g_assert_cmphex(qtest_readl(s, RESULTS + R_EAX_1F), ==, 0);
    g_assert_cmphex(qtest_readl(s, RESULTS + R_EBX_1F), ==, 0);
    g_assert_cmphex(qtest_readl(s, RESULTS + R_SYSCFG_LO), ==, 0);
    g_assert_cmphex(qtest_readl(s, RESULTS + R_SEV_LO), ==, 0);

    cleanup(s);
}

static void test_sme_hypervisor_bit_visible(void)
{
    QTestState *s = run_payload("max,phys-bits=48,sme=on");

    g_assert_cmphex(qtest_readl(s, RESULTS + R_ECX_CPUID1) & BIT(31),
                    ==, BIT(31));
    g_assert_cmphex(qtest_readl(s, RESULTS + R_EAX_1F), ==, 0x1);

    cleanup(s);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    if (g_str_equal(qtest_get_arch(), "i386") ||
        g_str_equal(qtest_get_arch(), "x86_64")) {
        qtest_add_func("/sme/cpuid/enabled", test_sme_enabled);
        qtest_add_func("/sme/cpuid/disabled", test_sme_disabled);
        qtest_add_func("/sme/cpuid/hypervisor-bit", test_sme_hypervisor_bit_visible);
    }

    return g_test_run();
}
