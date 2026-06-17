/*
 * QEMU x86 Memory Encryption - confidential-guest wrapper for the generic
 * memory-encryption engine.
 *
 * On x86 the confidential-guest object must be an X86ConfidentialGuest (the
 * machine casts cgs to that type during CPU init). This wrapper supplies such a
 * type while owning an arch-independent MemoryEncryptionEngine. It is the x86
 * integration point; the C-bit/ASID key resolver and SEV CPUID are layered on
 * top of this in subsequent work.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"

#include "qapi/error.h"
#include "qom/object_interfaces.h"
#include "system/confidential-guest-support.h"
#include "system/memory-encryption.h"
#include "target/i386/confidential-guest.h"

#define TYPE_X86_MEMORY_ENCRYPTION_CORE_GENERIC \
    "x86-memory-encryption-core-generic"
OBJECT_DECLARE_SIMPLE_TYPE(X86MemEncCore, X86_MEMORY_ENCRYPTION_CORE_GENERIC)

typedef struct X86MemEncCoreClass {
    X86ConfidentialGuestClass parent_class;
} X86MemEncCoreClass;

struct X86MemEncCore {
    X86ConfidentialGuest parent_obj;

    char *cipher_name;
    char *key_hex;
    uint32_t owner_key_id;

    MemoryEncryptionEngine *engine;
};

OBJECT_DEFINE_TYPE_WITH_INTERFACES(X86MemEncCore, x86_mem_enc_core,
                                   X86_MEMORY_ENCRYPTION_CORE_GENERIC,
                                   X86_CONFIDENTIAL_GUEST,
                                   { TYPE_USER_CREATABLE },
                                   { NULL })

/* ----------------------------------------------------------------------- */
/* hex key parsing                                                          */
/* ----------------------------------------------------------------------- */

static int hex_decode(const char *hex, uint8_t **out, size_t *outlen,
                      Error **errp)
{
    size_t hlen = strlen(hex);
    size_t blen = hlen / 2;
    uint8_t *buf;

    if (hlen % 2) {
        error_setg(errp, "memory-encryption key: odd-length hex string");
        return -1;
    }
    buf = g_malloc(blen ? blen : 1);
    for (size_t i = 0; i < blen; i++) {
        int b;

        if (sscanf(hex + 2 * i, "%2x", &b) != 1) {
            error_setg(errp, "memory-encryption key: invalid hex at offset %zu",
                       2 * i);
            g_free(buf);
            return -1;
        }
        buf[i] = (uint8_t)b;
    }

    *out = buf;
    *outlen = blen;
    return 0;
}

/* ----------------------------------------------------------------------- */
/* QOM properties                                                           */
/* ----------------------------------------------------------------------- */

static char *x86_mem_enc_core_get_cipher(Object *obj, Error **errp)
{
    return g_strdup(X86_MEMORY_ENCRYPTION_CORE_GENERIC(obj)->cipher_name);
}

static void x86_mem_enc_core_set_cipher(Object *obj, const char *value,
                                        Error **errp)
{
    X86MemEncCore *g = X86_MEMORY_ENCRYPTION_CORE_GENERIC(obj);

    g_free(g->cipher_name);
    g->cipher_name = g_strdup(value);
}

static char *x86_mem_enc_core_get_key(Object *obj, Error **errp)
{
    return g_strdup(X86_MEMORY_ENCRYPTION_CORE_GENERIC(obj)->key_hex ?: "");
}

static void x86_mem_enc_core_set_key(Object *obj, const char *value,
                                     Error **errp)
{
    X86MemEncCore *g = X86_MEMORY_ENCRYPTION_CORE_GENERIC(obj);

    g_free(g->key_hex);
    g->key_hex = g_strdup(value);
}

/* ----------------------------------------------------------------------- */
/* realization                                                              */
/* ----------------------------------------------------------------------- */

static void x86_mem_enc_core_complete(UserCreatable *uc, Error **errp)
{
    X86MemEncCore *g = X86_MEMORY_ENCRYPTION_CORE_GENERIC(uc);
    g_autofree uint8_t *key = NULL;
    size_t keylen = 0;

    if (g->key_hex) {
        if (hex_decode(g->key_hex, &key, &keylen, errp) < 0) {
            return;
        }
    }

    g->engine = mem_enc_engine_new(g->cipher_name, g->owner_key_id);

    if (mem_enc_set_key(g->engine, g->owner_key_id, key, keylen, errp) < 0) {
        return;
    }

    mem_enc_engine_activate(g->engine, &g->parent_obj.parent_obj);
}

static void x86_mem_enc_core_init(Object *obj)
{
    X86MemEncCore *g = X86_MEMORY_ENCRYPTION_CORE_GENERIC(obj);

    g->cipher_name = g_strdup("identity");
    g->owner_key_id = 1;

    object_property_add_str(obj, "cipher",
                            x86_mem_enc_core_get_cipher,
                            x86_mem_enc_core_set_cipher);
    object_property_add_str(obj, "key",
                            x86_mem_enc_core_get_key,
                            x86_mem_enc_core_set_key);
    object_property_add_uint32_ptr(obj, "owner-key-id", &g->owner_key_id,
                                   OBJ_PROP_FLAG_READWRITE);
}

static void x86_mem_enc_core_finalize(Object *obj)
{
    X86MemEncCore *g = X86_MEMORY_ENCRYPTION_CORE_GENERIC(obj);

    mem_enc_engine_free(g->engine);
    g_free(g->cipher_name);
    g_free(g->key_hex);
}

static void x86_mem_enc_core_class_init(ObjectClass *oc, const void *data)
{
    UserCreatableClass *uc = USER_CREATABLE_CLASS(oc);

    uc->complete = x86_mem_enc_core_complete;
}
