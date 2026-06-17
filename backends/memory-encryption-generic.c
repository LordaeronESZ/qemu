/*
 * QEMU Generic Memory Encryption - default confidential-guest wrapper
 *
 * A thin ConfidentialGuestSupport wrapper that owns a MemoryEncryptionEngine.
 * Suitable for machines that do not specialise their confidential-guest object
 * (i.e. do not cast cgs to an arch-specific subtype). The x86 target uses a
 * separate X86ConfidentialGuest-based wrapper (see target/i386/mem-enc.c).
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"

#include "qapi/error.h"
#include "qom/object_interfaces.h"
#include "system/confidential-guest-support.h"
#include "system/memory-encryption.h"

#define TYPE_MEMORY_ENCRYPTION_CORE_GENERIC "memory-encryption-core-generic"
OBJECT_DECLARE_SIMPLE_TYPE(MemEncCoreGeneric, MEMORY_ENCRYPTION_CORE_GENERIC)

typedef struct MemEncCoreGenericClass {
    ConfidentialGuestSupportClass parent_class;
} MemEncCoreGenericClass;

struct MemEncCoreGeneric {
    ConfidentialGuestSupport parent_obj;

    char *cipher_name;            /* -object property, e.g. "identity" */
    char *key_hex;                /* -object property: owner key in hex */
    uint32_t owner_key_id;        /* -object property, default 1 */

    MemoryEncryptionEngine *engine;
};

OBJECT_DEFINE_TYPE_WITH_INTERFACES(MemEncCoreGeneric, mem_enc_core_generic,
                                   MEMORY_ENCRYPTION_CORE_GENERIC,
                                   CONFIDENTIAL_GUEST_SUPPORT,
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

static char *mem_enc_core_generic_get_cipher(Object *obj, Error **errp)
{
    return g_strdup(MEMORY_ENCRYPTION_CORE_GENERIC(obj)->cipher_name);
}

static void mem_enc_core_generic_set_cipher(Object *obj, const char *value,
                                            Error **errp)
{
    MemEncCoreGeneric *g = MEMORY_ENCRYPTION_CORE_GENERIC(obj);

    g_free(g->cipher_name);
    g->cipher_name = g_strdup(value);
}

static char *mem_enc_core_generic_get_key(Object *obj, Error **errp)
{
    return g_strdup(MEMORY_ENCRYPTION_CORE_GENERIC(obj)->key_hex ?: "");
}

static void mem_enc_core_generic_set_key(Object *obj, const char *value,
                                         Error **errp)
{
    MemEncCoreGeneric *g = MEMORY_ENCRYPTION_CORE_GENERIC(obj);

    g_free(g->key_hex);
    g->key_hex = g_strdup(value);
}

/* ----------------------------------------------------------------------- */
/* realization                                                              */
/* ----------------------------------------------------------------------- */

static void mem_enc_core_generic_complete(UserCreatable *uc, Error **errp)
{
    MemEncCoreGeneric *g = MEMORY_ENCRYPTION_CORE_GENERIC(uc);
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

    mem_enc_engine_activate(g->engine, &g->parent_obj);
}

static void mem_enc_core_generic_init(Object *obj)
{
    MemEncCoreGeneric *g = MEMORY_ENCRYPTION_CORE_GENERIC(obj);

    g->cipher_name = g_strdup("identity");
    g->owner_key_id = 1;

    object_property_add_str(obj, "cipher",
                            mem_enc_core_generic_get_cipher,
                            mem_enc_core_generic_set_cipher);
    object_property_add_str(obj, "key",
                            mem_enc_core_generic_get_key,
                            mem_enc_core_generic_set_key);
    object_property_add_uint32_ptr(obj, "owner-key-id", &g->owner_key_id,
                                   OBJ_PROP_FLAG_READWRITE);
}

static void mem_enc_core_generic_finalize(Object *obj)
{
    MemEncCoreGeneric *g = MEMORY_ENCRYPTION_CORE_GENERIC(obj);

    mem_enc_engine_free(g->engine);
    g_free(g->cipher_name);
    g_free(g->key_hex);
}

static void mem_enc_core_generic_class_init(ObjectClass *oc, const void *data)
{
    UserCreatableClass *uc = USER_CREATABLE_CLASS(oc);

    uc->complete = mem_enc_core_generic_complete;
}
