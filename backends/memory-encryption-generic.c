/*
 * QEMU Generic Memory Encryption - default -object wrapper
 *
 * A plain user-creatable object that owns a MemoryEncryptionEngine and
 * activates it as the process-wide singleton.
 *
 * Usage:
 *   -object memory-encryption-core-generic,id=mec0,cipher=identity,key=<hex>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"

#include "qapi/error.h"
#include "qom/object_interfaces.h"
#include "system/memory-encryption.h"

#define TYPE_MEMORY_ENCRYPTION_CORE_GENERIC "memory-encryption-core-generic"
OBJECT_DECLARE_SIMPLE_TYPE(MemEncCore, MEMORY_ENCRYPTION_CORE_GENERIC)

typedef struct MemEncCoreClass {
    ObjectClass parent_class;
} MemEncCoreClass;

struct MemEncCore {
    Object parent_obj;

    char *cipher_name;            /* -object property, e.g. "identity" */
    char *key_hex;                /* -object property: owner key in hex */
    uint32_t owner_key_id;        /* -object property, default 1 */

    MemoryEncryptionEngine *engine;
};

OBJECT_DEFINE_TYPE_WITH_INTERFACES(MemEncCore, mem_enc_core,
                                   MEMORY_ENCRYPTION_CORE_GENERIC,
                                   OBJECT,
                                   { TYPE_USER_CREATABLE },
                                   { NULL })

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

static char *mem_enc_core_get_cipher(Object *obj, Error **errp)
{
    return g_strdup(MEMORY_ENCRYPTION_CORE_GENERIC(obj)->cipher_name);
}

static void mem_enc_core_set_cipher(Object *obj, const char *value,
                                    Error **errp)
{
    MemEncCore *c = MEMORY_ENCRYPTION_CORE_GENERIC(obj);

    g_free(c->cipher_name);
    c->cipher_name = g_strdup(value);
}

static char *mem_enc_core_get_key(Object *obj, Error **errp)
{
    return g_strdup(MEMORY_ENCRYPTION_CORE_GENERIC(obj)->key_hex ?: "");
}

static void mem_enc_core_set_key(Object *obj, const char *value, Error **errp)
{
    MemEncCore *c = MEMORY_ENCRYPTION_CORE_GENERIC(obj);

    g_free(c->key_hex);
    c->key_hex = g_strdup(value);
}

static void mem_enc_core_complete(UserCreatable *uc, Error **errp)
{
    MemEncCore *c = MEMORY_ENCRYPTION_CORE_GENERIC(uc);
    g_autofree uint8_t *key = NULL;
    size_t keylen = 0;

    if (c->key_hex) {
        if (hex_decode(c->key_hex, &key, &keylen, errp) < 0) {
            return;
        }
    }

    c->engine = mem_enc_engine_new(c->cipher_name, c->owner_key_id);

    if (mem_enc_set_key(c->engine, c->owner_key_id, key, keylen, errp) < 0) {
        return;
    }

    mem_enc_engine_activate(c->engine);
}

static void mem_enc_core_init(Object *obj)
{
    MemEncCore *c = MEMORY_ENCRYPTION_CORE_GENERIC(obj);

    c->cipher_name = g_strdup("identity");
    c->owner_key_id = 1;

    object_property_add_str(obj, "cipher",
                            mem_enc_core_get_cipher,
                            mem_enc_core_set_cipher);
    object_property_add_str(obj, "key",
                            mem_enc_core_get_key,
                            mem_enc_core_set_key);
    object_property_add_uint32_ptr(obj, "owner-key-id", &c->owner_key_id,
                                   OBJ_PROP_FLAG_READWRITE);
}

static void mem_enc_core_finalize(Object *obj)
{
    MemEncCore *c = MEMORY_ENCRYPTION_CORE_GENERIC(obj);

    mem_enc_engine_free(c->engine);
    g_free(c->cipher_name);
    g_free(c->key_hex);
}

static void mem_enc_core_class_init(ObjectClass *oc, const void *data)
{
    UserCreatableClass *uc = USER_CREATABLE_CLASS(oc);

    uc->complete = mem_enc_core_complete;
}
