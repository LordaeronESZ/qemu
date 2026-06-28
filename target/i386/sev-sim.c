/*
 * QEMU x86 SEV-style memory-encryption simulation.
 *
 * A plain user-creatable object that configures the generic
 * MemoryEncryptionEngine with AMD-SEV semantics for the *simulated machine*.
 * It deliberately does NOT
 * derive from ConfidentialGuestSupport: this models a physical machine whose
 * DRAM is encrypted by a hardware IP core, not a confidential-guest VM. The
 * engine is activated via the process-wide singleton, exactly like the generic
 * memory-encryption-core-generic object; the SEV-specific behaviour layered on
 * top is:
 *
 *   - the C-bit (a high guest-physical-address bit) selects encryption: an
 *     access with the C-bit set is an encrypted/private access (owner key),
 *     without it a plaintext/shared access. The C-bit is self-sufficient -- a
 *     private access claims its target page as encrypted (auto-manage), so the
 *     host never needs to pre-mark guest private memory managed;
 *   - CPUID leaf 0x8000001f advertises SEV, the C-bit position and the number
 *     of reduced physical bits.
 *
 * This is purely a software simulation for TCG; it provides no real
 * confidentiality and no launch/attestation flow yet.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"

#include "qapi/error.h"
#include "qom/object_interfaces.h"
#include "exec/memattrs.h"
#include "hw/core/cpu.h"
#include "system/memory-encryption.h"
#include "target/i386/sev-sim.h"

#define TYPE_X86_SEV_SIM "x86-sev-sim"
OBJECT_DECLARE_SIMPLE_TYPE(X86SevSim, X86_SEV_SIM)

typedef struct X86SevSimClass {
    ObjectClass parent_class;
} X86SevSimClass;

struct X86SevSim {
    Object parent_obj;

    char *cipher_name;
    char *key_hex;
    uint32_t owner_key_id;
    uint32_t cbitpos;          /* default 51 */
    uint32_t reduced_phys_bits;/* default 1 */
    bool encrypt_all;          /* treat all CPU accesses as encrypted */

    MemoryEncryptionEngine *engine;
};

OBJECT_DEFINE_TYPE_WITH_INTERFACES(X86SevSim, x86_sev_sim, X86_SEV_SIM,
                                   OBJECT,
                                   { TYPE_USER_CREATABLE },
                                   { NULL })

/* One SEV-sim config per VM; consulted by the accessors below. */
static X86SevSim *x86_sev_sim_singleton;

bool x86_sev_sim_active(void)
{
    return x86_sev_sim_singleton != NULL;
}

uint64_t x86_sev_sim_cbit_mask(void)
{
    return x86_sev_sim_singleton ? (1ULL << x86_sev_sim_singleton->cbitpos) : 0;
}

uint32_t x86_sev_sim_cbit_position(void)
{
    return x86_sev_sim_singleton ? x86_sev_sim_singleton->cbitpos : 0;
}

uint32_t x86_sev_sim_reduced_phys_bits(void)
{
    return x86_sev_sim_singleton ? x86_sev_sim_singleton->reduced_phys_bits : 0;
}

/*
 * Key resolver: an encrypted/private access (C-bit set) or any access in
 * encrypt-all mode uses the owner key; otherwise it is a plaintext/shared
 * view (no key) that observes the raw ciphertext backing.
 *
 * NOTE: @cs is intentionally accepted but not yet used. Real AMD SEV selects
 * the encryption key by ASID -- one key per guest VM, and a wrong ASID
 * decrypts to garbage -- and @cs is the hook through which a future
 * ASID->key lookup would read the current encryption context. This
 * implementation instead returns a single owner key (engine->owner_key_id),
 * which is correct for the single-VM / single-key case modelled today but
 * does not yet reproduce SEV's ASID-selected multi-key behaviour. The
 * underlying engine already supports multiple keys (cipher store plus
 * per-key working pages); wiring ASID selection is deferred to the SEV
 * launch/attestation phase.
 */
static uint32_t sev_sim_resolve(MemoryEncryptionEngine *eng, CPUState *cs,
                                hwaddr paddr, MemTxAttrs attrs)
{
    uint32_t owner = mem_enc_owner_key_id(eng);

    if (x86_sev_sim_singleton && x86_sev_sim_singleton->encrypt_all) {
        return owner;
    }
    return attrs.mem_enc ? owner : MEM_ENC_KEY_NONE;
}

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

static char *x86_sev_sim_get_cipher(Object *obj, Error **errp)
{
    return g_strdup(X86_SEV_SIM(obj)->cipher_name);
}

static void x86_sev_sim_set_cipher(Object *obj, const char *value, Error **errp)
{
    X86SevSim *s = X86_SEV_SIM(obj);

    g_free(s->cipher_name);
    s->cipher_name = g_strdup(value);
}

static char *x86_sev_sim_get_key(Object *obj, Error **errp)
{
    return g_strdup(X86_SEV_SIM(obj)->key_hex ?: "");
}

static void x86_sev_sim_set_key(Object *obj, const char *value, Error **errp)
{
    X86SevSim *s = X86_SEV_SIM(obj);

    g_free(s->key_hex);
    s->key_hex = g_strdup(value);
}

static bool x86_sev_sim_get_encrypt_all(Object *obj, Error **errp)
{
    return X86_SEV_SIM(obj)->encrypt_all;
}

static void x86_sev_sim_set_encrypt_all(Object *obj, bool value, Error **errp)
{
    X86_SEV_SIM(obj)->encrypt_all = value;
}

/* ----------------------------------------------------------------------- */
/* realization                                                              */
/* ----------------------------------------------------------------------- */

static void x86_sev_sim_complete(UserCreatable *uc, Error **errp)
{
    X86SevSim *s = X86_SEV_SIM(uc);
    g_autofree uint8_t *key = NULL;
    size_t keylen = 0;

    if (x86_sev_sim_singleton) {
        error_setg(errp, "only one x86-sev-sim object is supported");
        return;
    }

    if (s->key_hex) {
        if (hex_decode(s->key_hex, &key, &keylen, errp) < 0) {
            return;
        }
    }

    s->engine = mem_enc_engine_new(s->cipher_name, s->owner_key_id);
    if (mem_enc_set_key(s->engine, s->owner_key_id, key, keylen, errp) < 0) {
        return;
    }
    mem_enc_set_key_resolver(s->engine, sev_sim_resolve);

    /*
     * Make the C-bit self-sufficient: a private (C-bit) access to an unmanaged
     * page claims that page as encrypted, exactly as real SEV encrypts all of
     * the guest's C-bit memory without the host pre-marking it managed.
     */
    mem_enc_set_auto_manage(s->engine, true);

    /* Publish the SEV config for the page walk and CPUID. */
    x86_sev_sim_singleton = s;

    /* Activate the engine singleton so the cputlb/flatview hooks engage. */
    mem_enc_engine_activate(s->engine);
}

static void x86_sev_sim_init(Object *obj)
{
    X86SevSim *s = X86_SEV_SIM(obj);

    s->cipher_name = g_strdup("identity");
    s->owner_key_id = 1;
    s->cbitpos = 51;
    s->reduced_phys_bits = 1;

    object_property_add_str(obj, "cipher",
                            x86_sev_sim_get_cipher, x86_sev_sim_set_cipher);
    object_property_add_str(obj, "key",
                            x86_sev_sim_get_key, x86_sev_sim_set_key);
    object_property_add_uint32_ptr(obj, "owner-key-id", &s->owner_key_id,
                                   OBJ_PROP_FLAG_READWRITE);
    object_property_add_uint32_ptr(obj, "cbitpos", &s->cbitpos,
                                   OBJ_PROP_FLAG_READWRITE);
    object_property_add_uint32_ptr(obj, "reduced-phys-bits",
                                   &s->reduced_phys_bits,
                                   OBJ_PROP_FLAG_READWRITE);
    object_property_add_bool(obj, "encrypt-all",
                             x86_sev_sim_get_encrypt_all,
                             x86_sev_sim_set_encrypt_all);
}

static void x86_sev_sim_finalize(Object *obj)
{
    X86SevSim *s = X86_SEV_SIM(obj);

    if (x86_sev_sim_singleton == s) {
        x86_sev_sim_singleton = NULL;
    }
    mem_enc_engine_free(s->engine);
    g_free(s->cipher_name);
    g_free(s->key_hex);
}

static void x86_sev_sim_class_init(ObjectClass *oc, const void *data)
{
    UserCreatableClass *uc = USER_CREATABLE_CLASS(oc);

    uc->complete = x86_sev_sim_complete;
}
