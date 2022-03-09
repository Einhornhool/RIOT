#ifndef PSA_CRYPTO_SLOT_MANAGEMENT_H
#define PSA_CRYPTO_SLOT_MANAGEMENT_H

#include "clist.h"
#include "psa/crypto.h"
#include "psa_crypto_se_management.h"

#define PSA_PROTECTED_KEY_COUNT         (CONFIG_PSA_KEY_SLOT_COUNT)
#define PSA_ASYMMETRIC_KEYPAIR_COUNT    (CONFIG_PSA_KEY_SLOT_COUNT)
#define PSA_UNSTR_KEY_COUNT             (CONFIG_PSA_KEY_SLOT_COUNT)
#define PSA_KEY_SLOT_COUNT              (PSA_PROTECTED_KEY_COUNT + \
                                         PSA_ASYMMETRIC_KEYPAIR_COUNT + \
                                         PSA_UNSTR_KEY_COUNT)

#define PSA_KEY_ID_VOLATILE_MIN (PSA_KEY_ID_VENDOR_MIN)
#define PSA_KEY_ID_VOLATILE_MAX (PSA_KEY_ID_VENDOR_MIN + PSA_KEY_SLOT_COUNT)

/**
 * @brief Structure of a virtual key slot in local memory.
 *
 * A slot contains key attributes, a lock count and the key_data structure.
 * Key_data consists of the size of the stored key in bytes and a uint8_t data array large enough
 * to store the largest key used in the current build.
 * This type of key slot contains symmetric keys, asymmetric public keys or unstructured data.
 */
typedef struct {
    clist_node_t node;
    size_t lock_count;
    psa_key_attributes_t attr;
    struct key_data {
        uint8_t data[PSA_MAX_KEY_DATA_SIZE]; /*!< Contains symmetric raw key, OR slot number for symmetric key in case of SE, OR asymmetric key pair structure */
        size_t bytes; /*!< Contains actual size of symmetric key or size of asymmetric key pair  structure, TODO: Is there a better solution? */
    } key;
} psa_key_slot_t;

void psa_init_key_slots(void);

/** Test whether a key identifier is a volatile key identifier.
 *
 * @param key_id    Key identifier to test.
 *
 * @return  1       The key identifier is a volatile key identifier.
 *          0       The key identifier is not a volatile key identifier.
 */
static inline int psa_key_id_is_volatile(psa_key_id_t key_id)
{
    return ((key_id >= PSA_KEY_ID_VOLATILE_MIN) &&
            (key_id <= PSA_KEY_ID_VOLATILE_MAX));
}

static inline int psa_key_slot_occupied(psa_key_slot_t *slot)
{
    return (slot->attr.type != 0);
}

static inline int psa_is_key_slot_locked(psa_key_slot_t *slot)
{
    return (slot->lock_count > 0);
}

static inline psa_key_slot_number_t psa_key_slot_get_slot_number(psa_key_slot_t *slot)
{
    return *((psa_key_slot_number_t *)(slot->key.data));
}

static inline psa_status_t psa_key_lifetime_is_external(psa_key_lifetime_t lifetime)
{
    return (PSA_KEY_LIFETIME_GET_LOCATION(lifetime) != PSA_KEY_LOCATION_LOCAL_STORAGE);
}

psa_status_t psa_wipe_key_slot(psa_key_slot_t *slot);
void psa_wipe_all_key_slots(void);

psa_status_t psa_get_and_lock_key_slot(psa_key_id_t id, psa_key_slot_t **slot);
psa_status_t psa_allocate_empty_key_slot(   psa_key_id_t *id,
                                            const psa_key_attributes_t * attr,
                                            psa_key_slot_t ** p_slot);

psa_status_t psa_lock_key_slot(psa_key_slot_t *slot);
psa_status_t psa_unlock_key_slot(psa_key_slot_t *slot);
psa_status_t psa_validate_key_location(psa_key_lifetime_t lifetime, psa_se_drv_data_t **driver);
psa_status_t psa_validate_key_persistence(psa_key_lifetime_t lifetime);
int psa_is_valid_key_id(psa_key_id_t id, int vendor_ok);

void psa_get_key_data_from_key_slot(const psa_key_slot_t * slot, uint8_t ** key_data, size_t ** key_bytes);
void psa_get_public_key_data_from_key_slot(const psa_key_slot_t * slot, uint8_t ** pubkey_data, size_t ** pubkey_bytes);

#endif /* CRYPTO_SLOT_MANAGEMENT_H */
