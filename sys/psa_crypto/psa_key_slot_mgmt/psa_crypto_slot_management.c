/*
 * Copyright (C) 2021 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_psa_crypto
 * @{
 *
 * @file
 * @brief       PSA Crypto Key Slot Management implementation
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#include "clist.h"
#include "psa_crypto_slot_management.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

/**
 * @brief Structure for a protected key slot.
 *
 * These slots hold Slot Numbers for keys in protected storage and, if the key type is an asymmetric key pair, the public key.
 */
typedef struct {
    clist_node_t node;
    size_t lock_count;
    psa_key_attributes_t attr;
    struct prot_key_data {
        uint8_t data[sizeof(psa_key_slot_number_t)]; /*!< Contains symmetric raw key, OR slot number for symmetric key in case of SE, OR asymmetric key pair structure */
        size_t bytes; /*!< Contains actual size of symmetric key or size of asymmetric key pair  structure, TODO: Is there a better solution? */
        uint8_t pubkey_data[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE];
        size_t pubkey_bytes;
    } key;
} psa_prot_key_slot_t;

/**
 * @brief Structure for asymmetric key pairs.
 *
 * Contains asymmetric private and public key pairs.
 *
 */
typedef struct {
    clist_node_t node;
    size_t lock_count;
    psa_key_attributes_t attr;
    struct asym_key_data {
        uint8_t data[PSA_BITS_TO_BYTES(PSA_MAX_PRIV_KEY_SIZE)]; /*!< Contains asymmetric private key */
        size_t bytes; /*!< Contains actual size of asymmetric private key */
        uint8_t pubkey_data[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE]; /*!< Contains asymmetric public key */
        size_t pubkey_bytes; /*!< Contains actual size of asymmetric private key */
    } key;
} psa_asym_key_slot_t;

static psa_asym_key_slot_t asymmetric_key_slots[PSA_ASYMMETRIC_KEYPAIR_COUNT];
static psa_prot_key_slot_t protected_key_slots[PSA_PROTECTED_KEY_COUNT];
static psa_key_slot_t single_key_slots[PSA_SINGLE_KEY_COUNT];

static clist_node_t single_key_list_empty;
static clist_node_t protected_list_empty;
static clist_node_t asymmetric_list_empty;

/**
 * @brief Global list of used key slots
 */
static clist_node_t key_slot_list;

/**
 * @brief Counter for volatile key IDs.
 */
static psa_key_id_t key_id_count = PSA_KEY_ID_VOLATILE_MIN;

/**
 * @brief Get the correct empty slot list, depending on the key type
 *
 * @param attr
 * @return clist_node_t*   Pointer to the list the key is supposed to be stored in,
 *                         according to its attributes
 */
static clist_node_t * psa_get_empty_key_slot_list(const psa_key_attributes_t * attr)
{
    if (!psa_key_lifetime_is_external(attr->lifetime)) {
        if (PSA_KEY_TYPE_IS_KEY_PAIR(attr->type)) {
            return &asymmetric_list_empty;
        }
        return &single_key_list_empty;
    }
    return &protected_list_empty;
}

/**
 * @brief Initializes key slots with zeroes and creates empty lists to abstract key slot buffers.
 *
 */
void psa_init_key_slots(void)
{
    memset(protected_key_slots, 0, sizeof(protected_key_slots));
    memset(asymmetric_key_slots, 0, sizeof(asymmetric_key_slots));
    memset(single_key_slots, 0, sizeof(single_key_slots));

    /* Create empty lists to abstract key slot buffer */
#if PSA_PROTECTED_KEY_COUNT
    for (size_t i = 0; i < PSA_PROTECTED_KEY_COUNT; i++) {
        clist_rpush(&protected_list_empty, &protected_key_slots[i].node);
    }
#endif

#if PSA_ASYMMETRIC_KEYPAIR_COUNT
    for (size_t i = 0; i < PSA_ASYMMETRIC_KEYPAIR_COUNT; i++) {
        clist_rpush(&asymmetric_list_empty, &asymmetric_key_slots[i].node);
    }
#endif

#if PSA_SINGLE_KEY_COUNT
    for (size_t i = 0; i < PSA_SINGLE_KEY_COUNT; i++) {
        clist_rpush(&single_key_list_empty, &single_key_slots[i].node);
    }
#endif
    DEBUG("Init: \nUnstr Key Slots: %d\nAsym Key Slots: %d\nProt Key Slots: %d\n", clist_count(&single_key_list_empty), clist_count(&asymmetric_list_empty), clist_count(&protected_list_empty));
}

/**
 * @brief Wipe key slot with correct key slot size
 *
 * @param slot
 */
static void psa_wipe_real_slot_type(psa_key_slot_t * slot)
{
    psa_key_attributes_t attr = slot->attr;

    if (!psa_key_lifetime_is_external(attr.lifetime)) {
        if (PSA_KEY_TYPE_IS_KEY_PAIR(attr.type)) {
            memset((psa_asym_key_slot_t *) slot, 0, sizeof(psa_asym_key_slot_t));
        }
        else {
            memset(slot, 0, sizeof(psa_key_slot_t));
        }
    }
    else {
        memset((psa_prot_key_slot_t *) slot, 0, sizeof(psa_prot_key_slot_t));
    }
}

psa_status_t psa_wipe_key_slot(psa_key_slot_t *slot)
{
    /* Get list the slot is stored in */
    clist_node_t * empty_list = psa_get_empty_key_slot_list(&slot->attr);

    /* Get node to remove from key slot list */
    clist_node_t * n = clist_remove(&key_slot_list, &slot->node);
    if (n == NULL) {
        return PSA_ERROR_DOES_NOT_EXIST;
    }

    psa_key_slot_t * tmp = container_of(n, psa_key_slot_t, node);

    /* Wipe slot associated with node */
    psa_wipe_real_slot_type(tmp);

    /* Append node to empty list for later reuse */
    clist_rpush(empty_list, n);
    return PSA_SUCCESS;
}

void psa_wipe_all_key_slots(void)
{
    /* Move all list items to empty lists */
    while (!clist_is_empty(&key_slot_list)) {
        clist_node_t * to_remove = clist_rpop(&key_slot_list);
        psa_key_slot_t * slot = container_of(to_remove, psa_key_slot_t, node);
        clist_node_t * empty_list = psa_get_empty_key_slot_list(&slot->attr);

        psa_wipe_real_slot_type(slot);
        clist_rpush(empty_list, to_remove);
    };
}

/* Find a key slot with the desired key ID in key slot list */
static int psa_get_node_with_id(clist_node_t * n, void * arg)
{
    psa_key_slot_t * slot = container_of(n, psa_key_slot_t, node);
    psa_key_id_t * id = (psa_key_id_t *) arg;
    if (slot->attr.id == *id) {
        return 1;
    }

    return 0;
}

static psa_status_t psa_get_and_lock_key_slot_in_memory(psa_key_id_t id, psa_key_slot_t **p_slot)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (psa_key_id_is_volatile(id)) {
        clist_node_t * slot_node = clist_foreach(&key_slot_list, psa_get_node_with_id, &id);
        if (slot_node == NULL) {
            return PSA_ERROR_DOES_NOT_EXIST;
        }

        psa_key_slot_t * slot = container_of(slot_node, psa_key_slot_t, node);
        status = psa_lock_key_slot(slot);
        if (status == PSA_SUCCESS) {
            *p_slot = slot;
        }
        return status;
    }

    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_get_and_lock_key_slot(psa_key_id_t id, psa_key_slot_t **p_slot)
{
    /* TODO validate ID */

    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    *p_slot = NULL;

    status = psa_get_and_lock_key_slot_in_memory(id, p_slot);
    if (status != PSA_ERROR_DOES_NOT_EXIST) {
        return status;
    }

    /* TODO: get persistent key from storage and load into slot */

    return status;
}

static psa_status_t psa_allocate_key_slot_in_list(psa_key_slot_t ** p_slot, const psa_key_attributes_t * attr)
{
    clist_node_t * empty_list = psa_get_empty_key_slot_list(attr);
    /* Check if any empty elements of this key slot type are left */
    if (clist_is_empty(empty_list)) {
        return PSA_ERROR_INSUFFICIENT_STORAGE;
    }

    /* TODO: If no slots left: Look for slot in list with persistent key
    (key will be stored in persistent memory and slot can be reused) */

    /* Remove key slote node from empty list and append to actual list */
    clist_node_t * new_slot = clist_rpop(empty_list);
    clist_rpush(&key_slot_list, new_slot);

    psa_key_slot_t * slot = container_of(new_slot, psa_key_slot_t, node);
    *p_slot = slot;
    return PSA_SUCCESS;
}

psa_status_t psa_allocate_empty_key_slot(   psa_key_id_t *id,
                                            const psa_key_attributes_t * attr,
                                            psa_key_slot_t ** p_slot)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t * new_slot = NULL;

    /* Change later, when we also have persistent keys */
    if (key_id_count == PSA_KEY_ID_VOLATILE_MAX) {
        return PSA_ERROR_INSUFFICIENT_STORAGE;
    }

    status = psa_allocate_key_slot_in_list(&new_slot, attr);
    if (status != PSA_SUCCESS) {
        *p_slot = NULL;
        *id = 0;
        return status;
    }

    if (new_slot != NULL) {
        status = psa_lock_key_slot(new_slot);
        if (status != PSA_SUCCESS) {
            *p_slot = NULL;
            *id = 0;
            return status;
        }
        *id = key_id_count++;
        *p_slot = new_slot;

        return PSA_SUCCESS;
    }

    status = PSA_ERROR_INSUFFICIENT_MEMORY;
    *p_slot = NULL;
    *id = 0;
    return status;
}

psa_status_t psa_lock_key_slot(psa_key_slot_t *slot)
{
    if (slot->lock_count >= SIZE_MAX) {
        return PSA_ERROR_CORRUPTION_DETECTED;
    }

    slot->lock_count++;

    return PSA_SUCCESS;
}

psa_status_t psa_unlock_key_slot(psa_key_slot_t *slot)
{
    if (slot == NULL) {
        return PSA_SUCCESS;
    }

    if (slot->lock_count > 0) {
        slot->lock_count--;
        return PSA_SUCCESS;
    }

    return PSA_ERROR_CORRUPTION_DETECTED;
}

psa_status_t psa_validate_key_location(psa_key_lifetime_t lifetime, psa_se_drv_data_t **p_drv)
{
    if (psa_key_lifetime_is_external(lifetime)) {
#if IS_ACTIVE(CONFIG_PSA_SECURE_ELEMENT)
        psa_se_drv_data_t *driver = psa_get_se_driver_data(lifetime);
        if (driver != NULL) {
            if (p_drv != NULL) {
                *p_drv = driver;
            }
            return PSA_SUCCESS;
        }
#else
        (void) p_drv;
#endif /* CONFIG_PSA_SECURE_ELEMENT */
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    else {
        (void) p_drv;
        return PSA_SUCCESS;
    }
}

psa_status_t psa_validate_key_persistence(psa_key_lifetime_t lifetime)
{
    if (PSA_KEY_LIFETIME_IS_VOLATILE(lifetime)) {
        return PSA_SUCCESS;
    }
    /* TODO: Implement persistent key storage */
    return PSA_ERROR_NOT_SUPPORTED;
}

int psa_is_valid_key_id(psa_key_id_t id, int vendor)
{
    if ((PSA_KEY_ID_USER_MIN <= id) &&
        (id <= PSA_KEY_ID_USER_MAX)) {
        return 1;
    }

    if (vendor
        && (PSA_KEY_ID_VENDOR_MIN <= id)
        && (id <= PSA_KEY_ID_VENDOR_MAX)) {
        return 1;
    }

    return 0;
}

void psa_get_key_data_from_key_slot(const psa_key_slot_t * slot, uint8_t ** key_data, size_t ** key_bytes)
{
    psa_key_attributes_t attr = slot->attr;

    if (!psa_key_lifetime_is_external(attr.lifetime)) {
        if (PSA_KEY_TYPE_IS_KEY_PAIR(attr.type)) {
            *key_data = ((psa_asym_key_slot_t *)slot)->key.data;
            *key_bytes = &((psa_asym_key_slot_t *)slot)->key.bytes;
            return;
        }
        else {
            *key_data = ((psa_key_slot_t *)slot)->key.data;
            *key_bytes = &((psa_key_slot_t *)slot)->key.bytes;
            return;
        }
    }

    *key_data = ((psa_prot_key_slot_t *)slot)->key.data;
    *key_bytes = &((psa_prot_key_slot_t *)slot)->key.bytes;
}

void psa_get_public_key_data_from_key_slot(const psa_key_slot_t * slot, uint8_t ** pubkey_data, size_t ** pubkey_bytes)
{
    psa_key_attributes_t attr = slot->attr;
    if (!PSA_KEY_TYPE_IS_ASYMMETRIC(attr.type)) {
        *pubkey_data = NULL;
        *pubkey_bytes = NULL;
        return;
    }

    if (!psa_key_lifetime_is_external(attr.lifetime)) {
        if (PSA_KEY_TYPE_IS_KEY_PAIR(attr.type)) {
            *pubkey_data = ((psa_asym_key_slot_t *)slot)->key.pubkey_data;
            *pubkey_bytes = &((psa_asym_key_slot_t *)slot)->key.pubkey_bytes;
            return;
        }
        else {
            *pubkey_data = ((psa_key_slot_t *)slot)->key.data;
            *pubkey_bytes = &((psa_key_slot_t *)slot)->key.bytes;
            return;
        }
    }
    *pubkey_data = ((psa_prot_key_slot_t *)slot)->key.pubkey_data;
    *pubkey_bytes = &((psa_prot_key_slot_t *)slot)->key.pubkey_bytes;
}
