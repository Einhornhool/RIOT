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

#define ENABLE_DEBUG    (1)
#include "debug.h"

/**
 * @brief Structure of a virtual key slot in local memory.
 *
 * A slot contains key attributes, a lock count and the key_data structure.
 * Key_data consists of the size of the stored key in bytes and a uint8_t data array large enough
 * to store the largest key used in the current build.
 * Keys can be either symmetric or an asymmetric public key.
 */
typedef struct psa_key_slot_s {
    clist_node_t node;
    size_t lock_count;
    psa_key_attributes_t attr;
    struct key_data {
        uint8_t data[PSA_MAX_KEY_DATA_SIZE]; /*!< Contains symmetric raw key, OR slot number for symmetric key in case of SE, OR asymmetric key pair structure */
        size_t bytes; /*!< Contains actual size of symmetric key or size of asymmetric key pair  structure, TODO: Is there a better solution? */
    } key;
};

typedef struct {
    clist_node_t node;
    size_t lock_count;
    psa_key_attributes_t attr;
    struct key_data {
        uint8_t data[PSA_BITS_TO_BYTES(PSA_MAX_PRIV_KEY_SIZE)]; /*!< Contains asymmetric private key */
        size_t bytes; /*!< Contains actual size of asymmetric private key */
        uint8_t pubkey_data[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE]; /*!< Contains asymmetric public key */
        size_t pubkey_bytes; /*!< Contains actual size of asymmetric private key */
    } key;
} psa_asym_key_slot_t;

typedef struct {
    clist_node_t node;
    size_t lock_count;
    psa_key_attributes_t attr;
    struct key_data {
        uint8_t data[sizeof(psa_key_slot_number_t)]; /*!< Contains symmetric raw key, OR slot number for symmetric key in case of SE, OR asymmetric key pair structure */
        size_t bytes; /*!< Contains actual size of symmetric key or size of asymmetric key pair  structure, TODO: Is there a better solution? */
        uint8_t pubkey_data[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE];
        size_t pubkey_bytes;
    } key;
} psa_prot_key_slot_t;

static psa_prot_key_slot_t protected_key_slots[PSA_PROTECTED_KEY_COUNT][sizeof(psa_prot_key_slot_t)];
static clist_node_t protected_list_empty;
static clist_node_t protected_list;

static psa_asym_key_slot_t asymmetric_key_slots[PSA_ASYMMETRIC_KEYPAIR_COUNT][sizeof(psa_asym_key_slot_t)];
static clist_node_t asymmetric_list_empty;
static clist_node_t asymmetric_list;

static psa_key_slot_t unstructured_key_slots[PSA_UNSTR_KEY_COUNT][sizeof(psa_key_slot_t)];
static clist_node_t unstruct_list_empty;
static clist_node_t unstruct_list;

static psa_key_id_t unstr_key_id_count = PSA_KEY_ID_VOLATILE_MIN;
static psa_key_id_t asym_key_id_count = PSA_KEY_ID_VOLATILE_MIN + PSA_UNSTR_KEY_COUNT;
static psa_key_id_t prot_key_id_count = PSA_KEY_ID_VOLATILE_MIN + PSA_UNSTR_KEY_COUNT + PSA_ASYMMETRIC_KEYPAIR_COUNT;

static clist_node_t * psa_get_empty_key_slot_list(const psa_key_attributes_t * attr)
{
    if (PSA_KEY_LIFETIME_GET_LOCATION(attr->lifetime) == PSA_KEY_LOCATION_LOCAL_STORAGE) {
        if (PSA_KEY_TYPE_IS_KEY_PAIR(attr->type)) {
            return &asymmetric_list_empty;
        }
        return &unstruct_list_empty;
    }
    return &protected_list_empty;
}

static clist_node_t * psa_get_key_slot_list(const psa_key_attributes_t * attr)
{
    if (PSA_KEY_LIFETIME_GET_LOCATION(attr->lifetime) == PSA_KEY_LOCATION_LOCAL_STORAGE) {
        if (PSA_KEY_TYPE_IS_KEY_PAIR(attr->type)) {
            return &asymmetric_list;
        }
        return &unstruct_list;
    }
    return &protected_list;
}

void psa_init_key_slots(void)
{
    psa_wipe_all_key_slots();

    /* Create empty lists to abstract key slot buffer */
    for (size_t i = 0; i < PSA_PROTECTED_KEY_COUNT; i++) {
        clist_rpush(&protected_list_empty, &protected_key_slots[i].node);
    }

    for (size_t i = 0; i < PSA_ASYMMETRIC_KEYPAIR_COUNT; i++) {
        clist_rpush(&asymmetric_list_empty, &asymmetric_key_slots[i].node);
    }

    for (size_t i = 0; i < PSA_UNSTR_KEY_COUNT; i++) {
        clist_rpush(&unstruct_list_empty, &unstructured_key_slots[i].node);
    }
}

int psa_is_valid_key_id(psa_key_id_t id, int vendor_ok)
{
    if ((PSA_KEY_ID_USER_MIN <= id) &&
        (id <= PSA_KEY_ID_USER_MAX)) {
        return 1;
    }

    if (vendor_ok
        && (PSA_KEY_ID_VENDOR_MIN <= id)
        && (id <= PSA_KEY_ID_VENDOR_MAX)) {
        return 1;
    }

    return 0;
}

psa_status_t psa_wipe_key_slot(psa_key_slot_t *slot)
{
    /* Get list the slot is stored in */
    clist_node_t * list = psa_get_key_slot_list(&slot->attr);
    clist_node_t * empty_list = psa_get_empty_key_slot_list(&slot->attr);

    /* Remove node from list and add back to empty list to free node */
    clist_node_t * node = clist_remove(list, &slot->node);
    clist_rpush(empty_list, node);

    /* Wipe slot */
    memset(slot, 0, sizeof(*slot));

    return PSA_SUCCESS;
}

void psa_wipe_all_key_slots(void)
{
    /* Move all list items to empty lists */
    if (!clist_is_empty(&protected_list)) {
        for (size_t i = 0; i < PSA_PROTECTED_KEY_COUNT; i++) {
            clist_node_t * tmp = clist_rpop(&protected_list);
            clist_rpush(&protected_list_empty, tmp);
        }
    }

    if (!clist_is_empty(&asymmetric_list)) {
        for (size_t i = 0; i < PSA_ASYMMETRIC_KEYPAIR_COUNT; i++) {
            clist_node_t * tmp = clist_rpop(&asymmetric_list);
            clist_rpush(&asymmetric_list_empty, tmp);
        }
    }

    if (!clist_is_empty(&unstruct_list)) {
        for (size_t i = 0; i < PSA_UNSTR_KEY_COUNT; i++) {
            clist_node_t * tmp = clist_rpop(&unstruct_list);
            clist_rpush(&unstruct_list_empty, tmp);
        }
    }

    memset(protected_key_slots, 0, sizeof(protected_key_slots));
    memset(asymmetric_key_slots, 0, sizeof(asymmetric_key_slots));
    memset(unstructured_key_slots, 0, sizeof(unstructured_key_slots));
}

static int psa_get_node_with_id(clist_node_t * n, psa_key_id_t * id, void * arg)
{
    psa_key_slot_t * slot = container_of(n, psa_key_slot_t, node);
    if (slot->attr.id == id) {
        return 1;
    }
    return 0;
}

static psa_status_t psa_get_and_lock_key_slot_in_memory(psa_key_id_t id, psa_key_slot_t **p_slot)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot = NULL;

    if (psa_key_id_is_volatile(id)) {
        clist_node_t * slot_node = clist_foreach()
        status = (slot->attr.id == id) ? PSA_SUCCESS : PSA_ERROR_DOES_NOT_EXIST;
    }
    else {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    if (status == PSA_SUCCESS) {
        status = psa_lock_key_slot(slot);
        if (status == PSA_SUCCESS) {
            *p_slot = slot;
        }
    }

    (void) id;
    (void) p_slot;
    return status;
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

static psa_status_t psa_allocate_key_slot_in_list(psa_key_slot_t * slot, const psa_key_attributes_t * attr)
{
    clist_node_t * empty_list = psa_get_empty_key_slot_list(attr);
    clist_node_t * list = psa_get_key_slot_list(attr);

    /* Check if any empty elements of this key slot type are left */
    if (clist_is_empty(&empty_list)) {
        return PSA_ERROR_INSUFFICIENT_STORAGE;
    }

    /* TODO: If no slots left: Look for slot in list with persistent key
    (key will be stored in persistent memory and slot can be reused) */

    /* Remove key slote node from empty list and append to actual list */
    clist_node_t * new_slot = clist_rpop(&empty_list);
    clist_rpush(&list, new_slot);

    slot = container_of(new_slot, psa_key_slot_t, node);
    return PSA_SUCCESS;
}

psa_status_t psa_allocate_empty_key_slot(   psa_key_id_t *id,
                                            const psa_key_attributes_t * attr,
                                            psa_key_slot_t ** p_slot)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *new_slot;

    /* Change later, when we also have persistent keys */
    if (key_id_count == PSA_KEY_ID_VOLATILE_MAX) {
        return PSA_ERROR_INSUFFICIENT_STORAGE;
    }

    status = psa_allocate_key_slot_in_list(new_slot, attr);

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
