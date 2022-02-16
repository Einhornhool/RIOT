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

#include "psa_crypto_slot_management.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

#if IS_ACTIVE(CONFIG_PSA_SECURE_ELEMENT)
static uint8_t protected_key_data[PSA_PROTECTED_KEY_COUNT][sizeof(psa_key_slot_number_t)];
#endif
#if IS_ACTIVE(CONFIG_PSA_ASYMMETRIC)
static uint8_t asymmetric_key_data[PSA_ASYMMETRIC_KEYPAIR_COUNT][PSA_MAX_ASYMMETRIC_KEYPAIR_SIZE];
#endif

static uint8_t unstructured_key_data[PSA_UNSTR_KEY_COUNT][PSA_MAX_KEY_DATA_SIZE];


/* Slots for symmetric keys */
psa_key_slot_t key_slots[PSA_KEY_SLOT_COUNT];

void psa_init_key_slots(void)
{
    psa_wipe_all_key_slots();
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
    memset(slot->key.data, 0, slot->key.bytes);
#if IS_ACTIVE(CONFIG_PSA_ASYMMETRIC)
    memset(slot->key.pubkey_data, 0, slot->key.pubkey_bytes);
#endif
    memset(slot, 0, sizeof(*slot));

    return PSA_SUCCESS;
}

static psa_status_t psa_get_and_lock_key_slot_in_memory(psa_key_id_t id, psa_key_slot_t **p_slot)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot = NULL;

    if (psa_key_id_is_volatile(id)) {
        slot = &key_slots[id - PSA_KEY_ID_VOLATILE_MIN];
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

void psa_wipe_all_key_slots(void)
{
    for (int i = 0; i < PSA_KEY_SLOT_COUNT; i++) {
        psa_key_slot_t * slot = &key_slots[i];
        slot->lock_count = 1;
        psa_wipe_key_slot(slot);
    }
}

static int is_empty(uint8_t * array, size_t array_size)
{
    for (size_t i = 0; i < array_size; i++) {
        if (array[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static uint8_t * find_empty_spot(uint8_t * array, size_t array_size, size_t array_element_size)
{
    for (size_t i = 0; i < array_size; i++) {
        if (is_empty(&array[i], array_element_size)) {
            return &array[i];
        }
    }
    return NULL;
}

static psa_status_t psa_allocate_key_data(  psa_key_slot_t * slot,
                                            const psa_key_attributes_t * attr)
{
    uint8_t * key_data = NULL;
    size_t array_size;

    if (PSA_KEY_LIFETIME_GET_LOCATION(attr->lifetime) == PSA_KEY_LOCATION_LOCAL_STORAGE) {
        if (!PSA_KEY_TYPE_IS_KEY_PAIR(attr->type)) {
            array_size = sizeof(unstructured_key_data)/sizeof(unstructured_key_data[0]);
            key_data = find_empty_spot((uint8_t *)unstructured_key_data, array_size, sizeof(unstructured_key_data[0]));
        }
#if IS_ACTIVE(CONFIG_PSA_ASYMMETRIC)
        else {
            array_size = sizeof(asymmetric_key_data)/sizeof(asymmetric_key_data[0]);
            key_data = find_empty_spot((uint8_t *) asymmetric_key_data, array_size, sizeof(asymmetric_key_data[0]));
        }
#endif
    }
#if IS_ACTIVE(CONFIG_PSA_SECURE_ELEMENT)
    else {
        array_size = sizeof(protected_key_data)/sizeof(protected_key_data[0]);
        key_data = find_empty_spot((uint8_t *) protected_key_data, array_size, sizeof(protected_key_data[0]));
    }
#endif

    if (key_data == NULL) {
        return PSA_ERROR_INSUFFICIENT_STORAGE;
    }

#if IS_ACTIVE(CONFIG_PSA_ASYMMETRIC) || IS_ACTIVE(CONFIG_PSA_SECURE_ELEMENT_ECC)
    if (PSA_KEY_TYPE_IS_KEY_PAIR(attr->type)) {
        slot->key.pubkey_data = key_data + PSA_MAX_PRIV_KEY_SIZE;
    }
#endif
    slot->key.data = key_data;

    return PSA_SUCCESS;
}

psa_status_t psa_allocate_empty_key_slot(   psa_key_id_t *id,
                                            const psa_key_attributes_t * attr,
                                            psa_key_slot_t ** p_slot)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *selected_slot, *unlocked_persistent_slot;

    selected_slot = unlocked_persistent_slot = NULL;

    for (size_t i = 0; i < PSA_KEY_SLOT_COUNT; i++) {
        psa_key_slot_t *slot = &key_slots[i];
        if (!psa_key_slot_occupied(slot)) {
            selected_slot = slot;
            break;
        }
        /* If a key is stored in persistent memory, we can reuse its slot in local memory */
        if ((!PSA_KEY_LIFETIME_IS_VOLATILE(slot->attr.lifetime) &&
            (psa_key_slot_occupied(slot)))) {
            unlocked_persistent_slot = slot;
        }
    }

    if ((selected_slot == NULL) && (unlocked_persistent_slot != NULL)) {
        selected_slot = unlocked_persistent_slot;
        selected_slot->lock_count = 1;
        psa_wipe_key_slot(selected_slot);
    }

    if (selected_slot != NULL) {
        status = psa_lock_key_slot(selected_slot);
        if (status != PSA_SUCCESS) {
            *p_slot = NULL;
            *id = 0;
            return status;
        }
        status = psa_allocate_key_data(selected_slot, attr);
        if (status != PSA_SUCCESS) {
            *p_slot = NULL;
            *id = 0;
            return status;
        }
        *id = PSA_KEY_ID_VOLATILE_MIN + ((psa_key_id_t) (selected_slot - key_slots));
        *p_slot = selected_slot;

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
