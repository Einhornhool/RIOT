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

#define ENABLE_DEBUG    (0)
#include "debug.h"

typedef struct
{
    /* Slots for symmetric keys */
    psa_key_slot_t key_slots[PSA_KEY_SLOT_COUNT];

    /* Slots for asymmetric Key Pairs */
    psa_key_slot_t asymmetric_key_slots[PSA_KEY_SLOT_COUNT];

    /* Slots for keys stored in external storage */
    psa_key_slot_t external_key_slots[PSA_KEY_SLOT_COUNT];
} psa_key_storage_t;

static psa_key_storage_t key_storage;

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
    psa_key_type_t type = slot->attr.type;

    memset(slot, 0, sizeof(*slot));

    return PSA_SUCCESS;
}

static psa_status_t psa_get_and_lock_key_slot_in_memory(psa_key_id_t id, psa_key_slot_t **p_slot)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t slot_index;
    psa_key_slot_t *slot = NULL;

    if (psa_key_id_is_volatile(id)) {
        slot = &key_storage.key_slots[id - PSA_KEY_ID_VOLATILE_MIN];
        status = (slot->attr.id == id) ? PSA_SUCCESS : PSA_ERROR_DOES_NOT_EXIST;
    }
    else {
        if (!psa_is_valid_key_id(id, 1)) {
            return PSA_ERROR_INVALID_HANDLE;
        }

        for (slot_index = 0; slot_index < PSA_KEY_SLOT_COUNT; slot_index++) {
            slot = &key_storage.key_slots[slot_index];
            if (slot->attr.id == id) {
                break;
            }
        }
        status = (slot_index < PSA_KEY_SLOT_COUNT) ? PSA_SUCCESS : PSA_ERROR_DOES_NOT_EXIST;
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
        psa_key_slot_t *slot = &key_storage.key_slots[i];
        slot->lock_count = 1;
        psa_wipe_key_slot(slot);
    }
}

#if IS_ACTIVE(PSA_DYNAMIC_KEY_SLOT_ALLOCATION)
psa_status_t psa_allocate_empty_key_slot(   psa_key_id_t *id,
                                            const psa_key_attributes_t * attr,
                                            psa_key_slot_t **p_slot) {
    return PSA_ERROR_NOT_SUPPORTED;
}
#else
psa_status_t psa_allocate_empty_key_slot(   psa_key_id_t *id,
                                            const psa_key_attributes_t * attr,
                                            psa_key_slot_t **p_slot) {
    return PSA_ERROR_NOT_SUPPORTED;
}
#endif

psa_status_t psa_get_empty_key_slot(psa_key_id_t *id, const psa_key_attributes_t * attr, psa_key_slot_t **p_slot)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *selected_slot, *unlocked_persistent_slot;

    selected_slot = unlocked_persistent_slot = NULL;

    for (size_t i = 0; i < PSA_KEY_SLOT_COUNT; i++) {
        psa_key_slot_t *slot = &key_storage.key_slots[i];
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
        *id = PSA_KEY_ID_VOLATILE_MIN + ((psa_key_id_t) (selected_slot - key_storage.key_slots));
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
