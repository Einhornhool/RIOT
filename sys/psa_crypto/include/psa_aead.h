#include "psa/crypto.h"

psa_status_t psa_aead_ccm_aes_128_encrypt_setup(void);

psa_status_t psa_aead_ccm_aes_128_decrypt_setup(void);

psa_status_t psa_aead_ccm_aes_128_update_ad(void);

psa_status_t psa_aead_ccm_aes_128_update(void);

psa_status_t psa_aead_ccm_aes_128_finish(void);
