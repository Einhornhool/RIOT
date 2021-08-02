#include "psa/crypto.h"
#include "crypto/modes/ecb.h"
#include "crypto/modes/cbc.h"

#define ALG_IS_SUPPORTED(alg)   \
    (   (alg == PSA_ALG_ECB_NO_PADDING) || \
        (alg == PSA_ALG_CBC_NO_PADDING))

static psa_status_t cipher_to_psa_error(int error)
{
    switch(error) {
        case CIPHER_ERR_INVALID_KEY_SIZE:
        case CIPHER_ERR_INVALID_LENGTH:
        case CIPHER_ERR_BAD_CONTEXT_SIZE:
            return PSA_ERROR_INVALID_ARGUMENT;
        default:
            return PSA_ERROR_GENERIC_ERROR;
    }
}

psa_status_t psa_software_cipher_encrypt_setup(  psa_software_cipher_operation_t * operation,
                                                const psa_key_attributes_t *attributes,
                                                const uint8_t *key_buffer,
                                                size_t key_buffer_size,
                                                psa_algorithm_t alg)
{
    int status;

    if (attributes->type != PSA_KEY_TYPE_AES ||
        !ALG_IS_SUPPORTED(alg)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    status = cipher_init(&operation->cipher_ctx, CIPHER_AES, key_buffer, key_buffer_size);
    if (status != CIPHER_INIT_SUCCESS) {
        return cipher_to_psa_error(status);
    }

    operation->alg = alg;

    return PSA_SUCCESS;
}

psa_status_t psa_software_cipher_decrypt_setup(  psa_software_cipher_operation_t * operation,
                                                const psa_key_attributes_t *attributes,
                                                const uint8_t *key_buffer,
                                                size_t key_buffer_size,
                                                psa_algorithm_t alg)
{
    return psa_software_cipher_encrypt_setup(operation, attributes, key_buffer, key_buffer_size, alg);
}

psa_status_t psa_software_cipher_encrypt(psa_software_cipher_operation_t * operation,
                                        const uint8_t * input,
                                        size_t input_length,
                                        uint8_t * output,
                                        size_t output_size,
                                        size_t * output_length)
{
    (void) output_size;
    int ret = 0;

    switch(operation->alg){
        case PSA_ALG_ECB_NO_PADDING:

            ret = cipher_encrypt_ecb(&operation->cipher_ctx, input, input_length, output);
            if (ret <= 0) {
                return cipher_to_psa_error(ret);
            }
            *output_length = ret;
            return PSA_SUCCESS;
        case PSA_ALG_CBC_NO_PADDING:
            ret = cipher_encrypt_cbc(&operation->cipher_ctx, operation->iv, input, input_length, output);
            if (ret <= 0) {
                return cipher_to_psa_error(ret);
            }
            // *output_length = ret;
            *output_length = 0;
            return PSA_SUCCESS;
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t psa_software_cipher_set_iv(psa_cipher_operation_t *operation,
                               const uint8_t * iv,
                               size_t iv_length)
{
    if (iv_length > 16) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    memcpy(operation->ctx.sw_ctx.iv, iv, iv_length);
    operation->iv_set = 1;

    return PSA_SUCCESS;
}
