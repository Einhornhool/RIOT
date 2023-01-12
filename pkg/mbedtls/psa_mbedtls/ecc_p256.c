/*
 * Copyright (C) 2022 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_psa_crypto pkg_mbedtls
 * @{
 *
 * @brief       Glue code translating between PSA Crypto and the mbedtls legacy APIs
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/platform.h"

#include "mbedtls_psa_error.h"
#include "psa/crypto.h"

extern int mbedtls_fake_random(void *rng_state, unsigned char *output, size_t len);

static psa_status_t mbedtls_psa_ecp_load_representation(
    psa_key_type_t type, size_t curve_bits,
    const uint8_t *data, size_t data_length,
    mbedtls_ecp_keypair **p_ecp )
{
    mbedtls_ecp_group_id grp_id = MBEDTLS_ECP_DP_NONE;
    psa_status_t status;
    mbedtls_ecp_keypair *ecp = NULL;
    size_t curve_bytes = data_length;
    int explicit_bits = ( curve_bits != 0 );

    if( PSA_KEY_TYPE_IS_PUBLIC_KEY( type ) &&
        PSA_KEY_TYPE_ECC_GET_FAMILY( type ) != PSA_ECC_FAMILY_MONTGOMERY )
    {
        /* A Weierstrass public key is represented as:
         * - The byte 0x04;
         * - `x_P` as a `ceiling(m/8)`-byte string, big-endian;
         * - `y_P` as a `ceiling(m/8)`-byte string, big-endian.
         * So its data length is 2m+1 where m is the curve size in bits.
         */
        if( ( data_length & 1 ) == 0 )
            return( PSA_ERROR_INVALID_ARGUMENT );
        curve_bytes = data_length / 2;

        /* Montgomery public keys are represented in compressed format, meaning
         * their curve_bytes is equal to the amount of input. */

        /* Private keys are represented in uncompressed private random integer
         * format, meaning their curve_bytes is equal to the amount of input. */
    }

    if( explicit_bits )
    {
        /* With an explicit bit-size, the data must have the matching length. */
        if( curve_bytes != PSA_BITS_TO_BYTES( curve_bits ) )
            return( PSA_ERROR_INVALID_ARGUMENT );
    }
    else
    {
        /* We need to infer the bit-size from the data. Since the only
         * information we have is the length in bytes, the value of curve_bits
         * at this stage is rounded up to the nearest multiple of 8. */
        curve_bits = PSA_BYTES_TO_BITS( curve_bytes );
    }

    /* Allocate and initialize a key representation. */
    ecp = mbedtls_calloc( 1, sizeof( mbedtls_ecp_keypair ) );
    if( ecp == NULL )
        return( PSA_ERROR_INSUFFICIENT_MEMORY );
    mbedtls_ecp_keypair_init( ecp );

    /* Load the group. */
    grp_id = MBEDTLS_ECP_DP_SECP256R1;

    status = mbedtls_to_psa_error(
                mbedtls_ecp_group_load( &ecp->grp, grp_id ) );
    if( status != PSA_SUCCESS )
        goto exit;

    /* Load the key material. */
    if( PSA_KEY_TYPE_IS_PUBLIC_KEY( type ) )
    {
        /* Load the public value. */
        status = mbedtls_to_psa_error(
            mbedtls_ecp_point_read_binary( &ecp->grp, &ecp->Q,
                                           data,
                                           data_length ) );
        if( status != PSA_SUCCESS )
            goto exit;

        /* Check that the point is on the curve. */
        status = mbedtls_to_psa_error(
            mbedtls_ecp_check_pubkey( &ecp->grp, &ecp->Q ) );
        if( status != PSA_SUCCESS )
            goto exit;
    }
    else
    {
        /* Load and validate the secret value. */
        status = mbedtls_to_psa_error(
            mbedtls_ecp_read_key( ecp->grp.id,
                                  ecp,
                                  data,
                                  data_length ) );
        if( status != PSA_SUCCESS )
            goto exit;
    }

    *p_ecp = ecp;
exit:
    if( status != PSA_SUCCESS )
    {
        mbedtls_ecp_keypair_free( ecp );
        mbedtls_free( ecp );
    }

    return( status );
}

psa_status_t psa_generate_ecc_p256r1_key_pair(  const psa_key_attributes_t *attributes,
                                                uint8_t *priv_key_buffer, uint8_t *pub_key_buffer,
                                                size_t *priv_key_buffer_length,
                                                size_t *pub_key_buffer_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    int ret;

    size_t priv_key_size = PSA_BITS_TO_BYTES(attributes->bits);
    size_t pub_key_size = PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(attributes->bits);

    mbedtls_ecp_group_id grp_id = MBEDTLS_ECP_DP_SECP256R1;

    const mbedtls_ecp_curve_info *curve_info =
        mbedtls_ecp_curve_info_from_grp_id( grp_id );
    mbedtls_ecp_keypair ecp;

    if( grp_id == MBEDTLS_ECP_DP_NONE || curve_info == NULL )
        return( PSA_ERROR_NOT_SUPPORTED );

    mbedtls_ecp_keypair_init( &ecp );
    ret = mbedtls_ecp_gen_key( grp_id, &ecp,
                               mbedtls_fake_random,
                               NULL );
    if( ret != 0 )
    {
        mbedtls_ecp_keypair_free( &ecp );
        return( mbedtls_to_psa_error( ret ) );
    }

    status = mbedtls_to_psa_error(
        mbedtls_ecp_write_key( &ecp, priv_key_buffer, priv_key_size ) );

    /* Calculate the public key */
    status = mbedtls_to_psa_error(
        mbedtls_ecp_mul( &(ecp.grp), &(ecp.Q), &(ecp.d), &(ecp.grp.G),
                            mbedtls_fake_random,
                            NULL ) );
    if( status != PSA_SUCCESS )
        return( status );

    status = mbedtls_to_psa_error(
                    mbedtls_ecp_point_write_binary( &(ecp.grp), &(ecp.Q),
                                                    MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                    pub_key_buffer_length,
                                                    pub_key_buffer,
                                                    pub_key_size ) );
        if( status != PSA_SUCCESS )
            memset( pub_key_buffer, 0, pub_key_size );

    mbedtls_ecp_keypair_free( &ecp );

    if( status == PSA_SUCCESS ) {
        *priv_key_buffer_length = priv_key_size;
        *pub_key_buffer_length = pub_key_size;
    }

    return( status );
}

psa_status_t psa_ecc_p256r1_sign_hash(  const psa_key_attributes_t *attributes,
                                        psa_algorithm_t alg, const uint8_t *key_buffer,
                                        size_t key_buffer_size, const uint8_t *hash,
                                        size_t hash_length, uint8_t *signature,
                                        size_t signature_size, size_t *signature_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_keypair *ecp = NULL;
    int ret;
    size_t curve_bytes;
    mbedtls_mpi r, s;

    status = mbedtls_psa_ecp_load_representation( attributes->type,
                                                  attributes->bits,
                                                  key_buffer,
                                                  key_buffer_size,
                                                  &ecp );
    if( status != PSA_SUCCESS )
        return( status );

    curve_bytes = PSA_BITS_TO_BYTES( ecp->grp.pbits );
    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &s );

    if( signature_size < 2 * curve_bytes )
    {
        ret = MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK( mbedtls_ecdsa_sign( &ecp->grp, &r, &s, &ecp->d,
                                             hash, hash_length,
                                             mbedtls_fake_random,
                                             NULL ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &r,
                                               signature,
                                               curve_bytes ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &s,
                                               signature + curve_bytes,
                                               curve_bytes ) );

cleanup:
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );
    if( ret == 0 )
        *signature_length = 2 * curve_bytes;

    mbedtls_ecp_keypair_free(ecp);
    mbedtls_free( ecp );

    (void) alg;
    return( mbedtls_to_psa_error( ret ) );
}

psa_status_t psa_ecc_p256r1_verify_hash(const psa_key_attributes_t *attributes,
                                        psa_algorithm_t alg, const uint8_t *key_buffer,
                                        size_t key_buffer_size, const uint8_t *hash,
                                        size_t hash_length, const uint8_t *signature,
                                        size_t signature_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_keypair *ecp = NULL;
    int ret;
    size_t curve_bytes;
    mbedtls_mpi r, s;

    (void)alg;

    status = mbedtls_psa_ecp_load_representation( attributes->type,
                                                  256,
                                                  key_buffer,
                                                  key_buffer_size,
                                                  &ecp );
    if( status != PSA_SUCCESS )
        return( status );

    curve_bytes = PSA_BITS_TO_BYTES( ecp->grp.pbits );
    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &s );

    if( signature_length != 2 * curve_bytes )
    {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &r,
                                              signature,
                                              curve_bytes ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &s,
                                              signature + curve_bytes,
                                              curve_bytes ) );

    /* Check whether the public part is loaded. If not, load it. */
    if( mbedtls_ecp_is_zero( &ecp->Q ) )
    {
        MBEDTLS_MPI_CHK(
            mbedtls_ecp_mul( &ecp->grp, &ecp->Q, &ecp->d, &ecp->grp.G,
                             mbedtls_fake_random, NULL ) );
    }

    ret = mbedtls_ecdsa_verify( &ecp->grp, hash, hash_length,
                                &ecp->Q, &r, &s );

cleanup:
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );
    mbedtls_ecp_keypair_free( ecp );
    mbedtls_free( ecp );

    return( mbedtls_to_psa_error( ret ) );
}
