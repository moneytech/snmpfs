/*
 * This file is part of the snmpfs project (http://snmpfs.x25.pm).
 * snmpfs is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 2 of the license, or any later
 * version.  See LICENSE file for further copyright and license details.
 */

#ifndef SRC_SNMP_CRYPTO_H_
#define SRC_SNMP_CRYPTO_H_

#include "common.h"

#include "pdu.h"

#define SNMP_SECURITY_MODEL 0x03

#define AES_IV_LEN  0x10
#define MAX_AES_KEY_LEN  0x20
#define MAX_HASH_LEN    0x40
#define USM_HMAC_BLOCK_SIZE 0x100

#define PROCESSING_NO_ERROR                  0
#define PROCESSING_PARSE_ERROR              -1
#define PROCESSING_SECURITY_LEVEL_INVALID   -2
#define PROCESSING_SECURITY_TIME_INVALID    -3
#define PROCESSING_SECURITY_AUTH_FAILED     -4
#define PROCESSING_SECURITY_ENC_FAILED	    -5

/* SNMPv2c/SNMPv3 security models */
typedef enum {
    COMMUNITY = 0,
    USM = 1,
    TSM = 2,
    SSH = 3,
    NUMBER_OF_SEC_MODELS = 4
} SnmpSecurityModel;

typedef enum {
    NO_AUTH_NO_PRIV = 0,
    AUTH_NO_PRIV = 1,
    AUTH_PRIV = 2,
    NUMBER_OF_SEC_LEVELS = 3
} SnmpSecurityLevel;

typedef enum {
    SHA_1 = 0,
    SHA_2_224 = 1,
    SHA_2_256 = 2,
    SHA_2_384 = 3,
    SHA_2_512 = 4
} SnmpAuthAlgo;

typedef enum {
    AES_128_CFB = 0,
    AES_192_CFB = 1,
    AES_256_CFB = 2
} SnmpPrivAlgo;

typedef struct {

    /* USM level */
    SnmpSecurityLevel level;

    /* USM securityName */
    char user_name[MAX_USER_NAME_LENGTH];
    size_t user_name_len;

    /* USM authoritative engine ID */
    int auth_engine_id_preshared;
    uint8_t auth_engine_id[MAX_ENGINE_ID_LENGTH];
    size_t auth_engine_id_len;

    /* USM keys */
    SnmpAuthAlgo auth_algo;
    uint8_t auth_key[MAX_HASH_LEN];
    size_t auth_key_len;
    int auth_diversified;
    SnmpPrivAlgo priv_algo;
    uint8_t priv_key[MAX_AES_KEY_LEN];
    size_t priv_key_len;
    int priv_diversified;

    /* request keys */
    uint8_t req_auth_key[MAX_HASH_LEN];
    size_t req_auth_key_len;
    uint8_t req_priv_key[MAX_AES_KEY_LEN];
    size_t req_priv_key_len;

    /* trap keys */
    uint8_t trap_auth_key[MAX_HASH_LEN];
    size_t trap_auth_key_len;
    uint8_t trap_priv_key[MAX_AES_KEY_LEN];
    size_t trap_priv_key_len;

    /* engine parameters */
    uint32_t engine_boots;
    uint32_t engine_time_offset;

    /* anti-replay */
    uint32_t last_rec_boots;
    uint32_t last_rec_time;
    uint32_t last_rec_msg_id;
    uint8_t last_rec_iv[AES_IV_LEN];

} SnmpUSMCtx;

/**
 * init_crypto - initialize the crypto libraries.
 *
 * @return 0 on success or -1 on any error
 */
int init_crypto(void);

/**
 * finish_crypto - finalize the crypto libraries.
 *
 * @return 0 on success or -1 on any error
 */
int finish_crypto(void);

/**
 * get_auth_key_len - Returns the key length required for the
 * given authentication algorithm.
 *
 * @param algo IN - authentication algorithm to be used
 *
 * @return key length.
 */
size_t get_auth_key_len(const SnmpAuthAlgo algo);

/**
 * get_auth_tag_len - Returns the truncated authentication tag length
 * for the given authentication algorithm.
 *
 * @param algo IN - authentication algorithm to be used
 *
 * @return tag length.
 */
size_t get_auth_tag_len(const SnmpAuthAlgo algo);

/**
 * get_priv_key_len - Returns the key length required
 * for the given privacy algorithm.
 *
 * @param algo IN - privacy algorithm to be used
 *
 * @return key length.
 */
size_t get_priv_key_len(const SnmpPrivAlgo algo);

/**
 * derive_usm_master_key - Derive the master key for a given password (RFC 2274).
 *
 * @param pwd IN - password
 * @param algo IN - authentication algorithm to be used
 * @param key_len IN - desired key length
 * @param dst OUT - key output.
 *
 * @return 0 on success, -1 on error.
 */
int derive_usm_master_key(const char *pwd, const SnmpAuthAlgo algo,
        const size_t key_len, uint8_t *dst);

/**
 * diversify_key - Diversify the given key with given engine ID (RFC 3414).
 *
 * @param key IN - source key.
 * @param key_len IN - source key length.
 * @param engine_id IN - engine ID.
 * @param engine_id_len IN -  engine ID length.
 * @param algo IN -  authentication algorithm to be used.
 * @param dst OUT - destination buffer.
 *
 * @return 0 on success, -1 on error.
 */
int diversify_usm_key(const uint8_t *key, const size_t key_len,
        const uint8_t *engine_id, const size_t engine_id_len,
        const SnmpAuthAlgo algo, uint8_t *dst);

/**
 * process_incoming_pdu - authenticates and decrypts an incoming PDU.
 *
 * @param src IN - Incoming PDU before parsing.
 * @param src_len IN - Total length of PDU.
 * @param pdu OUT - destination for decrypted scoped PDU.
 * @param context IN - USM context.
 * @param time_sync IN - if non-zero, PDU is assumed to be time sync request.
 *
 * @return 0 on success, negative number on processing error.
 */
int process_incoming_pdu(uint8_t *src, size_t src_len, SnmpPDU *pdu,
        SnmpUSMCtx *context, int time_sync);

/**
 * process_outgoing_pdu - authenticates, encrypts and marshals an outgoing PDU.
 *
 * @param pdu IN - PDU to be sent out.
 * @param dst OUT - destination buffer for the resulting BER encoded datastream.
 * @param context IN - USM context.
 *
 * @return 0 on success, -1 on error.
 */
int process_outgoing_pdu(SnmpPDU *pdu, buf_t *dst, const SnmpUSMCtx *context);

#endif /* SRC_SNMP_CRYPTO_H_ */
