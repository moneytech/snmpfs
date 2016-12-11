/*
 * This file is part of the snmpfs project (http://snmpfs.x25.pm).
 * snmpfs is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 2 of the license, or any later
 * version.  See LICENSE file for further copyright and license details.
 */

#include "common.h"

#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <stddef.h>

#include "crypto.h"
#include "utils.h"

#define MAX_HEADER_LEN 512

static const EVP_MD *(*hash_algo[])(void) = {
    [SHA_1] = EVP_sha1,
    [SHA_2_224] = EVP_sha224,
    [SHA_2_256] = EVP_sha256,
    [SHA_2_384] = EVP_sha384,
    [SHA_2_512] = EVP_sha512
};

static const size_t hash_tag_len[] = {
    [SHA_1] = 12,
    [SHA_2_224] = 16,
    [SHA_2_256] = 24,
    [SHA_2_384] = 32,
    [SHA_2_512] = 48
};

static const size_t enc_key_len[] = {
    [AES_128_CFB] = 16,
    [AES_192_CFB] = 24,
    [AES_256_CFB] = 32
};

int init_crypto(void)
{
    OPENSSL_config(NULL);
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    return 0;
}

int finish_crypto(void)
{
    CONF_modules_free();
    OBJ_cleanup();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    return 0;
}

size_t get_auth_key_len(const SnmpAuthAlgo algo)
{
    return EVP_MD_size(hash_algo[algo]());
}

size_t get_auth_tag_len(const SnmpAuthAlgo algo)
{
    return hash_tag_len[algo];
}

size_t get_priv_key_len(const SnmpPrivAlgo algo)
{
    return enc_key_len[algo];
}

static int generate_tag(uint8_t *pdu, size_t pdu_len,
        uint8_t *auth_tag, const SnmpUSMCtx *ctx)
{
    memset(auth_tag, 0, hash_tag_len[ctx->auth_algo]);

    int res = -1;
    HMAC_CTX hmac_ctx;
    HMAC_CTX_init(&hmac_ctx);
    if (!HMAC_Init_ex(&hmac_ctx, ctx->auth_key,
        ctx->auth_key_len, hash_algo[ctx->auth_algo](), NULL))
        goto err;
    if (!HMAC_Update(&hmac_ctx, pdu, pdu_len))
        goto err;
    uint8_t tag_buf[EVP_MAX_MD_SIZE];
    if (!HMAC_Final(&hmac_ctx, tag_buf, NULL))
        goto err;
    memcpy(auth_tag, tag_buf, hash_tag_len[ctx->auth_algo]);
    res = 0;
err:
    HMAC_CTX_cleanup(&hmac_ctx);
    return res;
}

static void generate_iv(uint8_t *iv, uint32_t engine_time, uint32_t engine_boots,
        uint8_t *local_iv)
{
    iv[0] = engine_boots >> 24;
    iv[1] = engine_boots >> 16;
    iv[2] = engine_boots >> 8;
    iv[3] = engine_boots;
    iv[4] = engine_time >> 24;
    iv[5] = engine_time >> 16;
    iv[6] = engine_time >> 8;
    iv[7] = engine_time;
    memcpy(&iv[8], local_iv, AES_IV_LEN >> 1);
}

static int check_replay_counter(const SnmpPDU *pdu, SnmpUSMCtx *context)
{
    if (context->engine_boots != pdu->sec_params.auth_engine_boots)
        return -1;

    uint32_t engine_time = context->engine_time_offset;
    if (engine_time < context->last_rec_time)
        context->last_rec_time = 0;

    if (abs(engine_time - pdu->sec_params.auth_engine_time) > 250)
        /* RFC requires 150 sec max, but some clients seem
         * to go out-of-sync too fast that way */
        return -1;
    if (pdu->sec_params.auth_engine_time < context->last_rec_time)
        return -1;
    if (pdu->sec_params.auth_engine_time == context->last_rec_time &&
        pdu->msg_id == context->last_rec_msg_id &&
        !memcmp(context->last_rec_iv, pdu->sec_params.priv_param,
        min(pdu->sec_params.priv_param_len, sizeof(context->last_rec_iv)))) {
        return -1;
    }

    return 0;
}

static int decrypt_scoped_pdu(SnmpPDU *pdu, const SnmpUSMCtx *context)
{
    buf_t buf;
    asn1raw_t raw_tlv;

    if (pdu->is_enc) {
        if (pdu->sec_params.priv_param_len != (AES_IV_LEN >> 1))
            return -1;

        init_ibuf(&buf, pdu->scoped_pdu.enc.data, pdu->scoped_pdu.enc.len);
        if (decode_TLV(&raw_tlv, &buf))
            return -1;
        if (raw_tlv.type != TAG_OCTETSTRING)
            return -1;

        uint8_t iv[AES_IV_LEN];
        generate_iv(iv, pdu->sec_params.auth_engine_time,
                pdu->sec_params.auth_engine_boots,
                pdu->sec_params.priv_param);

        AES_KEY key;
        if (AES_set_encrypt_key(context->priv_key,
                enc_key_len[context->priv_algo] << 3, &key))
            return -1;

        int offset = 0;
        AES_cfb128_encrypt(raw_tlv.value, pdu->scoped_pdu.enc.data,
                raw_tlv.length, &key, iv, &offset, AES_DECRYPT);
        pdu->scoped_pdu.enc.len = raw_tlv.length;
    }

    init_ibuf(&buf, pdu->scoped_pdu.enc.data, pdu->scoped_pdu.enc.len);
    if (decode_TLV(&raw_tlv, &buf))
        return -1;
    if (decode_snmp_scoped_pdu(&raw_tlv, &pdu->scoped_pdu.plain))
        return -1;
    return 0;
}

static int encrypt_scoped_pdu(SnmpPDU *pdu, buf_t *dst, const SnmpUSMCtx *ctx)
{
    pdu->sec_params.auth_engine_boots = ctx->engine_boots;
    pdu->sec_params.auth_engine_time = ctx->engine_time_offset;
    pdu->sec_params.priv_param_len = AES_IV_LEN >> 1;
    if (RAND_bytes(pdu->sec_params.priv_param, AES_IV_LEN >> 1) != 1) {
        syslog(LOG_ERR, "failed to generate iv nonce : %s",
                ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    uint8_t iv[AES_IV_LEN];
    generate_iv(iv, pdu->sec_params.auth_engine_time,
            pdu->sec_params.auth_engine_boots,
            pdu->sec_params.priv_param);

    AES_KEY key;
    if (AES_set_encrypt_key(ctx->priv_key, enc_key_len[ctx->priv_algo] << 3, &key))
        return -1;
    int offset = 0;
    AES_cfb128_encrypt(&dst->buffer[dst->pos], &dst->buffer[dst->pos],
            dst->size - dst->pos, &key, iv, &offset, AES_ENCRYPT);

    return 0;
}

int derive_usm_master_key(const char *pwd, const SnmpAuthAlgo algo,
        const size_t key_len, uint8_t *dst)
{
    size_t pwd_len = strlen(pwd);
    if (pwd_len < 1)
        return -1;

    EVP_MD_CTX *md_ctx;
    if((md_ctx = EVP_MD_CTX_create()) == NULL)
        return -1;
    if(EVP_DigestInit_ex(md_ctx, hash_algo[algo](), NULL) != 1)
        goto err;

    int index = 0;
    int count = 0;
    uint8_t buf[USM_HMAC_BLOCK_SIZE];

    /* process till 1Mb exceeded */
    while (count < 1048576) {
        /* expand password to fill the buffer */
        for (int i = 0; i < USM_HMAC_BLOCK_SIZE; i++)
            buf[i] = pwd[index++ % pwd_len];
        if (EVP_DigestUpdate(md_ctx, buf, USM_HMAC_BLOCK_SIZE) != 1)
            goto err;
        count += USM_HMAC_BLOCK_SIZE;
    }

    unsigned int buf_len;
    if(EVP_DigestFinal_ex(md_ctx, buf, &buf_len) != 1)
        goto err;
    EVP_MD_CTX_destroy(md_ctx);

    memcpy(dst, buf, key_len);
    return 0;
err:
    EVP_MD_CTX_destroy(md_ctx);
    return -1;
}

int diversify_usm_key(const uint8_t *key, const size_t key_len,
        const uint8_t *engine_id, const size_t engine_id_len,
        const SnmpAuthAlgo algo, uint8_t *dst)
{
    EVP_MD_CTX *md_ctx;
    if((md_ctx = EVP_MD_CTX_create()) == NULL)
        return -1;
    if(EVP_DigestInit_ex(md_ctx, hash_algo[algo](), NULL) != 1)
        goto err;
    if (EVP_DigestUpdate(md_ctx, key, key_len) != 1)
        goto err;
    if (EVP_DigestUpdate(md_ctx, engine_id, engine_id_len) != 1)
        goto err;
    if (EVP_DigestUpdate(md_ctx, key, key_len) != 1)
        goto err;

    unsigned int buf_len;
    uint8_t buf[MAX_HASH_LEN];
    if(EVP_DigestFinal_ex(md_ctx, buf, &buf_len) != 1)
        goto err;
    EVP_MD_CTX_destroy(md_ctx);

    memcpy(dst, buf, key_len);
    return 0;
err:
    EVP_MD_CTX_destroy(md_ctx);
    return -1;
}

int process_incoming_pdu(uint8_t *src, size_t src_len, SnmpPDU *pdu,
        SnmpUSMCtx *ctx, int time_sync)
{
    /* validate PDU header */
    if (ctx->level > NO_AUTH_NO_PRIV && !pdu->is_auth)
        return PROCESSING_SECURITY_LEVEL_INVALID;
    if (ctx->level < AUTH_NO_PRIV && pdu->is_auth)
        return PROCESSING_SECURITY_LEVEL_INVALID;
    if (!time_sync) {
        if (ctx->level > AUTH_NO_PRIV && !pdu->is_enc)
            return PROCESSING_SECURITY_LEVEL_INVALID;
        if (ctx->level < AUTH_PRIV && pdu->is_enc)
            return PROCESSING_SECURITY_LEVEL_INVALID;
    }

    if (ctx->level > NO_AUTH_NO_PRIV) {
        /* validate timestamp */
        if (!time_sync && check_replay_counter(pdu, ctx))
            return PROCESSING_SECURITY_TIME_INVALID;

        /* validate tag */
        if (pdu->sec_params.auth_param_len != hash_tag_len[ctx->auth_algo])
            return PROCESSING_SECURITY_AUTH_FAILED;
        if (generate_tag(src, src_len,
            pdu->sec_params.auth_param_offset, ctx)) {
            return PROCESSING_SECURITY_AUTH_FAILED;
        } else {
            uint32_t res = 0;
            for (int i = 0; i < hash_tag_len[ctx->auth_algo]; i++) {
                res |= pdu->sec_params.auth_param[i] ^
                       pdu->sec_params.auth_param_offset[i];
            }
            if ((1 & ((res - 1) >> 8)) - 1) {
                return PROCESSING_SECURITY_AUTH_FAILED;
            }
        }
    }

    /* decrypt scoped PDU */
    if (decrypt_scoped_pdu(pdu, ctx))
        return PROCESSING_SECURITY_ENC_FAILED;

    /* cache authentication values for replay protection */
    ctx->last_rec_msg_id = pdu->msg_id;
    ctx->last_rec_time = pdu->sec_params.auth_engine_time;
    memcpy(ctx->last_rec_iv, pdu->sec_params.priv_param,
        min(pdu->sec_params.priv_param_len, sizeof(ctx->last_rec_iv)));

    return PROCESSING_NO_ERROR;
}

int process_outgoing_pdu(SnmpPDU *pdu, buf_t *dst, const SnmpUSMCtx *ctx)
{
    unsigned int mark = dst->pos;

    if (encode_snmp_scoped_pdu(&pdu->scoped_pdu.plain, dst))
        return -1;

    /* encrypt scoped PDU */
    if (pdu->is_enc) {
        if (encrypt_scoped_pdu(pdu, dst, ctx))
            return -1;
        if (encode_TLV(dst, mark, TAG_OCTETSTRING, FLAG_UNIVERSAL))
            return -1;
    }

    /* put dummy tag */
    if (pdu->is_auth) {
        memset(pdu->sec_params.auth_param, 0, hash_tag_len[ctx->auth_algo]);
        pdu->sec_params.auth_param_len = hash_tag_len[ctx->auth_algo];
    } else {
        pdu->sec_params.auth_param_len = 0;
    }

    if (encode_snmp_pdu(pdu, dst, mark - dst->pos))
        return -1;

    /* apply tag */
    if (pdu->is_auth && generate_tag(&dst->buffer[dst->pos],
        mark - dst->pos, pdu->sec_params.auth_param_offset, ctx))
        return -1;

    return 0;
}
