/*
 * This file is part of the snmpfs project (http://snmpfs.x25.pm).
 * snmpfs is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 2 of the license, or any later
 * version.  See LICENSE file for further copyright and license details.
 */

#include "common.h"

#include "utils.h"
#include "crypto.h"
#include "snmp-data.h"

static SnmpErrorStatus get_error_status(asn1int_t status)
{
    switch (status) {
        case NO_ERROR:
        case TOO_BIG:
        case NO_SUCH_NAME:
        case BAD_VALUE:
        case READ_ONLY:
        case GENERAL_ERROR:
        case NO_ACCESS:
        case WRONG_TYPE:
        case WRONG_LENGTH:
        case WRONG_ENCODING:
        case WRONG_VALUE:
        case NO_CREATION:
        case INCONSISTENT_VALUE:
        case RESOURCE_UNAVAILABLE:
        case COMMIT_FAILED:
        case UNDO_FAILED:
        case AUTHORIZATION_ERROR:
        case NOT_WRITABLE:
        case INCONSISTENT_NAME: {
            return (SnmpErrorStatus) status;
        }

        default: {
            return -1;
        }
    }
}

static SnmpPduType get_pdu_type(asn1int_t id)
{
    switch (id) {
        case GET:
        case GET_NEXT:
        case RESPONSE:
        case SET:
        case GET_BULK:
        case INFORM:
        case TRAP:
        case REPORT: {
            return (SnmpPduType) id;
        }

        default: {
            return -1;
        }
    }
}

int decode_snmp_pdu(const asn1raw_t *src, SnmpPDU *pdu)
{
    if (src->type != TAG_SEQUENCE)
        return -1;

    buf_t buf;
    asn1raw_t raw_tlv;
    init_ibuf(&buf, src->value, src->length);

    /* check version */
    if (decode_TLV(&raw_tlv, &buf))
        return PARSE_ERROR;
    if (raw_tlv.type != TAG_INTEGER)
        return PARSE_ERROR;
    if (decode_INTEGER(&raw_tlv) != SNMP_VERSION)
        return PARSE_ERROR_VERSION;

    if (decode_TLV(&raw_tlv, &buf))
        return PARSE_ERROR;
    if (raw_tlv.type != TAG_SEQUENCE)
        return PARSE_ERROR;

    buf_t global_data;
    init_ibuf(&global_data, raw_tlv.value, raw_tlv.length);

    /* message ID */
    if (decode_TLV(&raw_tlv, &global_data))
        return PARSE_ERROR;
    if (raw_tlv.type != TAG_INTEGER)
        return PARSE_ERROR;
    pdu->msg_id = decode_INTEGER(&raw_tlv);

    /* max message size */
    if (decode_TLV(&raw_tlv, &global_data))
        return PARSE_ERROR;
    if (raw_tlv.type != TAG_INTEGER)
        return PARSE_ERROR;
    pdu->max_size = decode_INTEGER(&raw_tlv);

    /* message flags */
    if (decode_TLV(&raw_tlv, &global_data))
        return PARSE_ERROR;
    if (raw_tlv.type != TAG_OCTETSTRING)
        return PARSE_ERROR;
    if (raw_tlv.length != 1)
        return PARSE_ERROR;

    pdu->req_response = (raw_tlv.value[0] & 0x04) != 0x00;
    pdu->is_enc = (raw_tlv.value[0] & 0x02) != 0x00;
    pdu->is_auth = (raw_tlv.value[0] & 0x01) != 0x00;
    if (decode_TLV(&raw_tlv, &global_data))
        return PARSE_ERROR;
    if (raw_tlv.type != TAG_INTEGER)
        return PARSE_ERROR;
    if (decode_INTEGER(&raw_tlv) != SNMP_SECURITY_MODEL)
        return PARSE_ERROR_SEC_MODEL;

    /* security parameters */
    if (decode_TLV(&raw_tlv, &buf))
        return PARSE_ERROR;
    if (decode_usm_security_parameters(&raw_tlv, &pdu->sec_params))
        return PARSE_ERROR;

    /* scoped PDU */
    pdu->scoped_pdu.enc.data = &buf.buffer[buf.pos];
    pdu->scoped_pdu.enc.len = buf.size - buf.pos;
    if (decode_TLV(&raw_tlv, &buf))
        return PARSE_ERROR;
    if (buf.pos != buf.size)
        return PARSE_ERROR;

    return PARSE_SUCCESS;
}

int encode_snmp_pdu(SnmpPDU *pdu, buf_t *dst, const int dummy_scoped_pdu)
{
    unsigned int mark = dst->pos;

    /* scoped PDU */
    mark = dst->pos + dummy_scoped_pdu;

    /* security parameters */
    if (encode_usm_security_parameters(&pdu->sec_params, dst))
        return -1;

    /* global message data */
    unsigned global_mark = dst->pos;
    asn1int_t security_model = SNMP_SECURITY_MODEL;
    uint8_t flags = ((pdu->req_response != 0) << 2)
            | ((pdu->is_enc != 0) << 1) | (pdu->is_auth != 0);
    asn1int_t max_size = pdu->max_size;
    asn1int_t msg_id = pdu->msg_id;
    if (encode_INTEGER(dst, &security_model, TAG_INTEGER, FLAG_UNIVERSAL))
        return -1;
    if (encode_OCTET_STRING(dst, &flags, 1))
        return -1;
    if (encode_INTEGER(dst, &max_size, TAG_INTEGER, FLAG_UNIVERSAL))
        return -1;
    if (encode_INTEGER(dst, &msg_id, TAG_INTEGER, FLAG_UNIVERSAL))
        return -1;
    if (encode_TLV(dst, global_mark, TAG_SEQUENCE, FLAG_STRUCTURED))
        return -1;

    /* message version */
    asn1int_t version = SNMP_VERSION;
    if (encode_INTEGER(dst, &version, TAG_INTEGER, FLAG_UNIVERSAL))
        return -1;

    if (encode_TLV(dst, mark, TAG_SEQUENCE, FLAG_STRUCTURED))
        return -1;

    return 0;
}

int decode_usm_security_parameters(const asn1raw_t *src,
        SnmpUSMSecurityParameters *params)
{
    if (src->type != TAG_OCTETSTRING)
        return -1;

    buf_t buf;
    asn1raw_t raw_val;
    init_ibuf(&buf, src->value, src->length);

    if (decode_TLV(&raw_val, &buf))
        return -1;
    if (raw_val.type != TAG_SEQUENCE)
        return -1;

    init_ibuf(&buf, raw_val.value, raw_val.length);

    /* engine ID */
    if (decode_TLV(&raw_val, &buf))
        return -1;
    if (raw_val.type != TAG_OCTETSTRING)
        return -1;
    if (raw_val.length > MAX_ENGINE_ID_LENGTH)
        return -1;
    memcpy(params->auth_engine_id, raw_val.value, raw_val.length);
    params->auth_engine_id_len = raw_val.length;

    /* engine boots */
    if (decode_TLV(&raw_val, &buf))
        return -1;
    if (raw_val.type != TAG_INTEGER)
        return -1;
    params->auth_engine_boots = decode_INTEGER(&raw_val);

    /* engine time */
    if (decode_TLV(&raw_val, &buf))
        return -1;
    if (raw_val.type != TAG_INTEGER)
        return -1;
    params->auth_engine_time = decode_INTEGER(&raw_val);

    /* user name */
    if (decode_TLV(&raw_val, &buf))
        return -1;
    if (raw_val.type != TAG_OCTETSTRING)
        return -1;
    if (raw_val.length >= MAX_USER_NAME_LENGTH)
        return -1;
    memcpy(params->user_name, raw_val.value, raw_val.length);
    params->user_name[raw_val.length] = '\0';

    /* authentication params */
    if (decode_TLV(&raw_val, &buf))
        return -1;
    if (raw_val.type != TAG_OCTETSTRING)
        return -1;
    if (raw_val.length > MAX_AUTHENTICATION_PARAMETERS)
        return -1;
    memcpy(params->auth_param, raw_val.value, raw_val.length);
    params->auth_param_len = raw_val.length;
    params->auth_param_offset = raw_val.value;

    /* privacy params */
    if (decode_TLV(&raw_val, &buf))
        return -1;
    if (raw_val.type != TAG_OCTETSTRING)
        return -1;
    if (raw_val.length > MAX_PRIVACY_PARAMETERS)
        return -1;
    memcpy(params->priv_param, raw_val.value, raw_val.length);
    params->priv_param_len = raw_val.length;
    return 0;
}

int encode_usm_security_parameters(SnmpUSMSecurityParameters *params, buf_t *dst)
{
    unsigned int mark = dst->pos;

    asn1int_t engine_time = params->auth_engine_time;
    asn1int_t engine_boots = params->auth_engine_boots;

    if (encode_OCTET_STRING(dst, params->priv_param, params->priv_param_len))
        return -1;
    params->auth_param_offset = &dst->buffer[dst->pos] - params->auth_param_len;
    if (encode_OCTET_STRING(dst, params->auth_param, params->auth_param_len))
        return -1;
    if (encode_OCTET_STRING(dst, (unsigned char *) params->user_name,
            strnlen((char *) params->user_name, MAX_USER_NAME_LENGTH)))
        return -1;
    if (encode_INTEGER(dst, &engine_time, TAG_INTEGER, FLAG_UNIVERSAL))
        return -1;
    if (encode_INTEGER(dst, &engine_boots, TAG_INTEGER, FLAG_UNIVERSAL))
        return -1;
    if (encode_OCTET_STRING(dst, params->auth_engine_id,
            params->auth_engine_id_len))
        return -1;
    if (encode_TLV(dst, mark, TAG_SEQUENCE, FLAG_STRUCTURED))
        return -1;
    if (encode_TLV(dst, mark, TAG_OCTETSTRING, FLAG_UNIVERSAL))
        return -1;

    return 0;
}

int decode_snmp_scoped_pdu(const asn1raw_t *src, SnmpScopedPDU *pdu)
{
    if (src->type != TAG_SEQUENCE) {
        return -1;
    }

    buf_t buf;
    asn1raw_t raw_tlv;
    init_ibuf(&buf, src->value, src->length);

    /* context engine ID */
    if (decode_TLV(&raw_tlv, &buf))
        return -1;
    if (raw_tlv.type != TAG_OCTETSTRING || raw_tlv.length >= MAX_CONTEXT_ENGINE_ID)
        return -1;
    memcpy(pdu->ctx_engine_id, raw_tlv.value, raw_tlv.length);
    pdu->ctx_engine_id_len = raw_tlv.length;

    /* context name */
    if (decode_TLV(&raw_tlv, &buf))
        return -1;
    if (raw_tlv.type != TAG_OCTETSTRING || raw_tlv.length >= MAX_CONTEXT_NAME)
        return -1;
    memcpy(pdu->ctx_engine_name, raw_tlv.value, raw_tlv.length);
    pdu->ctx_engine_name_len = raw_tlv.length;

    /* PDU type */
    if (decode_TLV(&raw_tlv, &buf))
        return -1;
    if (buf.pos != buf.size)
        return -1;
    if ((pdu->type = get_pdu_type(raw_tlv.type | raw_tlv.flags)) == -1)
        return -1;

    init_ibuf(&buf, raw_tlv.value, raw_tlv.length);

    /* request ID */
    if (decode_TLV(&raw_tlv, &buf))
        return -1;
    if (raw_tlv.type != TAG_INTEGER)
        return -1;
    pdu->req_id = decode_INTEGER(&raw_tlv);

    if (pdu->type == GET_BULK) {
        if (decode_TLV(&raw_tlv, &buf))
            return -1;
        if (raw_tlv.type != TAG_INTEGER)
            return -1;
        pdu->non_rep = decode_INTEGER(&raw_tlv);

        if (decode_TLV(&raw_tlv, &buf))
            return -1;
        if (raw_tlv.type != TAG_INTEGER)
            return -1;
        pdu->max_rep = decode_INTEGER(&raw_tlv);
    } else {
        if (decode_TLV(&raw_tlv, &buf))
            return -1;
        if (raw_tlv.type != TAG_INTEGER)
            return -1;
        if ((pdu->err_status = get_error_status(
                decode_INTEGER(&raw_tlv))) == -1)
            return -1;

        if (decode_TLV(&raw_tlv, &buf))
            return -1;
        if (raw_tlv.type != TAG_INTEGER)
            return -1;
        pdu->err_index = decode_INTEGER(&raw_tlv);
    }

    /* variable bindings */
    if (decode_TLV(&raw_tlv, &buf))
        return -1;
    if (buf.pos != buf.size)
        return -1;

    init_ibuf(&buf, raw_tlv.value, raw_tlv.length);
    pdu->num_of_bindings = 0;

    while (buf.pos < buf.size) {
        if (pdu->num_of_bindings >= MAX_SNMP_VAR_BINDINGS)
            return -1;
        if (decode_TLV(&raw_tlv, &buf))
            return -1;
        if (decode_variable_binding(&raw_tlv,
                &pdu->bindings[pdu->num_of_bindings++]))
            return -1;
    }

    return 0;
}

int encode_snmp_scoped_pdu(const SnmpScopedPDU *pdu, buf_t *dst)
{
    unsigned int mark = dst->pos;

    /* variable bindings */
    for (int i = pdu->num_of_bindings - 1; i >= 0; i--) {
        if (encode_variable_binding(&pdu->bindings[i], dst)) {
            return -1;
        }
    }
    if (encode_TLV(dst, mark, TAG_SEQUENCE, FLAG_STRUCTURED))
        return -1;

    /* error indication */
    asn1int_t error_index = pdu->err_index;
    if (encode_INTEGER(dst, &error_index, TAG_INTEGER, FLAG_UNIVERSAL))
        return -1;

    asn1int_t error_status = pdu->err_status;
    if (encode_INTEGER(dst, &error_status, TAG_INTEGER, FLAG_UNIVERSAL))
        return -1;

    /* response ID */
    asn1int_t response_id = pdu->req_id;
    if (encode_INTEGER(dst, &response_id, TAG_INTEGER, FLAG_UNIVERSAL))
        return -1;
    if (encode_TLV(dst, mark, 0x3f & pdu->type, FLAG_CONTEXT))
        return -1;

    /* context name/id */
    if (encode_OCTET_STRING(dst, pdu->ctx_engine_name, pdu->ctx_engine_name_len))
        return -1;
    if (encode_OCTET_STRING(dst, pdu->ctx_engine_id, pdu->ctx_engine_id_len))
        return -1;
    if (encode_TLV(dst, mark, TAG_SEQUENCE, FLAG_STRUCTURED))
        return -1;

    return 0;
}

SnmpVariableBinding *add_variable_binding(SnmpScopedPDU *pdu)
{
    if (pdu->num_of_bindings >= MAX_SNMP_VAR_BINDINGS)
        return NULL;

    return &pdu->bindings[pdu->num_of_bindings++];
}
