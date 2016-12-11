/*
 * This file is part of the snmpfs project (http://snmpfs.x25.pm).
 * snmpfs is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 2 of the license, or any later
 * version.  See LICENSE file for further copyright and license details.
 */

#ifndef SRC_SNMP_PDU_H_
#define SRC_SNMP_PDU_H_

#include "common.h"

#include "snmp-data.h"

#define SNMP_VERSION 3

#define MAX_CONTEXT_ENGINE_ID   0x40
#define MAX_CONTEXT_NAME 0x40
#define MAX_SNMP_VAR_BINDINGS   0x40

#define MAX_ENGINE_ID_LENGTH          0x40
#define MAX_USER_NAME_LENGTH          0x40
#define MAX_AUTHENTICATION_PARAMETERS 0x40
#define MAX_PRIVACY_PARAMETERS        0x40

#define PARSE_SUCCESS          0
#define PARSE_ERROR           -1
#define PARSE_ERROR_VERSION   -2
#define PARSE_ERROR_SEC_MODEL -3

#define GET_SCOPED_PDU(pdu) (&(pdu).scoped_pdu.decrypted)

#define NEW_VAR_BINDING(x,y) \
	SnmpVariableBinding *x = add_variable_binding(y); \
	if (x == NULL) { \
        syslog(LOG_WARNING, "PDU building error: no variable binding slots left"); \
        return -1; \
	}

/* SNMP PDU types */
typedef enum {
    GET = 0xA0,
    GET_NEXT = 0xA1,
    RESPONSE = 0xA2,
    SET = 0xA3,
    GET_BULK = 0xA5,
    INFORM = 0xA6,
    TRAP = 0xA7,
    REPORT = 0xA8
} SnmpPduType;

/* SNMP error status */
typedef enum {

    /* The agent reports that no errors occurred during transmission. */
    NO_ERROR = 0,

    /* The agent could not place the results of the requested SNMP
     * operation in a single SNMP message. */
    TOO_BIG = 1,

    /* The requested SNMP operation identified an unknown variable. */
    NO_SUCH_NAME = 2,

    /* The requested SNMP operation tried to change a variable
     * but it specified either a syntax or value error. */
    BAD_VALUE = 3,

    /* The requested SNMP operation tried to change a variable
     * that was not allowed to change, according to the community
     * profile of the variable. */
    READ_ONLY = 4,

    /* An error other than one of those listed here occurred
     * during the requested SNMP operation. */
    GENERAL_ERROR = 5,

    /* The specified SNMP variable is not accessible. */
    NO_ACCESS = 6,

    /* The value specifies a type that is inconsistent
     * with the type required for the variable. */
    WRONG_TYPE = 7,

    /* The value specifies a length that is inconsistent
     * with the length required for the variable. */
    WRONG_LENGTH = 8,

    /* The value contains an ASN.1 encoding that is inconsistent
     * with the ASN.1 tag of the field. */
    WRONG_ENCODING = 9,

    /* The value cannot be assigned to the variable. */
    WRONG_VALUE = 10,

    /* The variable does not exist, and the agent cannot create it. */
    NO_CREATION = 11,

    /* The value is inconsistent with values of other managed objects. */
    INCONSISTENT_VALUE = 12,

    /* Assigning the value to the variable requires allocation
     * of resources that are currently unavailable. */
    RESOURCE_UNAVAILABLE = 13,

    /* No validation errors occurred, but no variables were updated. */
    COMMIT_FAILED = 14,

    /* No validation errors occurred. Some variables were updated
     * because it was not possible to undo their assignment. */
    UNDO_FAILED = 15,

    /* An authorization error occurred. */
    AUTHORIZATION_ERROR = 16,

    /* The variable exists but the agent cannot modify it. */
    NOT_WRITABLE = 17,

    /* The variable does not exist; the agent cannot create it
     * because the named object instance is inconsistent with
     * the values of other managed objects. */
    INCONSISTENT_NAME = 18

} SnmpErrorStatus;

/* USM security parameter block, included in SNMP PDU header */
typedef struct {

    /* authoritative engine ID */
    uint8_t auth_engine_id[MAX_ENGINE_ID_LENGTH];
    size_t auth_engine_id_len;

    /* authoritative engine boot counter and time */
    uint32_t auth_engine_boots;
    uint32_t auth_engine_time;

    /* securityName */
    char user_name[MAX_USER_NAME_LENGTH];

    /* authentication parameters (digest) */
    uint8_t auth_param[MAX_AUTHENTICATION_PARAMETERS];
    size_t auth_param_len;
    uint8_t *auth_param_offset;

    /* privacy parameters (salt) */
    uint8_t priv_param[MAX_PRIVACY_PARAMETERS];
    size_t priv_param_len;

} SnmpUSMSecurityParameters;

/* Scoped PDU */
typedef struct {

    /* context engine identifier */
    uint8_t ctx_engine_id[MAX_CONTEXT_ENGINE_ID];
    size_t ctx_engine_id_len;

    /* context engine name */
    uint8_t ctx_engine_name[MAX_CONTEXT_NAME];
    size_t ctx_engine_name_len;

    /* request identifier */
    uint32_t req_id;

    /* request type */
    SnmpPduType type;

    /* for non-bulk requests only */
    SnmpErrorStatus err_status;
    uint32_t err_index;

    /* for bulk requests only */
    uint32_t non_rep;
    uint32_t max_rep;

    /* variable bindings */
    SnmpVariableBinding bindings[MAX_SNMP_VAR_BINDINGS];
    size_t num_of_bindings;

} SnmpScopedPDU;

/* SNMP message */
typedef struct {

    /* Message identifier */
    uint32_t msg_id;

    /* Maximum message size (including header) */
    uint32_t max_size;

    /* Scoped PDU is encrypted */
    uint8_t is_enc;

    /* Scoped PDU is authenticated */
    uint8_t is_auth;

    /* Message requires response */
    uint8_t req_response;

    /* Security parameter block */
    SnmpUSMSecurityParameters sec_params;

    /* Scoped PDU */
    union {
        struct {
            uint8_t *data;
            size_t len;
        } enc;
        SnmpScopedPDU plain;
    } scoped_pdu;

} SnmpPDU;

/**
 * decode_snmp_pdu - Extracts an SNMP PDU from a given BER encoded TLV.
 *
 * @param src IN - TLV containing SNMP PDU.
 * @param pdu OUT - destination pdu struct
 *
 * @return 0 on success, negative number on error (see PARSE_* defines)
 * @note scoped PDU is not decrypted or parsed by this function.
 */
int decode_snmp_pdu(const asn1raw_t *src, SnmpPDU *pdu);

/**
 * encode_snmp_pdu - Encodes an SNMP pdu into a BER TLV.
 *
 * @param pdu IN - PDU to be encoded.
 * @param dst OUT - destination output.
 * @param dummy_scoped_pdu IN - if non-zero, skip the scoped PDU
 * 		and assume scoped PDU size as given.
 *
 * @return 0 on success, -1 on error.
 * @note scoped PDU is expected already encrypted
 */
int encode_snmp_pdu(SnmpPDU *pdu, buf_t *dst, const int dummy_scoped_pdu);

/**
 * decode_usm_security_parameters - Extracts USM security parameters
 * from given BER encoded TLV.
 *
 * @param src IN - TLV containing USM security parameters.
 * @param params OUT - destination parameter block
 *
 * @return 0 on success, -1 on parse error.
 */
int decode_usm_security_parameters(const asn1raw_t *src, SnmpUSMSecurityParameters *params);

/**
 * encode_usm_security_parameters - Encodes the USM security parameters to a BER TLV.
 *
 * @param params IN/OUT - USM parameter block to be encoded.
 * @param dst OUT - destination output.
 *
 * @return 0 on success, -1 on encoding error.
 */
int encode_usm_security_parameters(SnmpUSMSecurityParameters *params, buf_t *dst);

/**
 * decode_snmp_scoped_pdu - Extracts a scoped SNMP PDU from a
 * given BER encoded TLV.
 *
 * @param src IN - TLV containing scoped PDU.
 * @param pdu OUT - destination scoped pdu struct
 *
 * @return 0 on success, -1 on parse error
 */
int decode_snmp_scoped_pdu(const asn1raw_t *src, SnmpScopedPDU *pdu);

/**
 * encode_snmp_scoped_pdu - Encodes a scoped SNMP pdu into a BER TLV.
 *
 * @param pdu IN - Scoped PDU to be encoded.
 * @param dst OUT - destination output.
 *
 * @return 0 on success, -1 on encoding error.
 */
int encode_snmp_scoped_pdu(const SnmpScopedPDU *pdu, buf_t *dst);

/**
 * add_variable_binding - Adds a new variable binding to a scoped PDU.
 *
 * @param pdu IN/OUT - Scoped PDU.
 *
 * @return reference to the new variable binding, NULL on error.
 */
SnmpVariableBinding *add_variable_binding(SnmpScopedPDU *pdu);

#endif /* SRC_SNMP_PDU_H_ */
