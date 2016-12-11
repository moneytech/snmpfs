/*
 * This file is part of the snmpfs project (http://snmpfs.x25.pm).
 * snmpfs is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 2 of the license, or any later
 * version.  See LICENSE file for further copyright and license details.
 */

#ifndef SRC_SNMPFS_H_
#define SRC_SNMPFS_H_

#include "common.h"

#include "crypto.h"

#define MAX_ALIAS_LEN   64

typedef struct {

    /* directory name */
    char *alias;

    /* address */
    char *address;
    uint8_t address_resolved[16];
    uint16_t port;
    uint8_t retries;
    uint8_t timeout;

    /* scoped PDU */
    uint8_t version;
    int ctx_preshared;
    uint8_t ctx_engine_id[MAX_ENGINE_ID_LENGTH];
    size_t ctx_engine_id_len;
    uint8_t ctx_name[MAX_CONTEXT_NAME];
    size_t ctx_name_len;

    /* security context */
    SnmpSecurityModel sec_model;
    SnmpUSMCtx usm_ctx;

} AgentCtx;

typedef struct {
    AgentCtx **list;
    size_t len;
} AgentList;

/**
 * init_agent_ctx - Initialize an SNMP agent context.
 *
 * @param ctx OUT - allocated SNMP agent context.
 */
void init_agent_ctx(AgentCtx *ctx);

/**
 * free_agent_ctx - Finalize an SNMP agent context.
 *
 * @param ctx IN - initialized SNMP agent context.
 */
void free_agent_ctx(AgentCtx *ctx);

/**
 * set_debug_logging - enables/disables the debug logging.
 *
 * @param enabled IN - new debug logging state
 */
void set_debug_logging(int enabled);

/**
 * debug_logging_enabled - returns the debug logging state.
 *
 * @return 0 when disabled, 1 when enabled.
 */
int debug_logging_enabled(void);

#endif /* SRC_SNMPFS_H_ */
