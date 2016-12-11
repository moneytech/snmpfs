/*
 * This file is part of the snmpfs project (http://snmpfs.x25.pm).
 * snmpfs is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 2 of the license, or any later
 * version.  See LICENSE file for further copyright and license details.
 */

#ifndef SRC_CACHE_H_
#define SRC_CACHE_H_

#include "common.h"

#include "snmpfs.h"

/**
 * init_cache - initialize the daemon cache
 *
 * @return returns 0 on success, -1 on failure.
 */
int init_cache(void);

/**
 * finish_cache - finalise the daemon cache
 *
 * @return returns 0 on success, -1 on failure.
 */
int finish_cache(void);

/**
 * get_boot_count - returns the daemon boot counter.
 *
 * @return SNMP boot counter.
 */
uint32_t get_boot_count(void);

/**
 * get_boot_time - returns the uptime of the daemon (in seconds)
 *
 * @return daemon uptime in seconds
 */
uint32_t get_boot_time(void);

/**
 * sync_from_disk - updates the agent list with cached runtime state
 *
 * @return 0 if success, -1 if failed
 */
int sync_cache_from_disk(AgentList *agents);

/**
 * sync_to_disk - writes the current agent runtime configuration to disk
 *
 * @return 0 if success, -1 if failed
 */
int sync_cache_to_disk(AgentList *agents);

#endif /* SRC_CACHE_H_ */
