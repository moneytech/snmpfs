/*
 * This file is part of the snmpfs project (http://snmpfs.x25.pm).
 * snmpfs is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 2 of the license, or any later
 * version.  See LICENSE file for further copyright and license details.
 */

#include "common.h"

#include "config.h"
#include "cache.h"
#include "utils.h"

#define BOOT_CACHE  "/boot.count"
#define AGENT_CACHE  "/agent.cache"

static uint32_t boot_count = 0;
static uint32_t start_time = 0;

int init_cache(void)
{
    start_time = get_uptime();
    if (start_time == -1)
        return -1;

    if (!strcmp(get_cache_dir(), "")) {
        syslog(LOG_INFO, "SNMP caching disabled");
        return 0;
    }

    struct stat dir_stats;
    if (stat(get_cache_dir(), &dir_stats) == 0) {
        if (!S_ISDIR(dir_stats.st_mode)) {
            syslog(LOG_ERR, "cache path is not a directory");
            return -1;
        }
    } else if (errno == ENOENT) {
        if (mkpath(get_cache_dir(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) {
            syslog(LOG_ERR, "failed to initialize cache directory : %s",
                    strerror(errno));
            return -1;
        }
    } else {
        syslog(LOG_ERR, "failed to search cache directory : %s", strerror(errno));
        return -1;
    }

    char *boot_file = strconcat(get_cache_dir(), BOOT_CACHE);
    if (boot_file == NULL)
        return -1;
    FILE *f = fopen(boot_file, "w");
    if (f == NULL) {
        syslog(LOG_ERR, "boot counter could not be updated : %s", strerror(errno));
        free(boot_file);
        return -1;
    }
    fprintf(f, "%"PRIu32"\n", boot_count);
    fflush(f);
    fclose(f);

    char *agent_file = strconcat(get_cache_dir(), AGENT_CACHE);
    if (agent_file == NULL)
        return -1;
    if ((f = fopen(agent_file, "a")) == NULL) {
        syslog(LOG_ERR, "agent cache could not be initialized : %s",
                strerror(errno));
        free(boot_file);
        free(agent_file);
        return -1;
    }
    fclose(f);

    if (get_uid() != 0 || get_gid() != 0) {
        if (chown(get_cache_dir(), get_uid(), get_gid())
                || chown(boot_file, get_uid(), get_gid())
                || chown(agent_file, get_uid(), get_gid())) {
            syslog(LOG_ERR, "failed to set cache permissions : %s",
                    strerror(errno));
            return -1;
        }
    }
    free(boot_file);
    free(agent_file);
    return 0;
}

int finish_cache(void)
{
    return 0;
}

uint32_t get_boot_count(void)
{
    return boot_count;
}

uint32_t get_boot_time(void)
{
    return get_uptime() - start_time;
}

static int skip_agents(char *alias, AgentList *agents, int *i)
{
    while (*i < agents->len) {
        switch (strcmp(agents->list[*i]->alias, alias)) {
            case 0:
                return 0;

            case -1:
                (*i)++;
                break;

            default:
                return -1;
        }
    }

    return -1;
}

/* cache line per agent:
 *
 * alias:trap_engine_id:ctx_engine_id:ctx_name:
 *       auth_engine_id:auth_algo:auth_key:priv_algo:priv_key:
 *       req_auth_key:req_priv_key:trap_auth_key:trap_priv_key:
 *       last_rec_boots:last_rec_time:last_msg_id:last_aes_iv
 */
int sync_cache_from_disk(AgentList *agents)
{
    if (!strcmp(get_cache_dir(), ""))
        return 0;

    char *agent_cache = strconcat(get_cache_dir(), AGENT_CACHE);
    if (agent_cache == NULL)
        return -1;
    FILE *f = fopen(agent_cache, "r");
    if (f == NULL) {
        syslog(LOG_ERR, "failed to open agent cache : %s", strerror(errno));
        free(agent_cache);
        return -1;
    }

    uint8_t *daemon_engine_id;
    size_t daemon_engine_id_len = get_engine_id(&daemon_engine_id);

    for (int i = 0; i < agents->len && !feof(f); i++) {
        char alias[HEX_LEN(MAX_ALIAS_LEN)];
        char ctx_engine_id[HEX_LEN(MAX_ENGINE_ID_LENGTH)];
        char ctx_name[HEX_LEN(MAX_CONTEXT_NAME)];

        uint8_t auth_algo;
        char auth_key[HEX_LEN(MAX_HASH_LEN)];
        uint8_t priv_algo;
        char priv_key[HEX_LEN(MAX_AES_KEY_LEN)];

        char trap_engine_id[HEX_LEN(MAX_ENGINE_ID_LENGTH)];
        char trap_auth_key[HEX_LEN(MAX_HASH_LEN)];
        char trap_priv_key[HEX_LEN(MAX_AES_KEY_LEN)];

        char auth_engine_id[HEX_LEN(MAX_ENGINE_ID_LENGTH)];
        char req_auth_key[HEX_LEN(MAX_HASH_LEN)];
        char req_priv_key[HEX_LEN(MAX_AES_KEY_LEN)];

        uint32_t last_rec_boots;
        uint32_t last_rec_time;
        uint32_t last_msg_id;
        char last_aes_iv[HEX_LEN(AES_IV_LEN)];

        if (fscanf(f, "%130[^:]:%130[^:]:%130[^:]:%130[^:]:%130[^:]:"
                "%c:%130[^:]:%c:%68[^:]:%130[^:]:%68[^:]:%130[^:]:%68[^:]:"
                "%"PRIu32":%"PRIu32":%"PRIu32":%34s\n", alias, trap_engine_id,
                ctx_engine_id, ctx_name, auth_engine_id, &auth_algo,
                auth_key, &priv_algo, priv_key, req_auth_key, req_priv_key,
                trap_auth_key, trap_priv_key, &last_rec_boots, &last_rec_time,
                &last_msg_id, last_aes_iv) != 17) {
            break;
        }
        if (skip_agents(alias, agents, &i)) {
            syslog(LOG_DEBUG, "spurious cache entry %s", alias);
            continue;
        }

        /* restore PDU context */
        if (!agents->list[i]->ctx_preshared) {
            ssize_t len = from_hex(ctx_engine_id,
                agents->list[i]->ctx_engine_id, MAX_ENGINE_ID_LENGTH);
            if (len > 0)
                agents->list[i]->ctx_engine_id_len = len;
            len = from_hex(ctx_name, agents->list[i]->ctx_name, MAX_CONTEXT_NAME);
            if (len > 0)
                agents->list[i]->ctx_name_len = len;
        }

        /* replay state */
        agents->list[i]->usm_ctx.last_rec_boots = last_rec_boots;
        agents->list[i]->usm_ctx.last_rec_time = last_rec_time;
        agents->list[i]->usm_ctx.last_rec_msg_id = last_msg_id;
        from_hex(last_aes_iv, agents->list[i]->usm_ctx.last_rec_iv, AES_IV_LEN);

        /* security context */
        uint8_t buf[max(max(MAX_ENGINE_ID_LENGTH,MAX_HASH_LEN), MAX_AES_KEY_LEN)];
        size_t buf_len;
        int req_keys_oos = 0;
        int trap_keys_oos = 0;
        if (agents->list[i]->usm_ctx.auth_engine_id_preshared) {
            buf_len = from_hex(auth_engine_id, buf, MAX_ENGINE_ID_LENGTH);
            if (buf_len != agents->list[i]->usm_ctx.auth_engine_id_len &&
                memcmp(buf, agents->list[i]->usm_ctx.auth_engine_id, buf_len)) {
                syslog(LOG_INFO, "authoritative engine ID of agent %s has changed; "
                        "discarding previous key data", alias);
                req_keys_oos = 1;
            }
        } else {
            ssize_t len = from_hex(auth_engine_id,
                agents->list[i]->usm_ctx.auth_engine_id, MAX_ENGINE_ID_LENGTH);
            if (len > 0)
                agents->list[i]->usm_ctx.auth_engine_id_len = len;
        }

        buf_len = from_hex(trap_engine_id, buf, MAX_ENGINE_ID_LENGTH);
        if (buf_len != daemon_engine_id_len &&
            memcmp(buf, daemon_engine_id, buf_len)) {
            syslog(LOG_INFO, "authoritative engine ID of daemon has changed; "
                    "discarding previous key data for %s", alias);
            trap_keys_oos = 1;
        }
        if (agents->list[i]->usm_ctx.auth_algo != (auth_algo - '0') ||
                agents->list[i]->usm_ctx.priv_algo != (priv_algo - '0')) {
            syslog(LOG_INFO, "security algorithm for agent %s changed; "
                    "discarding previous key data", alias);
            req_keys_oos = 1;
            trap_keys_oos = 1;
        }

        buf_len = from_hex(auth_key, buf, MAX_HASH_LEN);
        if (buf_len != agents->list[i]->usm_ctx.auth_key_len ||
                memcmp(buf, agents->list[i]->usm_ctx.auth_key, buf_len)) {
            syslog(LOG_INFO, "authentication key of agent %s has changed; "
                    "discarding previous key data", alias);
            req_keys_oos = 1;
            trap_keys_oos = 1;
        }

        buf_len = from_hex(priv_key, buf, MAX_AES_KEY_LEN);
        if (buf_len != agents->list[i]->usm_ctx.priv_key_len ||
                memcmp(buf, agents->list[i]->usm_ctx.priv_key, buf_len)) {
            syslog(LOG_INFO, "privacy key of agent %s has changed; "
                    "discarding previous key data", alias);
            req_keys_oos = 1;
            trap_keys_oos = 1;
        }

        if (!req_keys_oos) {
            buf_len = from_hex(req_auth_key, buf, MAX_HASH_LEN);
            if (buf_len > 0) {
                syslog(LOG_DEBUG,
                    "restoring request authentication key %s for agent %s",
                    req_auth_key, alias);
                memcpy(agents->list[i]->usm_ctx.req_auth_key, buf, buf_len);
                agents->list[i]->usm_ctx.req_auth_key_len = buf_len;
            }

            buf_len = from_hex(req_priv_key, buf, MAX_AES_KEY_LEN);
            if (buf_len > 0) {
                syslog(LOG_DEBUG, "restoring request privacy key %s for agent %s",
                    req_priv_key, alias);
                memcpy(agents->list[i]->usm_ctx.req_priv_key, buf, buf_len);
                agents->list[i]->usm_ctx.req_priv_key_len = buf_len;
            }
        }

        if (!trap_keys_oos) {
            buf_len = from_hex(trap_auth_key, buf, MAX_HASH_LEN);
            if (buf_len > 0) {
                syslog(LOG_DEBUG,
                    "restoring trap authentication key %s for agent %s",
                    trap_auth_key, alias);
                memcpy(agents->list[i]->usm_ctx.trap_auth_key, buf, buf_len);
                agents->list[i]->usm_ctx.trap_auth_key_len = buf_len;
            }

            buf_len = from_hex(trap_priv_key, buf, MAX_AES_KEY_LEN);
            if (buf_len > 0) {
                syslog(LOG_DEBUG, "restoring trap privacy key %s for agent %s",
                    trap_priv_key, alias);
                memcpy(agents->list[i]->usm_ctx.trap_priv_key, buf, buf_len);
                agents->list[i]->usm_ctx.trap_priv_key_len = buf_len;
            }
        }
    }

    fclose(f);
    free(agent_cache);
    return 0;
}

int sync_cache_to_disk(AgentList *agents)
{
    if (!strcmp(get_cache_dir(), ""))
        return 0;
    char *agent_cache = strconcat(get_cache_dir(), AGENT_CACHE);
    if (agent_cache == NULL)
        return -1;
    FILE *f = fopen(agent_cache, "w");
    if (f == NULL) {
        syslog(LOG_ERR, "failed to open agent cache : %s", strerror(errno));
        free(agent_cache);
        return -1;
    }

    uint8_t *engine_id;
    size_t engine_id_len = get_engine_id(&engine_id);

    for (int i = 0; i < agents->len; i++) {
        AgentCtx *agent = agents->list[i];

        char buf[1024];
        size_t offset = 0;
        offset += snprintf(buf + offset, sizeof(buf) - offset, "%s:",
                agent->alias);
        offset += to_hex(engine_id, engine_id_len, buf + offset,
                sizeof(buf) - offset);
        buf[offset - 1] = ':';
        offset += to_hex(agent->ctx_engine_id, agent->ctx_engine_id_len,
                buf + offset, sizeof(buf) - offset);
        buf[offset - 1] = ':';
        offset += to_hex(agent->ctx_name, agent->ctx_name_len, buf + offset,
                sizeof(buf) - offset);
        buf[offset - 1] = ':';
        offset += to_hex(agent->usm_ctx.auth_engine_id,
                agent->usm_ctx.auth_engine_id_len, buf + offset,
                sizeof(buf) - offset);
        buf[offset - 1] = ':';
        buf[offset++] = '0' + agent->usm_ctx.auth_algo;
        buf[offset++] = ':';
        offset += to_hex(agent->usm_ctx.auth_key, agent->usm_ctx.auth_key_len,
                buf + offset, sizeof(buf) - offset);
        buf[offset - 1] = ':';
        buf[offset++] = '0' + agent->usm_ctx.priv_algo;
        buf[offset++] = ':';
        offset += to_hex(agent->usm_ctx.priv_key, agent->usm_ctx.priv_key_len,
                buf + offset, sizeof(buf) - offset);
        buf[offset - 1] = ':';
        offset += to_hex(agent->usm_ctx.req_auth_key,
                agent->usm_ctx.req_auth_key_len, buf + offset,
                sizeof(buf) - offset);
        buf[offset - 1] = ':';
        offset += to_hex(agent->usm_ctx.req_priv_key,
                agent->usm_ctx.req_priv_key_len, buf + offset,
                sizeof(buf) - offset);
        buf[offset - 1] = ':';
        offset += to_hex(agent->usm_ctx.trap_auth_key,
                agent->usm_ctx.trap_auth_key_len, buf + offset,
                sizeof(buf) - offset);
        buf[offset - 1] = ':';
        offset += to_hex(agent->usm_ctx.trap_priv_key,
                agent->usm_ctx.trap_priv_key_len, buf + offset,
                sizeof(buf) - offset);
        buf[offset - 1] = ':';
        offset += snprintf(buf + offset, sizeof(buf) - offset,
                "%"PRIu32":%"PRIu32":%"PRIu32":", agent->usm_ctx.last_rec_boots,
                agent->usm_ctx.last_rec_time, agent->usm_ctx.last_rec_msg_id);
        offset += to_hex(agent->usm_ctx.last_rec_iv,
                sizeof(agent->usm_ctx.last_rec_iv), buf + offset,
                sizeof(buf) - offset);
        buf[offset - 1] = '\n';
        buf[offset] = '\0';
        if (fputs(buf, f) < 0) {
            fclose(f);
            free(agent_cache);
            return -1;
        }
    }

    fclose(f);
    free(agent_cache);
    return 0;
}
