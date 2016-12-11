/*
 * This file is part of the snmpfs project (http://snmpfs.x25.pm).
 * snmpfs is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 2 of the license, or any later
 * version.  See LICENSE file for further copyright and license details.
 */

#include "common.h"

#include <pwd.h>
#include <grp.h>
#include <libconfig.h>

#include "config.h"
#include "crypto.h"
#include "utils.h"

#define KEY_DAEMON  "daemon"
#define KEY_UID "uid"
#define KEY_GID "gid"
#define KEY_TRAP_PORT   "trap-port"
#define KEY_ENGINE_ID   "engine-id"
#define KEY_MOUNT_DIR   "mount-dir"
#define KEY_CACHE_DIR   "cache-dir"
#define KEY_MIB_DIR "mib-dir"

#define KEY_AGENTS  "agents"
#define KEY_ALIAS   "alias"
#define KEY_ADDRESS    "address"
#define KEY_PORT    "port"
#define KEY_RETRIES    "retries"
#define KEY_TIMEOUT    "timeout"
#define KEY_VERSION    "version"
#define KEY_CONTEXT_ENGINE_ID    "context-engine-id"
#define KEY_CONTEXT_NAME    "context-name"
#define KEY_SECURITY    "security"
#define KEY_SEC_MODEL    "model"
#define KEY_SEC_LEVEL    "level"
#define KEY_SEC_NAME    "name"
#define KEY_SEC_ENGINE_ID    "engine-id"
#define KEY_SEC_AUTH_ALGO    "auth-algo"
#define KEY_SEC_PRIV_ALGO    "priv-algo"
#define KEY_SEC_AUTH_PASSWORD    "auth-password"
#define KEY_SEC_PRIV_PASSWORD    "priv-password"
#define KEY_SEC_AUTH_KEY    "auth-key"
#define KEY_SEC_PRIV_KEY    "priv-key"

#define MAX_ENGINE_ID   0x40

static int reload_daemon_config(const config_setting_t *);
static int reload_agent_config(const config_setting_t *, AgentList *);
static int reload_dir(const config_setting_t *, const char *, char **, char *);
static int set_default_engine_id(void);
static int load_agent_config(config_setting_t *, AgentCtx *);
static int load_agent_sec_config(const config_setting_t *, AgentCtx *);
static int load_agent_sec_keys(const config_setting_t *, char *, char *,
        const SnmpAuthAlgo, size_t, uint8_t *, size_t *, int *);
static int load_agent_sec_div_keys(AgentCtx *);
static void dump_keys(const char *, const char *, const uint8_t *,
        const size_t, const uint8_t *, const size_t);
static int compare_agents(const void *, const void *);
static void copy_runtime_settings(const AgentCtx *, AgentCtx *);
static SnmpSecurityLevel get_sec_level_from_string(const char *);
static SnmpAuthAlgo get_auth_algo_from_string(const char *);
static SnmpPrivAlgo get_priv_algo_from_string(const char *);
static char *creat_alias(const char *);

static char *default_mount_dir = MOUNT_DIR;
static char *default_cache_dir = CACHE_DIR;
static char *default_mib_dir = MIB_DIR;

/* runtime configuration */
static const char *config_file = CONFIG_FILE;
static int uid = 0;
static int gid = 0;
static char *mount_dir = NULL;
static char *cache_dir = NULL;
static char *mib_dir = NULL;
static uint16_t trap_port = TRAP_PORT;
static uint8_t engine_id[MAX_ENGINE_ID];
static size_t engine_id_len = 0;

void set_config_file(const char *path)
{
    config_file = path;
}

int get_uid(void)
{
    return uid;
}

int get_gid(void)
{
    return gid;
}

char *get_mount_dir(void)
{
    return mount_dir;
}

char *get_cache_dir(void)
{
    return cache_dir;
}

char *get_mib_dir(void)
{
    return mib_dir;
}

uint16_t get_trap_port(void)
{
    return trap_port;
}

size_t get_engine_id(uint8_t **dst)
{
    *dst = engine_id;
    return engine_id_len;
}

int reload_config(AgentList *agents)
{
    int ret_val = 0;

    config_t cfg;
    config_init(&cfg);

    if (access(config_file, F_OK) == -1) {
        syslog(LOG_ERR, "configuration missing or not accessible");
        ret_val = -1;
        goto finish;
    }

    if (!config_read_file(&cfg, config_file)) {
        syslog(LOG_ERR, "failed to parse configuration %s:%d - %s",
                config_error_file(&cfg), config_error_line(&cfg),
                config_error_text(&cfg));
        ret_val = -1;
        goto finish;
    }

    config_setting_t *daemon_cfg = config_lookup(&cfg, KEY_DAEMON);
    if (daemon_cfg == NULL) {
        syslog(LOG_WARNING,
                "no daemon configuration specified;  using defaults");
    } else if (reload_daemon_config(daemon_cfg)) {
        syslog(LOG_ERR, "invalid daemon configuration");
        ret_val = -1;
        goto finish;
    }

    config_setting_t *agent_cfg = config_lookup(&cfg, KEY_AGENTS);
    if (agent_cfg == NULL) {
        syslog(LOG_WARNING, "no agents configured");
    } else if (reload_agent_config(agent_cfg, agents)) {
        syslog(LOG_ERR, "invalid agent configuration");
        ret_val = -1;
        goto finish;
    }

    finish: config_destroy(&cfg);
    return ret_val;
}

static int reload_daemon_config(const config_setting_t *daemon_cfg)
{
    const char *str;

    /* fetch uid */
    if (config_setting_lookup_string(daemon_cfg, KEY_UID, &str) == CONFIG_TRUE) {
        struct passwd *user = getpwnam(str);
        if (user == NULL) {
            syslog(LOG_ERR, "failed to find uid for user %s", str);
            return -1;
        } else {
            uid = user->pw_uid;
        }
    } else {
        config_setting_lookup_int(daemon_cfg, KEY_UID, (int *) &uid);
    }

    /* fetch gid */
    if (config_setting_lookup_string(daemon_cfg, KEY_GID, &str) == CONFIG_TRUE) {
        struct group *grp = getgrnam(str);
        if (grp == NULL) {
            syslog(LOG_ERR, "failed to find gid for group %s", str);
            return -1;
        } else {
            gid = grp->gr_gid;
        }
    } else {
        config_setting_lookup_int(daemon_cfg, KEY_GID, (int *) &gid);
    }

    /* fetch cache dir */
    if (reload_dir(daemon_cfg, KEY_CACHE_DIR, &cache_dir, default_cache_dir)) {
        syslog(LOG_ERR, "invalid cache directory");
        return -1;
    }

    /* fetch mib dir */
    if (reload_dir(daemon_cfg, KEY_MIB_DIR, &mib_dir, default_mib_dir)) {
        syslog(LOG_ERR, "invalid MIB directory");
        return -1;
    }

    /* fetch mount dir */
    if (reload_dir(daemon_cfg, KEY_MOUNT_DIR, &mount_dir, default_mount_dir)) {
        syslog(LOG_ERR, "invalid mount directory");
        return -1;
    }

    /* fetch trap port */
    int port_override;
    if (config_setting_lookup_int(daemon_cfg, KEY_TRAP_PORT,
            &port_override) == CONFIG_TRUE) {
        trap_port = (uint16_t) port_override;
    }

    /* fetch engine ID */
    if (config_setting_lookup_string(daemon_cfg, KEY_ENGINE_ID,
            &str) == CONFIG_TRUE) {
        engine_id_len = from_hex(str, engine_id, sizeof(engine_id));
        if (engine_id_len == -1) {
            syslog(LOG_ERR, "failed to parse engine id %s", str);
            return -1;
        }
    } else if (set_default_engine_id()) {
        return -1;
    }

    return 0;
}

static int reload_dir(const config_setting_t *cfg, const char *key, char **dst,
        char *default_val)
{
    if (*dst != default_val)
        free(*dst);

    const char *str;
    if (config_setting_lookup_string(cfg, key, &str) == CONFIG_TRUE) {
        *dst = strdup(str);
        struct stat cache_stat;
        if (*dst == NULL || stat(str, &cache_stat) != 0||
        !S_ISDIR(cache_stat.st_mode)) {
            free(*dst);
            return -1;
        }
    } else {
        *dst = default_val;
    }

    return 0;
}

static int set_default_engine_id(void)
{
    engine_id[0] = ((ENTERPRISE_NUMBER >> 24) & 0xff) | 0x80;
    engine_id[1] = (ENTERPRISE_NUMBER >> 16) & 0xff;
    engine_id[2] = (ENTERPRISE_NUMBER >> 8) & 0xff;
    engine_id[3] = ENTERPRISE_NUMBER & 0xff;
    engine_id[4] = 0x04;

    if (gethostname((char *) &engine_id[5], sizeof(engine_id) - 5)) {
        syslog(LOG_ERR, "failed to retrieve host name : %s", strerror(errno));
        return -1;
    }

    engine_id_len = 5 + strnlen((char *) &engine_id[5], sizeof(engine_id) - 5);
    return 0;
}

static int reload_agent_config(const config_setting_t *cfg, AgentList *dst)
{
    size_t count = config_setting_length(cfg);
    AgentCtx **agents = malloc(count * sizeof(AgentCtx *));
    if (agents == NULL)
        return -1;

    int i = 0;
    for (int i = 0; i < count; i++) {
        config_setting_t *agent = config_setting_get_elem(cfg, i);
        agents[i] = malloc(sizeof(AgentCtx));
        if (agents[i] == NULL)
            goto err;
        init_agent_ctx(agents[i]);
        if (load_agent_config(agent, agents[i]))
            goto err;
        syslog(LOG_INFO, "loaded configuration for SNMP agent %s",
                agents[i]->alias);
    }

    qsort(agents, count, sizeof(AgentCtx *), compare_agents);

    for (int j = 1; j < count; j++) {
        if (!strcmp(agents[j - 1]->alias, agents[j]->alias)) {
            syslog(LOG_ERR, "duplicate agent entry %s", agents[j]->alias);
            goto err;
        }
    }

    int j = 0;
    for (int k = 0; k < dst->len; k++) {
        AgentCtx *prev = dst->list[k];

        while (j < count) {
            if (!strcmp(agents[j]->alias, prev->alias))
                copy_runtime_settings(prev, agents[j]);
            j++;
        }
        free_agent_ctx(prev);
    }

    free(dst->list);
    dst->list = agents;
    dst->len = count;
    return 0;

err:
    for (int j = 0; j <= i; j++)
        free_agent_ctx(agents[j]);
    free(agents);
    return -1;
}

static int load_agent_config(config_setting_t *cfg, AgentCtx *dst)
{
    const char *str;
    if (config_setting_lookup_string(cfg, KEY_ADDRESS, &str) == CONFIG_FALSE) {
        syslog(LOG_ERR, "address missing in agent configuration");
        return -1;
    }
    dst->address = strdup(str);

    int port;
    if (config_setting_lookup_int(cfg, KEY_PORT, &port) == CONFIG_TRUE)
        dst->port = port;

    int retries;
    if (config_setting_lookup_int(cfg, KEY_RETRIES, &retries) == CONFIG_TRUE)
        dst->retries = retries;

    int timeout;
    if (config_setting_lookup_int(cfg, KEY_TIMEOUT, &timeout) == CONFIG_TRUE)
        dst->timeout = timeout;

    if (config_setting_lookup_string(cfg, KEY_ALIAS, &str) == CONFIG_TRUE) {
        dst->alias = creat_alias(str);
    } else {
        dst->alias = creat_alias(dst->address);
    }
    if (dst->alias == NULL)
        return -1;

    int version;
    if (config_setting_lookup_int(cfg, KEY_VERSION, &version) == CONFIG_TRUE
            && version != SNMP_VERSION) {
        syslog(LOG_ERR, "unsupported version %i", version);
        return -1;
    }

    if (config_setting_lookup_string(cfg, KEY_CONTEXT_ENGINE_ID,
            &str) == CONFIG_TRUE) {
        dst->ctx_preshared = 1;
        int size = from_hex(str, dst->ctx_engine_id,
                sizeof(dst->ctx_engine_id));
        if (size < 0) {
            syslog(LOG_ERR, "context engine ID too long");
            return -1;
        }
        dst->ctx_engine_id_len = size;

        if (config_setting_lookup_string(cfg, KEY_CONTEXT_NAME,
                &str) == CONFIG_TRUE) {
            size_t ctx_name_len = strlen(str);
            if (ctx_name_len < 2 || str[0] != '0' || str[1] != 'x') {
                if (ctx_name_len > 63) {
                    syslog(LOG_ERR, "context name too long");
                    return -1;
                }
                dst->ctx_name_len = ctx_name_len;
                memcpy(dst->ctx_name, str, ctx_name_len);
            } else {
                size = from_hex(str, dst->ctx_name, sizeof(dst->ctx_name));
                if (size < 0) {
                    syslog(LOG_ERR, "context name too long");
                    return -1;
                }
                dst->ctx_name_len = size;
            }
        }
    }

    if (config_setting_lookup_string(cfg, KEY_SEC_MODEL, &str) == CONFIG_TRUE
            && lenient_strcmp(str, "USM")) {
        syslog(LOG_ERR, "no support for security model %s", str);
        return -1;
    }

    const config_setting_t *sec_cfg = config_setting_lookup(cfg, KEY_SECURITY);
    if (sec_cfg == NULL) {
        syslog(LOG_WARNING, "no security configuration found for agent %s",
            dst->alias);
    } else if (load_agent_sec_config(sec_cfg, dst)) {
        return -1;
    }

    return 0;
}

static int load_agent_sec_config(const config_setting_t *cfg, AgentCtx *dst)
{
    const char *str;
    if (config_setting_lookup_string(cfg, KEY_SEC_NAME, &str) == CONFIG_TRUE) {
        if (strlen(str) > MAX_USER_NAME_LENGTH) {
            syslog(LOG_ERR, "user name too long: %s", str);
            return -1;
        }
        strcpy(dst->usm_ctx.user_name, str);
        dst->usm_ctx.user_name_len = strlen(str);
    } else {
        syslog(LOG_WARNING, "no user name specified for agent %s", dst->alias);
    }

    if (config_setting_lookup_string(cfg, KEY_SEC_ENGINE_ID,
            &str) == CONFIG_TRUE) {
        dst->usm_ctx.auth_engine_id_preshared = 1;
        int size = from_hex(str, dst->usm_ctx.auth_engine_id,
                sizeof(dst->usm_ctx.auth_engine_id));
        if (size < 0) {
            syslog(LOG_ERR, "security context engine ID too long");
            return -1;
        }
        dst->usm_ctx.auth_engine_id_len = size;
    }

    if (config_setting_lookup_string(cfg, KEY_SEC_LEVEL, &str) == CONFIG_TRUE) {
        int level = get_sec_level_from_string(str);
        if (level == -1) {
            syslog(LOG_ERR, "invalid security level %s", str);
            return -1;
        }
        dst->usm_ctx.level = level;
    } else {
        syslog(LOG_WARNING,
                "security level for agent %s set too lowest;  consider increasing",
                dst->alias);
    }

    if (config_setting_lookup_string(cfg, KEY_SEC_AUTH_ALGO,
            &str) == CONFIG_TRUE) {
        int algo = get_auth_algo_from_string(str);
        if (algo == -1) {
            syslog(LOG_ERR, "invalid authentication algorithm %s", str);
            return -1;
        }
        dst->usm_ctx.auth_algo = algo;
    } else {
        syslog(LOG_DEBUG,
                "using default authentication algorithm (HMAC-SHA-256)");
    }

    if (config_setting_lookup_string(cfg, KEY_SEC_PRIV_ALGO,
            &str) == CONFIG_TRUE) {
        int algo = get_priv_algo_from_string(str);
        if (algo == -1) {
            syslog(LOG_ERR, "invalid privacy algorithm %s", str);
            return -1;
        }
        dst->usm_ctx.priv_algo = algo;
    } else {
        syslog(LOG_DEBUG, "using default privacy algorithm (AES-256)");
    }

    if (load_agent_sec_keys(cfg, KEY_SEC_AUTH_PASSWORD, KEY_SEC_AUTH_KEY,
            dst->usm_ctx.auth_algo, get_auth_key_len(dst->usm_ctx.auth_algo),
            dst->usm_ctx.auth_key, &dst->usm_ctx.auth_key_len,
            &dst->usm_ctx.auth_diversified)) {
        syslog(LOG_ERR, "failed to load authentication key for agent %s",
                dst->alias);
        return -1;
    }

    if (load_agent_sec_keys(cfg, KEY_SEC_PRIV_PASSWORD, KEY_SEC_PRIV_KEY,
            dst->usm_ctx.auth_algo, get_priv_key_len(dst->usm_ctx.priv_algo),
            dst->usm_ctx.priv_key, &dst->usm_ctx.priv_key_len,
            &dst->usm_ctx.priv_diversified)) {
        syslog(LOG_ERR, "failed to load privacy key for agent %s", dst->alias);
        return -1;
    }

    if (dst->usm_ctx.auth_algo > 0 && dst->usm_ctx.auth_key_len == 0) {
        syslog(LOG_ERR, "missing authentication key for agent %s", dst->alias);
        return -1;
    }

    if (dst->usm_ctx.priv_algo > 0 && dst->usm_ctx.priv_key_len == 0) {
        syslog(LOG_ERR, "missing privacy key for agent %s", dst->alias);
        return -1;
    }

    if (load_agent_sec_div_keys(dst)) {
        syslog(LOG_ERR, "failed to diversify keys for agent %s", dst->alias);
        return -1;
    }

    return 0;
}

static int load_agent_sec_keys(const config_setting_t *cfg, char *pwd_key,
        char *key_key, const SnmpAuthAlgo algo, size_t key_len, uint8_t *dst,
        size_t *dst_len, int *div_indicator)
{
    const char *str;
    if (config_setting_lookup_string(cfg, key_key, &str) == CONFIG_TRUE) {
        ssize_t size = from_hex(str, dst, key_len);
        if (size != key_len) {
            syslog(LOG_ERR, "preshared key has invalid length");
            return -1;
        }
        *dst_len = key_len;
        *div_indicator = 1;
    } else if (config_setting_lookup_string(cfg, pwd_key, &str) == CONFIG_TRUE) {
        if (derive_usm_master_key(str, algo, key_len, dst)) {
            syslog(LOG_ERR, "failed to derive master key from password");
            return -1;
        }
        *dst_len = key_len;
    }

    return 0;
}

static int load_agent_sec_div_keys(AgentCtx *ctx)
{
    SnmpUSMCtx *usm_ctx = &ctx->usm_ctx;

    if (usm_ctx->auth_diversified) {
        memcpy(usm_ctx->req_auth_key, usm_ctx->auth_key, usm_ctx->auth_key_len);
        memcpy(usm_ctx->trap_auth_key, usm_ctx->auth_key, usm_ctx->auth_key_len);
        usm_ctx->req_auth_key_len = usm_ctx->auth_key_len;
        usm_ctx->trap_auth_key_len = usm_ctx->auth_key_len;
    } else {
        if (usm_ctx->auth_engine_id_preshared) {
            if (diversify_usm_key(usm_ctx->auth_key, usm_ctx->auth_key_len,
                    usm_ctx->auth_engine_id, usm_ctx->auth_engine_id_len,
                    usm_ctx->auth_algo, usm_ctx->req_auth_key))
                return -1;
            usm_ctx->req_auth_key_len = usm_ctx->auth_key_len;
        }

        if (diversify_usm_key(usm_ctx->auth_key, usm_ctx->auth_key_len,
                usm_ctx->auth_engine_id, usm_ctx->auth_engine_id_len,
                usm_ctx->auth_algo, usm_ctx->trap_auth_key))
            return -1;
        usm_ctx->trap_auth_key_len = usm_ctx->auth_key_len;
    }

    if (usm_ctx->priv_diversified) {
        memcpy(usm_ctx->req_priv_key, usm_ctx->priv_key, usm_ctx->priv_key_len);
        memcpy(usm_ctx->trap_priv_key, usm_ctx->priv_key, usm_ctx->priv_key_len);
        usm_ctx->req_priv_key_len = usm_ctx->priv_key_len;
        usm_ctx->trap_priv_key_len = usm_ctx->priv_key_len;
    } else {
        if (usm_ctx->auth_engine_id_preshared) {
            if (diversify_usm_key(usm_ctx->priv_key, usm_ctx->priv_key_len,
                    usm_ctx->auth_engine_id, usm_ctx->auth_engine_id_len,
                    usm_ctx->auth_algo, usm_ctx->req_priv_key))
                return -1;
            usm_ctx->req_auth_key_len = usm_ctx->auth_key_len;
        }

        if (diversify_usm_key(usm_ctx->priv_key, usm_ctx->priv_key_len,
                usm_ctx->auth_engine_id, usm_ctx->auth_engine_id_len,
                usm_ctx->auth_algo, usm_ctx->trap_priv_key))
            return -1;
        usm_ctx->trap_priv_key_len = usm_ctx->priv_key_len;
    }

    if (debug_logging_enabled()) {
        dump_keys(ctx->alias, "request", usm_ctx->req_auth_key,
            usm_ctx->req_auth_key_len, usm_ctx->req_priv_key,
            usm_ctx->req_priv_key_len);
        dump_keys(ctx->alias, "trap", usm_ctx->trap_auth_key,
            usm_ctx->trap_auth_key_len, usm_ctx->trap_priv_key,
            usm_ctx->trap_priv_key_len);
    }

    return 0;
}

static void dump_keys(const char *alias, const char *prefix, const uint8_t *auth_key,
    const size_t auth_key_len, const uint8_t *priv_key, const size_t priv_key_len)
{
    if (auth_key_len < 1 || priv_key_len < 1)
        return;

    char auth_dump[HEX_LEN(auth_key_len)];
    char priv_dump[HEX_LEN(priv_key_len)];
    to_hex(auth_key, auth_key_len, auth_dump, sizeof(auth_dump));
    to_hex(priv_key, priv_key_len, priv_dump, sizeof(priv_dump));
    syslog(LOG_DEBUG, "%s key for %s : authentication %s, encryption %s",
            prefix, alias, auth_dump, priv_dump);
}

static int compare_agents(const void *a, const void *b)
{
    AgentCtx *agent1 = *(AgentCtx **) a;
    AgentCtx *agent2 = *(AgentCtx **) b;
    return strcmp(agent1->alias, agent2->alias);
}

static void copy_runtime_settings(const AgentCtx *from, AgentCtx *to)
{
    memcpy(to->address_resolved, from->address_resolved,
            sizeof(to->address_resolved));

    if (!to->ctx_preshared) {
        memcpy(to->ctx_engine_id, from->ctx_engine_id, from->ctx_engine_id_len);
        memcpy(to->ctx_name, from->ctx_name, from->ctx_name_len);
        to->ctx_engine_id_len = from->ctx_engine_id_len;
        to->ctx_name_len = from->ctx_name_len;
    }

    if (!to->usm_ctx.auth_engine_id_preshared) {
        memcpy(to->usm_ctx.auth_engine_id, from->usm_ctx.auth_engine_id,
                from->usm_ctx.auth_engine_id_len);
        memcpy(to->usm_ctx.req_auth_key, from->usm_ctx.req_auth_key,
                from->usm_ctx.req_auth_key_len);
        memcpy(to->usm_ctx.req_priv_key, from->usm_ctx.req_priv_key,
                from->usm_ctx.req_priv_key_len);
        to->usm_ctx.auth_engine_id_len = from->usm_ctx.auth_engine_id_len;
        to->usm_ctx.req_auth_key_len = from->usm_ctx.req_auth_key_len;
        to->usm_ctx.req_priv_key_len = from->usm_ctx.req_priv_key_len;
    }

    to->usm_ctx.engine_boots = from->usm_ctx.engine_boots;
    to->usm_ctx.engine_time_offset = from->usm_ctx.engine_time_offset;
    to->usm_ctx.last_rec_boots = from->usm_ctx.last_rec_boots;
    to->usm_ctx.last_rec_time = from->usm_ctx.last_rec_time;
    to->usm_ctx.last_rec_msg_id = from->usm_ctx.last_rec_msg_id;
    memcpy(to->usm_ctx.last_rec_iv, from->usm_ctx.last_rec_iv,
            sizeof(to->usm_ctx.last_rec_iv));
}

static SnmpSecurityLevel get_sec_level_from_string(const char *str)
{
    if (!lenient_strcmp(str, "authPriv")) {
        return AUTH_PRIV;
    } else if (!lenient_strcmp(str, "authNoPriv")) {
        return AUTH_NO_PRIV;
    } else if (!lenient_strcmp(str, "noAuthNoPriv")) {
        return NO_AUTH_NO_PRIV;
    } else {
        return -1;
    }
}

static SnmpAuthAlgo get_auth_algo_from_string(const char *str)
{
    if (!lenient_strcmp(str, "SHA2-224")) {
        return SHA_2_224;
    } else if (!lenient_strcmp(str, "SHA2-256") || !lenient_strcmp(str, "SHA2")) {
        return SHA_2_256;
    } else if (!lenient_strcmp(str, "SHA2-384")) {
        return SHA_2_384;
    } else if (!lenient_strcmp(str, "SHA2-512")) {
        return SHA_2_512;
    } else if (!lenient_strcmp(str, "SHA1")) {
        return SHA_1;
    } else {
        return -1;
    }
}

static SnmpPrivAlgo get_priv_algo_from_string(const char *str)
{
    if (!lenient_strcmp(str, "AES-256")) {
        return AES_256_CFB;
    } else if (!lenient_strcmp(str, "AES-192")) {
        return AES_192_CFB;
    } else if (!lenient_strcmp(str, "AES-128")) {
        return AES_128_CFB;
    } else {
        return -1;
    }
}

static char *creat_alias(const char *input)
{
    char alias[MAX_ALIAS_LEN];
    const char *p = input;
    int i;
    for (i = 0; *p && i < sizeof(alias) - 1; p++) {
        if (isgraph(*p) && *p != ':')
            alias[i++] = *p;
    }
    if (i < 1)
        return NULL;
    alias[i] = '\0';

    if (!strcmp(alias, "ctl") || !strcmp(alias, "trap")) {
        return strconcat("agent-", alias);
    } else {
        return strdup(alias);
    }
}
