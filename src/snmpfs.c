/*
 * This file is part of the snmpfs project (http://snmpfs.x25.pm).
 * snmpfs is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 2 of the license, or any later
 * version.  See LICENSE file for further copyright and license details.
 */

#include "common.h"

#include <signal.h>
#include <fcntl.h>
#include <dirent.h>
#include <dlfcn.h>
#include <limits.h>
#include <getopt.h>

#include "cache.h"
#include "config.h"

/* indicates if debug logging is enabled */
static int debug_logging = 0;

/* indicates if process is finished */
static int req_exit = 2;

/* indicates if configuration needs to be reloaded */
static int req_reload_config = 0;

/* PID file */
static const char *pid_file = RUN_DIR "/snmpfs.pid";

static AgentList agent_list;

static void main_loop(void)
{
    while (req_exit == 2) {
        pause();

        if (req_reload_config) {
            syslog(LOG_DEBUG, "reloading configuration");
            if (reload_config(&agent_list)) {
                syslog(LOG_ERR, "invalid configuration;  exiting process");
                req_exit = EXIT_FAILURE;
            }

            if (sync_cache_from_disk(&agent_list)) {
                syslog(LOG_ERR, "failed to sync cache");
                req_exit = EXIT_FAILURE;
            }

            req_reload_config = 0;
        }

        /* TODO */
    }
}

static void handle_signal(int signal)
{
    if (signal == SIGHUP) {
        req_reload_config = 1;
    } else {
        req_exit = EXIT_SUCCESS;
    }
}

static void usage(void)
{
    fprintf(stderr, "usage: snmpfs [-qfdv] [-c <config-file>]\n");
    exit(EXIT_SUCCESS);
}

static int init_run_dir(void)
{
    struct stat rundir;
    if (stat(RUN_DIR, &rundir) == -1) {
        if(ENOENT != errno)
            goto failed;
    } else if (!S_ISDIR(rundir.st_mode)) {
        if (remove(RUN_DIR) == -1)
            goto failed;
    } else {
        goto set_permissions;
    }

    if (mkdir(RUN_DIR, 0775) == -1)
        goto failed;

set_permissions:
    if (get_uid() != 0 && get_gid() != 0 &&
        chown(RUN_DIR, get_uid(), get_gid()) == -1)
        goto failed;

    return 0;

failed:
    syslog(LOG_ERR, "failed to initialise runtime directory : %s", strerror(errno));
    return -1;
}

static int create_pid_file(void)
{
    int mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;
    int f = open(pid_file, O_RDWR | O_CREAT, mode);
    if (f == -1)
        goto failed;

    char pid[16];
    snprintf(pid, sizeof(pid), "%u\n", getpid());
    ssize_t size = write(f, pid, strlen(pid) + 1);
    if (size < 0)
        goto failed;
    close(f);
    chmod(pid_file, mode);
    return 0;

failed:
    if (f != -1)
        close(f);
    syslog(LOG_ERR, "failed to create PID file : %s", strerror(errno));
    return -1;
}

static int remove_pid_file(void)
{
    if (remove(pid_file) != 0) {
        syslog(LOG_ERR, "failed to remove PID file : %s", strerror(errno));
        return -1;
    }

    return 0;
}

void set_debug_logging(int enabled)
{
    debug_logging = enabled ? 1 : 0;
    setlogmask(LOG_UPTO(enabled ? LOG_DEBUG : LOG_INFO));
}

int debug_logging_enabled(void)
{
    return debug_logging;
}

int main(int argc, char **argv)
{
    int daemonize = 1;
    int log_level = LOG_INFO;
    int opt;
    while ((opt = getopt(argc, argv, "c:fvqdh?p:")) != -1) {
        switch (opt) {
            case 'c': {
                set_config_file(optarg);
                break;
            }

            case 'f': {
                daemonize = 0;
                break;
            }

            case 'v': {
                fprintf(stderr, "%s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
                exit(EXIT_SUCCESS);
            }

            case 'q': {
                log_level = LOG_WARNING;
                break;
            }

            case 'd': {
                debug_logging = 1;
                log_level = LOG_DEBUG;
                struct rlimit core_limits;
                core_limits.rlim_cur = RLIM_INFINITY;
                core_limits.rlim_max = RLIM_INFINITY;
                setrlimit(RLIMIT_CORE, &core_limits);
                break;
            }

            default: {
                usage();
                break;
            }
        }
    }

    setlogmask(LOG_UPTO(log_level));
    openlog(PACKAGE_NAME, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_DAEMON);

    if (daemonize) {
        signal(SIGCHLD, SIG_IGN);
        int pid = fork();

        if (pid < 0)
            goto daemonize_failed;
        else if (pid > 0)
            /* exit parent */
            exit(EXIT_SUCCESS);

        /* new session leader */
        if (setsid() < 0)
            goto daemonize_failed;

        pid = fork();
        if (pid < 0)
            goto daemonize_failed;
        else if (pid > 0)
            /* exit parent */
            exit(EXIT_SUCCESS);

        umask(0);
        char *work_dir = get_cache_dir();
        if (work_dir == NULL)
            work_dir = "/tmp";
        if (chdir(work_dir) == -1)
            goto daemonize_failed;

        /* redirect stdio */
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        open("/dev/null", O_RDWR);
        if (dup(0) == -1 || dup(0) == -1) {
            syslog(LOG_ERR, "failed to reroute stdin/out : %s.", strerror(errno));
            exit(EXIT_FAILURE);
        }

        create_pid_file();
        goto daemonize_completed;

daemonize_failed:
        syslog(LOG_ERR, "failed to daemonize : %s.", strerror(errno));
        exit(EXIT_FAILURE);
    } else {
        umask(0);
    }
daemonize_completed: ;

    if (init_run_dir())
        exit(EXIT_FAILURE);

    init_crypto();

    memset(&agent_list, 0, sizeof(agent_list));

    if (reload_config(&agent_list)) {
        syslog(LOG_ERR, "invalid configuration;  exiting process");
        exit(EXIT_FAILURE);
    }
    if (init_cache() == -1) {
        syslog(LOG_ERR, "failed to initialise SNMP agent cache");
        exit(EXIT_FAILURE);
    }
    if (sync_cache_from_disk(&agent_list)) {
        syslog(LOG_ERR, "failed to sync cache");
        exit(EXIT_FAILURE);
    }

    /* set signal handler */
    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sa.sa_flags = 0; /* no SA_RESTART */
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTERM, &sa, NULL) == -1 ||
        sigaction(SIGINT, &sa, NULL) == -1 ||  sigaction(SIGHUP, &sa, NULL) == -1) {
        syslog(LOG_ERR, "failed to register signal handler : %s", strerror(errno));
        req_exit = EXIT_FAILURE;
    }

    /* drop privileges after mounting file system */
    if (getuid() != get_uid() || getgid() != get_gid()) {
        if (setgid(get_gid()) != 0) {
            syslog(LOG_ERR, "unable to drop group privileges : %s", strerror(errno));
            req_exit = EXIT_FAILURE;
        }
        if (setuid(get_uid()) != 0) {
            syslog(LOG_ERR, "unable to drop user privileges : %s", strerror(errno));
            req_exit = EXIT_FAILURE;
        }
    }

    main_loop();

    if (sync_cache_to_disk(&agent_list))
        syslog(LOG_WARNING, "failed to update cache");
    finish_cache();

    finish_crypto();
    remove_pid_file();
    closelog();

    exit(req_exit);
}

void init_agent_ctx(AgentCtx *ctx)
{
    ctx->alias = NULL;
    ctx->address = NULL;
    memset(ctx->address_resolved, 0, sizeof(ctx->address_resolved));
    ctx->port = TRAP_PORT;
    ctx->retries = REQ_RETRIES;
    ctx->timeout = REQ_TIMEOUT;
    ctx->version = SNMP_VERSION;
    ctx->ctx_preshared = 0;
    ctx->ctx_engine_id_len = 0;
    ctx->ctx_name_len = 0;
    ctx->sec_model = USM;
    ctx->usm_ctx.level = NO_AUTH_NO_PRIV;
    ctx->usm_ctx.user_name_len = 0;
    ctx->usm_ctx.auth_engine_id_preshared = 0;
    ctx->usm_ctx.auth_engine_id_len = 0;
    ctx->usm_ctx.auth_algo = SHA_2_256;
    ctx->usm_ctx.auth_key_len = 0;
    ctx->usm_ctx.auth_diversified = 0;
    ctx->usm_ctx.priv_algo = AES_256_CFB;
    ctx->usm_ctx.priv_key_len = 0;
    ctx->usm_ctx.priv_diversified = 0;
    ctx->usm_ctx.req_auth_key_len = 0;
    ctx->usm_ctx.req_priv_key_len = 0;
    ctx->usm_ctx.trap_auth_key_len = 0;
    ctx->usm_ctx.trap_priv_key_len = 0;
    ctx->usm_ctx.engine_boots = 0;
    ctx->usm_ctx.engine_time_offset = 0;
    ctx->usm_ctx.last_rec_boots = 0;
    ctx->usm_ctx.last_rec_time = 0;
    ctx->usm_ctx.last_rec_msg_id = 0;
    memset(ctx->usm_ctx.last_rec_iv, 0, sizeof(ctx->usm_ctx.last_rec_iv));
}

void free_agent_ctx(AgentCtx *ctx)
{
    free(ctx->alias);
    free(ctx->address);
    free(ctx);
}
