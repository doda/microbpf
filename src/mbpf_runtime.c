/*
 * microBPF Runtime Implementation
 *
 * Core runtime for executing microBPF programs using MQuickJS.
 */

#include "mbpf.h"
#include "mbpf_package.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Internal structures */
struct mbpf_runtime {
    mbpf_runtime_config_t config;
    mbpf_program_t *programs;
    size_t program_count;
    bool initialized;
};

struct mbpf_program {
    mbpf_runtime_t *runtime;
    mbpf_manifest_t manifest;
    void *bytecode;
    size_t bytecode_len;
    mbpf_stats_t stats;
    mbpf_hook_id_t attached_hook;
    bool attached;
    struct mbpf_program *next;
};

/* Default log handler */
static void default_log_fn(int level, const char *msg) {
    const char *level_str = "INFO";
    switch (level) {
        case 0: level_str = "DEBUG"; break;
        case 1: level_str = "INFO"; break;
        case 2: level_str = "WARN"; break;
        case 3: level_str = "ERROR"; break;
    }
    fprintf(stderr, "[mbpf %s] %s\n", level_str, msg);
}

/* Runtime initialization */
mbpf_runtime_t *mbpf_runtime_init(const mbpf_runtime_config_t *cfg) {
    mbpf_runtime_t *rt = calloc(1, sizeof(mbpf_runtime_t));
    if (!rt) {
        return NULL;
    }

    if (cfg) {
        rt->config = *cfg;
    } else {
        /* Set reasonable defaults */
        rt->config.default_heap_size = 16384;    /* 16KB */
        rt->config.default_max_steps = 100000;
        rt->config.default_max_helpers = 1000;
        rt->config.allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ |
                                          MBPF_CAP_MAP_WRITE;
        rt->config.require_signatures = false;
        rt->config.debug_mode = false;
    }

    if (!rt->config.log_fn) {
        rt->config.log_fn = default_log_fn;
    }

    rt->initialized = true;
    return rt;
}

/* Runtime shutdown */
void mbpf_runtime_shutdown(mbpf_runtime_t *rt) {
    if (!rt) return;

    /* Unload all programs */
    mbpf_program_t *prog = rt->programs;
    while (prog) {
        mbpf_program_t *next = prog->next;
        mbpf_program_unload(rt, prog);
        prog = next;
    }

    free(rt);
}

/* Program loading */
int mbpf_program_load(mbpf_runtime_t *rt, const void *pkg, size_t pkg_len,
                      const mbpf_load_opts_t *opts, mbpf_program_t **out_prog) {
    if (!rt || !pkg || pkg_len < sizeof(mbpf_file_header_t) || !out_prog) {
        return MBPF_ERR_INVALID_ARG;
    }

    /* Parse header */
    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(pkg, pkg_len, &header);
    if (err != MBPF_OK) {
        return err;
    }

    /* Allocate program structure */
    mbpf_program_t *prog = calloc(1, sizeof(mbpf_program_t));
    if (!prog) {
        return MBPF_ERR_NO_MEM;
    }

    prog->runtime = rt;

    /* Get and parse manifest */
    const void *manifest_data;
    size_t manifest_len;
    err = mbpf_package_get_section(pkg, pkg_len, MBPF_SEC_MANIFEST,
                                   &manifest_data, &manifest_len);
    if (err != MBPF_OK) {
        free(prog);
        return MBPF_ERR_MISSING_SECTION;
    }

    err = mbpf_package_parse_manifest(manifest_data, manifest_len,
                                       &prog->manifest);
    if (err != MBPF_OK) {
        free(prog);
        return err;
    }

    /* Get bytecode section */
    const void *bytecode_data;
    size_t bytecode_len;
    err = mbpf_package_get_section(pkg, pkg_len, MBPF_SEC_BYTECODE,
                                   &bytecode_data, &bytecode_len);
    if (err != MBPF_OK) {
        mbpf_manifest_free(&prog->manifest);
        free(prog);
        return MBPF_ERR_MISSING_SECTION;
    }

    /* Copy bytecode (needs to be mutable for relocation) */
    prog->bytecode = malloc(bytecode_len);
    if (!prog->bytecode) {
        mbpf_manifest_free(&prog->manifest);
        free(prog);
        return MBPF_ERR_NO_MEM;
    }
    memcpy(prog->bytecode, bytecode_data, bytecode_len);
    prog->bytecode_len = bytecode_len;

    /* Add to runtime's program list */
    prog->next = rt->programs;
    rt->programs = prog;
    rt->program_count++;

    *out_prog = prog;
    return MBPF_OK;
}

/* Program unloading */
int mbpf_program_unload(mbpf_runtime_t *rt, mbpf_program_t *prog) {
    if (!rt || !prog) {
        return MBPF_ERR_INVALID_ARG;
    }

    /* Remove from list */
    mbpf_program_t **pp = &rt->programs;
    while (*pp && *pp != prog) {
        pp = &(*pp)->next;
    }
    if (*pp) {
        *pp = prog->next;
        rt->program_count--;
    }

    /* Free resources */
    mbpf_manifest_free(&prog->manifest);
    free(prog->bytecode);
    free(prog);

    return MBPF_OK;
}

/* Program attach */
int mbpf_program_attach(mbpf_runtime_t *rt, mbpf_program_t *prog,
                        mbpf_hook_id_t hook) {
    if (!rt || !prog) {
        return MBPF_ERR_INVALID_ARG;
    }

    if (prog->attached) {
        return MBPF_ERR_ALREADY_ATTACHED;
    }

    prog->attached_hook = hook;
    prog->attached = true;

    return MBPF_OK;
}

/* Program detach */
int mbpf_program_detach(mbpf_runtime_t *rt, mbpf_program_t *prog,
                        mbpf_hook_id_t hook) {
    if (!rt || !prog) {
        return MBPF_ERR_INVALID_ARG;
    }

    if (!prog->attached || prog->attached_hook != hook) {
        return MBPF_ERR_NOT_ATTACHED;
    }

    prog->attached = false;
    prog->attached_hook = 0;

    return MBPF_OK;
}

/* Run program */
int mbpf_run(mbpf_runtime_t *rt, mbpf_hook_id_t hook,
             const void *ctx_blob, size_t ctx_len,
             int32_t *out_rc) {
    if (!rt || !out_rc) {
        return MBPF_ERR_INVALID_ARG;
    }

    /* Find attached programs for this hook */
    /* TODO: Implement actual JS execution with MQuickJS */
    /* For now, return success with default pass */
    *out_rc = MBPF_NET_PASS;

    return MBPF_OK;
}

/* Stats access */
int mbpf_program_stats(mbpf_program_t *prog, mbpf_stats_t *out_stats) {
    if (!prog || !out_stats) {
        return MBPF_ERR_INVALID_ARG;
    }

    *out_stats = prog->stats;
    return MBPF_OK;
}

/* Version info */
const char *mbpf_version_string(void) {
    static char version[32];
    snprintf(version, sizeof(version), "%d.%d.%d",
             MBPF_VERSION_MAJOR, MBPF_VERSION_MINOR, MBPF_VERSION_PATCH);
    return version;
}

uint32_t mbpf_api_version(void) {
    return MBPF_API_VERSION;
}
