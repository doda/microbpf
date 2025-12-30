/*
 * mbpf_manifest_gen - Generate manifest section for microBPF packages
 *
 * This tool generates CBOR or JSON encoded manifest sections that can be
 * assembled into .mbpf packages.
 *
 * Usage: mbpf_manifest_gen [options] -o output
 *
 * Options:
 *   --name NAME        Program name (required)
 *   --version VER      Program version (required)
 *   --hook TYPE        Hook type: 1-6 or name (required)
 *   --entry SYMBOL     Entry function (default: mbpf_prog)
 *   --heap SIZE        Heap size in bytes (default: 8192)
 *   --max-steps N      Max execution steps (default: 10000)
 *   --max-helpers N    Max helper calls (default: 100)
 *   --max-time-us N    Max wall time us (default: 0)
 *   --caps CAP,...     Comma-separated capabilities
 *   --word-size N      Target word size: 32 or 64
 *   --endianness E     Target endianness: little or big
 *   --format FMT       Output format: cbor or json
 *   -o FILE            Output file (required)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "mbpf.h"
#include "mbpf_package.h"
#include "mbpf_manifest_gen.h"

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options] -o output\n", prog);
    fprintf(stderr, "\nGenerate a manifest section for microBPF packages.\n");
    fprintf(stderr, "\nRequired options:\n");
    fprintf(stderr, "  --name NAME        Program name\n");
    fprintf(stderr, "  --version VER      Program version\n");
    fprintf(stderr, "  --hook TYPE        Hook type (1-6 or tracepoint/timer/net_rx/net_tx/security/custom)\n");
    fprintf(stderr, "  -o FILE            Output file\n");
    fprintf(stderr, "\nOptional options:\n");
    fprintf(stderr, "  --entry SYMBOL     Entry function (default: mbpf_prog)\n");
    fprintf(stderr, "  --heap SIZE        Heap size in bytes (default: 8192)\n");
    fprintf(stderr, "  --max-steps N      Max execution steps (default: 10000)\n");
    fprintf(stderr, "  --max-helpers N    Max helper calls (default: 100)\n");
    fprintf(stderr, "  --max-time-us N    Max wall time us (default: 0 = disabled)\n");
    fprintf(stderr, "  --caps CAP,...     Comma-separated capabilities\n");
    fprintf(stderr, "  --word-size N      Target word size: 32 or 64 (default: host)\n");
    fprintf(stderr, "  --endianness E     Target endianness: little or big (default: little)\n");
    fprintf(stderr, "  --format FMT       Output format: cbor or json (default: cbor)\n");
    fprintf(stderr, "\nCapabilities: CAP_LOG, CAP_MAP_READ, CAP_MAP_WRITE, CAP_MAP_ITERATE,\n");
    fprintf(stderr, "              CAP_EMIT, CAP_TIME, CAP_STATS\n");
    exit(1);
}

static int parse_hook_type(const char *s) {
    if (strcmp(s, "tracepoint") == 0 || strcmp(s, "1") == 0)
        return MBPF_HOOK_TRACEPOINT;
    if (strcmp(s, "timer") == 0 || strcmp(s, "2") == 0)
        return MBPF_HOOK_TIMER;
    if (strcmp(s, "net_rx") == 0 || strcmp(s, "3") == 0)
        return MBPF_HOOK_NET_RX;
    if (strcmp(s, "net_tx") == 0 || strcmp(s, "4") == 0)
        return MBPF_HOOK_NET_TX;
    if (strcmp(s, "security") == 0 || strcmp(s, "5") == 0)
        return MBPF_HOOK_SECURITY;
    if (strcmp(s, "custom") == 0 || strcmp(s, "6") == 0)
        return MBPF_HOOK_CUSTOM;
    return -1;
}

static uint32_t parse_capabilities(const char *s) {
    uint32_t caps = 0;
    char *dup = strdup(s);
    char *token = strtok(dup, ",");
    while (token) {
        /* Trim whitespace */
        while (*token == ' ') token++;
        char *end = token + strlen(token) - 1;
        while (end > token && *end == ' ') *end-- = '\0';

        if (strcmp(token, "CAP_LOG") == 0)
            caps |= MBPF_CAP_LOG;
        else if (strcmp(token, "CAP_MAP_READ") == 0)
            caps |= MBPF_CAP_MAP_READ;
        else if (strcmp(token, "CAP_MAP_WRITE") == 0)
            caps |= MBPF_CAP_MAP_WRITE;
        else if (strcmp(token, "CAP_MAP_ITERATE") == 0)
            caps |= MBPF_CAP_MAP_ITERATE;
        else if (strcmp(token, "CAP_EMIT") == 0)
            caps |= MBPF_CAP_EMIT;
        else if (strcmp(token, "CAP_TIME") == 0)
            caps |= MBPF_CAP_TIME;
        else if (strcmp(token, "CAP_STATS") == 0)
            caps |= MBPF_CAP_STATS;
        else {
            fprintf(stderr, "Warning: unknown capability '%s'\n", token);
        }
        token = strtok(NULL, ",");
    }
    free(dup);
    return caps;
}

int main(int argc, char *argv[]) {
    const char *output = NULL;
    const char *name = NULL;
    const char *version = NULL;
    const char *hook_str = NULL;
    const char *entry = "mbpf_prog";
    const char *caps_str = NULL;
    const char *endianness = "little";
    const char *format = "cbor";
    uint32_t heap_size = MBPF_MIN_HEAP_SIZE;
    uint32_t max_steps = 10000;
    uint32_t max_helpers = 100;
    uint32_t max_time_us = 0;
    uint32_t word_size = 0;  /* 0 = auto-detect */

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) {
            name = argv[++i];
        } else if (strcmp(argv[i], "--version") == 0 && i + 1 < argc) {
            version = argv[++i];
        } else if (strcmp(argv[i], "--hook") == 0 && i + 1 < argc) {
            hook_str = argv[++i];
        } else if (strcmp(argv[i], "--entry") == 0 && i + 1 < argc) {
            entry = argv[++i];
        } else if (strcmp(argv[i], "--heap") == 0 && i + 1 < argc) {
            heap_size = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--max-steps") == 0 && i + 1 < argc) {
            max_steps = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--max-helpers") == 0 && i + 1 < argc) {
            max_helpers = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--max-time-us") == 0 && i + 1 < argc) {
            max_time_us = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--caps") == 0 && i + 1 < argc) {
            caps_str = argv[++i];
        } else if (strcmp(argv[i], "--word-size") == 0 && i + 1 < argc) {
            word_size = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--endianness") == 0 && i + 1 < argc) {
            endianness = argv[++i];
        } else if (strcmp(argv[i], "--format") == 0 && i + 1 < argc) {
            format = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
        }
    }

    /* Validate required arguments */
    if (!name) {
        fprintf(stderr, "Error: --name is required\n");
        usage(argv[0]);
    }
    if (!version) {
        fprintf(stderr, "Error: --version is required\n");
        usage(argv[0]);
    }
    if (!hook_str) {
        fprintf(stderr, "Error: --hook is required\n");
        usage(argv[0]);
    }
    if (!output) {
        fprintf(stderr, "Error: -o is required\n");
        usage(argv[0]);
    }

    int hook_type = parse_hook_type(hook_str);
    if (hook_type < 0) {
        fprintf(stderr, "Error: invalid hook type '%s'\n", hook_str);
        usage(argv[0]);
    }

    /* Build manifest structure */
    mbpf_manifest_t m;
    mbpf_manifest_init_defaults(&m);

    strncpy(m.program_name, name, sizeof(m.program_name) - 1);
    strncpy(m.program_version, version, sizeof(m.program_version) - 1);
    strncpy(m.entry_symbol, entry, sizeof(m.entry_symbol) - 1);
    m.hook_type = hook_type;
    m.heap_size = heap_size;
    m.budgets.max_steps = max_steps;
    m.budgets.max_helpers = max_helpers;
    m.budgets.max_wall_time_us = max_time_us;

    if (caps_str) {
        m.capabilities = parse_capabilities(caps_str);
    }

    if (word_size == 32 || word_size == 64) {
        m.target.word_size = word_size;
    }

    if (strcmp(endianness, "big") == 0) {
        m.target.endianness = 1;
    } else {
        m.target.endianness = 0;
    }

    /* Validate manifest */
    int err = mbpf_manifest_validate(&m);
    if (err != MBPF_OK) {
        fprintf(stderr, "Error: invalid manifest (error %d)\n", err);
        return 1;
    }

    /* Generate output */
    FILE *f = fopen(output, "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    if (strcmp(format, "json") == 0) {
        size_t size = mbpf_manifest_json_size(&m);
        char *buf = malloc(size);
        if (!buf) {
            fprintf(stderr, "Error: out of memory\n");
            fclose(f);
            return 1;
        }

        size_t len = size;
        err = mbpf_manifest_generate_json(&m, buf, &len);
        if (err != MBPF_OK) {
            fprintf(stderr, "Error: failed to generate JSON (error %d)\n", err);
            free(buf);
            fclose(f);
            return 1;
        }

        fwrite(buf, 1, len, f);
        free(buf);
    } else {
        size_t size = mbpf_manifest_cbor_size(&m);
        uint8_t *buf = malloc(size);
        if (!buf) {
            fprintf(stderr, "Error: out of memory\n");
            fclose(f);
            return 1;
        }

        size_t len = size;
        err = mbpf_manifest_generate_cbor(&m, buf, &len);
        if (err != MBPF_OK) {
            fprintf(stderr, "Error: failed to generate CBOR (error %d)\n", err);
            free(buf);
            fclose(f);
            return 1;
        }

        fwrite(buf, 1, len, f);
        free(buf);
    }

    fclose(f);
    return 0;
}
