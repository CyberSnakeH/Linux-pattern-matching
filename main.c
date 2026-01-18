#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include "Process.h"

#define DEFAULT_PATTERN_FILE "pattern.txt"
#define SCAN_CHUNK_SIZE (1024 * 1024)

typedef struct {
    unsigned char *bytes;
    unsigned char *mask;
    size_t length;
    ssize_t anchor_index;
} Pattern;

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [-v] [-p pattern_file] <process_name>\n", prog);
}

static int hex_value(int c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int parse_pattern(const char *pattern_str, Pattern *out) {
    size_t cap = strlen(pattern_str) / 2 + 1;
    unsigned char *bytes = calloc(cap, 1);
    unsigned char *mask = calloc(cap, 1);
    size_t len = 0;

    if (!bytes || !mask) {
        free(bytes);
        free(mask);
        perror("Failed to allocate pattern buffers");
        return -1;
    }

    for (const char *p = pattern_str; *p != '\0';) {
        if (isspace((unsigned char)*p)) {
            p++;
            continue;
        }
        if (*p == '?') {
            p++;
            if (*p == '?') {
                p++;
            }
            bytes[len] = 0;
            mask[len] = 0;
            len++;
            continue;
        }

        int hi = hex_value((unsigned char)*p++);
        if (hi < 0 || *p == '\0') {
            fprintf(stderr, "Invalid pattern near '%c'\n", *(p - 1));
            free(bytes);
            free(mask);
            return -1;
        }
        int lo = hex_value((unsigned char)*p++);
        if (lo < 0) {
            fprintf(stderr, "Invalid pattern near '%c'\n", *(p - 1));
            free(bytes);
            free(mask);
            return -1;
        }

        bytes[len] = (unsigned char)((hi << 4) | lo);
        mask[len] = 0xFF;
        len++;
    }

    if (len == 0) {
        fprintf(stderr, "Pattern is empty. Please provide a valid pattern.\n");
        free(bytes);
        free(mask);
        return -1;
    }

    out->bytes = bytes;
    out->mask = mask;
    out->length = len;
    out->anchor_index = -1;
    for (size_t i = 0; i < len; i++) {
        if (mask[i] == 0xFF) {
            out->anchor_index = (ssize_t)i;
            break;
        }
    }

    return 0;
}

static void free_pattern(Pattern *pattern) {
    if (!pattern) {
        return;
    }
    free(pattern->bytes);
    free(pattern->mask);
    pattern->bytes = NULL;
    pattern->mask = NULL;
    pattern->length = 0;
    pattern->anchor_index = -1;
}

static int read_pattern_file(const char *path, char **out_pattern) {
    FILE *file = fopen(path, "r");
    if (!file) {
        perror("Failed to open pattern file");
        return -1;
    }

    char *line = NULL;
    size_t cap = 0;
    char *pattern = NULL;

    while (getline(&line, &cap, file) != -1) {
        char *p = line;
        while (isspace((unsigned char)*p)) {
            p++;
        }
        if (*p == '\0') {
            continue;
        }
        if (strncmp(p, "Pattern:", 8) == 0) {
            p += 8;
        }
        while (isspace((unsigned char)*p)) {
            p++;
        }
        if (*p == '\0') {
            continue;
        }
        p[strcspn(p, "\r\n")] = '\0';
        pattern = strdup(p);
        if (!pattern) {
            perror("Failed to allocate pattern string");
            free(line);
            fclose(file);
            return -1;
        }
        break;
    }

    free(line);
    fclose(file);

    if (!pattern) {
        fprintf(stderr, "Pattern file is empty or missing a pattern.\n");
        return -1;
    }

    *out_pattern = pattern;
    return 0;
}

static int pattern_match_at(const unsigned char *buffer, const Pattern *pattern, size_t offset) {
    for (size_t i = 0; i < pattern->length; i++) {
        if (pattern->mask[i] == 0) {
            continue;
        }
        if (buffer[offset + i] != pattern->bytes[i]) {
            return 0;
        }
    }
    return 1;
}

static ssize_t find_pattern_in_buffer(const unsigned char *buffer, size_t buffer_len, const Pattern *pattern) {
    if (pattern->length == 0 || buffer_len < pattern->length) {
        return -1;
    }

    if (pattern->anchor_index < 0) {
        return 0;
    }

    size_t last_start = buffer_len - pattern->length;
    size_t anchor = (size_t)pattern->anchor_index;
    unsigned char needle = pattern->bytes[anchor];
    size_t i = 0;

    while (i <= last_start) {
        size_t search_len = last_start - i + 1;
        const unsigned char *found = memchr(buffer + i + anchor, needle, search_len);
        if (!found) {
            return -1;
        }
        size_t pos = (size_t)(found - buffer) - anchor;
        if (pattern_match_at(buffer, pattern, pos)) {
            return (ssize_t)pos;
        }
        i = pos + 1;
    }

    return -1;
}

static int scan_region(const Process *proc,
                       uintptr_t start,
                       uintptr_t end,
                       const Pattern *pattern,
                       int verbose,
                       uintptr_t *found_addr) {
    if (end <= start || pattern->length == 0) {
        return 0;
    }

    size_t overlap = pattern->length > 1 ? pattern->length - 1 : 0;
    size_t chunk = SCAN_CHUNK_SIZE;
    unsigned char *buffer = malloc(chunk + overlap);
    if (!buffer) {
        perror("Failed to allocate scan buffer");
        return -1;
    }

    size_t carry = 0;
    uintptr_t addr = start;

    while (addr < end) {
        size_t to_read = (size_t)(end - addr);
        if (to_read > chunk) {
            to_read = chunk;
        }

        ssize_t nread = process_read_memory(proc, (unsigned long)addr, buffer + carry, to_read);
        if (nread <= 0) {
            if (verbose) {
                fprintf(stderr, "Failed to read memory at 0x%lx: %s\n",
                        (unsigned long)addr, strerror(errno));
            }
            break;
        }

        size_t total = carry + (size_t)nread;
        ssize_t pos = find_pattern_in_buffer(buffer, total, pattern);
        if (pos >= 0) {
            *found_addr = (addr - carry) + (uintptr_t)pos;
            free(buffer);
            return 1;
        }

        if (overlap == 0) {
            carry = 0;
        } else if (total >= overlap) {
            memmove(buffer, buffer + total - overlap, overlap);
            carry = overlap;
        } else {
            carry = total;
        }

        addr += (uintptr_t)nread;
    }

    free(buffer);
    return 0;
}

static int scan_process(const Process *proc, const Pattern *pattern, int verbose) {
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", process_get_pid(proc));

    FILE *maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        perror("Failed to open maps file");
        return -1;
    }

    char line[512];
    int found_count = 0;

    while (fgets(line, sizeof(line), maps_file)) {
        unsigned long long start = 0;
        unsigned long long end = 0;
        char perms[5] = {0};

        if (sscanf(line, "%llx-%llx %4s", &start, &end, perms) != 3) {
            continue;
        }

        if (perms[0] != 'r' || perms[2] != 'x') {
            continue;
        }

        if (verbose) {
            fprintf(stderr, "Scanning region 0x%llx-0x%llx (%s)\n", start, end, perms);
        }

        uintptr_t found_addr = 0;
        int found = scan_region(proc, (uintptr_t)start, (uintptr_t)end, pattern, verbose, &found_addr);
        if (found < 0) {
            fclose(maps_file);
            return -1;
        }
        if (found > 0) {
            printf("Pattern found at address: 0x%lx\n", (unsigned long)found_addr);
            found_count++;
        }
    }

    fclose(maps_file);
    return found_count;
}

int main(int argc, char *argv[]) {
    int verbose = 0;
    const char *pattern_path = DEFAULT_PATTERN_FILE;
    int opt;

    while ((opt = getopt(argc, argv, "vp:")) != -1) {
        switch (opt) {
            case 'v':
                verbose = 1;
                break;
            case 'p':
                pattern_path = optarg;
                break;
            default:
                usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (optind >= argc) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *process_name = argv[optind];

    Process *proc = process_create(process_name);
    if (!proc) {
        fprintf(stderr, "Failed to create process object for %s\n", process_name);
        return EXIT_FAILURE;
    }

    if (verbose) {
        fprintf(stderr, "Process name: %s, PID: %d\n", process_get_name(proc), process_get_pid(proc));
    }

    char *pattern_str = NULL;
    if (read_pattern_file(pattern_path, &pattern_str) != 0) {
        process_destroy(proc);
        return EXIT_FAILURE;
    }

    Pattern pattern = {0};
    if (parse_pattern(pattern_str, &pattern) != 0) {
        free(pattern_str);
        process_destroy(proc);
        return EXIT_FAILURE;
    }

    free(pattern_str);

    int found = scan_process(proc, &pattern, verbose);
    if (found < 0) {
        free_pattern(&pattern);
        process_destroy(proc);
        return EXIT_FAILURE;
    }
    if (found == 0) {
        printf("Pattern not found in executable regions.\n");
    }
    printf("Just %d address(es) found.\n", found);
    if (found > 1) {
        printf("Try to add more details to the pattern.\n");
    }

    free_pattern(&pattern);
    process_destroy(proc);

    return found ? EXIT_SUCCESS : EXIT_FAILURE;
}
