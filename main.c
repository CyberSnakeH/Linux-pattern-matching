#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "Process.h"

#define MAX_PATTERN_LENGTH 1024


void pattern_to_bytes_and_mask(const char *pattern, unsigned char **bytes, unsigned char **mask_bytes, size_t *length) {
    size_t pattern_len = strlen(pattern) / 2; 
    *bytes = (unsigned char *)malloc(pattern_len);
    *mask_bytes = (unsigned char *)malloc(pattern_len);
    *length = pattern_len;

    char byte_str[3] = {0}; 
    for (size_t i = 0; i < pattern_len; i++) {
        strncpy(byte_str, &pattern[i * 2], 2);
        if (strncmp(byte_str, "??", 2) == 0) {
            (*bytes)[i] = 0;
            (*mask_bytes)[i] = 0;
        } else {
            (*bytes)[i] = (unsigned char)strtol(byte_str, NULL, 16);
            (*mask_bytes)[i] = 0xFF;
        }
    }
    printf("Debug: Pattern and mask converted to bytes\n");
}


int mask_check(const unsigned char *memory, const unsigned char *pattern, const unsigned char *mask, size_t pattern_len, size_t offset) {
    for (size_t i = 0; i < pattern_len; i++) {
        if ((memory[offset + i] & mask[i]) != (pattern[i] & mask[i])) {
            return 0;  
        }
    }
    return 1;  
}

unsigned long find_pattern_in_memory_region(const Process *proc, unsigned long start, unsigned long end, const unsigned char *pattern, const unsigned char *mask, size_t pattern_len) {
    size_t size = end - start;
    unsigned char *buffer = (unsigned char *)malloc(size);
    if (!buffer) {
        perror("Failed to allocate memory");
        return 0;
    }

    printf("Debug: Reading memory from 0x%lx to 0x%lx\n", start, end);
    if (process_read_memory(proc, start, buffer, size) != size) {
        free(buffer);
        return 0;
    }

    for (size_t i = 0; i <= size - pattern_len; i++) {
        if (mask_check(buffer, pattern, mask, pattern_len, i)) {
            printf("Debug: Pattern matched at offset %zu in region 0x%lx to 0x%lx\n", i, start, end);
            free(buffer);
            return start + i;
        }
    }

    free(buffer);
    return 0;
}

void list_all_rxp_regions(pid_t pid) {
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        perror("Failed to open maps file");
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), maps_file)) {
        unsigned long start, end;
        char perms[5];
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3) {
            continue;
        }

       
        if (strcmp(perms, "r-xp") != 0) {
            continue;
        }

        printf("Debug: Found r-xp region from 0x%lx to 0x%lx\n", start, end);
    }

    fclose(maps_file);
}

void find_pattern_in_all_memory_regions(const Process *proc, const unsigned char *pattern, const unsigned char *mask, size_t pattern_len) {
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", process_get_pid(proc));

    FILE *maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        perror("Failed to open maps file");
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), maps_file)) {
        unsigned long start, end;
        char perms[5];
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3) {
            continue;
        }

        
        if (strcmp(perms, "r-xp") != 0) {
            continue;
        }

        printf("Debug: Scanning region from 0x%lx to 0x%lx with permissions %s\n", start, end, perms);
        unsigned long found_address = find_pattern_in_memory_region(proc, start, end, pattern, mask, pattern_len);
        if (found_address != 0) {
            printf("Pattern found at address: 0x%lx\n", found_address);
        } else {
            printf("Pattern not found in region 0x%lx to 0x%lx\n", start, end);
        }
    }

    fclose(maps_file);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <process_name>\n", argv[0]);
        return EXIT_FAILURE;
    }

    
    Process *proc = process_create(argv[1]);
    if (!proc) {
        fprintf(stderr, "Failed to create process object for %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    
    printf("Process name: %s, PID: %d\n", process_get_name(proc), process_get_pid(proc));

    
    FILE *pattern_file = fopen("pattern.txt", "r");
    if (!pattern_file) {
        perror("Failed to open pattern file");
        process_destroy(proc);
        return EXIT_FAILURE;
    }

    char pattern_str[MAX_PATTERN_LENGTH] = {0};
    fscanf(pattern_file, "Pattern: %s\n", pattern_str);
    fclose(pattern_file);

    if (strlen(pattern_str) == 0) {
        fprintf(stderr, "Pattern is empty. Please provide a valid pattern.\n");
        process_destroy(proc);
        return EXIT_FAILURE;
    }

    
    unsigned char *pattern = NULL, *mask = NULL;
    size_t pattern_len;
    pattern_to_bytes_and_mask(pattern_str, &pattern, &mask, &pattern_len);

    list_all_rxp_regions(process_get_pid(proc));

    find_pattern_in_all_memory_regions(proc, pattern, mask, pattern_len);

    free(pattern);
    free(mask);

    process_destroy(proc);

    return EXIT_SUCCESS;
}
