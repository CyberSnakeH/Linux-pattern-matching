#define _GNU_SOURCE
#include "Process.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>
#include <limits.h>

static int is_pid_dir(const char *name) {
    if (!name || *name == '\0') {
        return 0;
    }
    for (const unsigned char *p = (const unsigned char *)name; *p != '\0'; p++) {
        if (!isdigit(*p)) {
            return 0;
        }
    }
    return 1;
}


Process* process_create(const char *name) {
    Process *proc = (Process *)malloc(sizeof(Process));
    if (!proc) {
        perror("Failed to allocate memory for Process");
        return NULL;
    }
    strncpy(proc->name, name, sizeof(proc->name) - 1);
    proc->name[sizeof(proc->name) - 1] = '\0';
    proc->pid = -1;

    DIR *dir;
    struct dirent *ent;
    char buffer[512];

    if ((dir = opendir("/proc")) == NULL) {
        perror("Failed to open /proc");
        free(proc);
        return NULL;
    }

    while ((ent = readdir(dir)) != NULL) {
        if (!is_pid_dir(ent->d_name))
            continue;

        snprintf(buffer, sizeof(buffer), "/proc/%s/comm", ent->d_name);
        FILE *fp = fopen(buffer, "r");
        if (fp) {
            if (fgets(buffer, sizeof(buffer), fp)) {
                buffer[strcspn(buffer, "\n")] = '\0';
                if (strcmp(buffer, name) == 0) {
                    char *end = NULL;
                    long pid = strtol(ent->d_name, &end, 10);
                    if (end && *end == '\0' && pid > 0 && pid <= INT_MAX) {
                        proc->pid = (pid_t)pid;
                    }
                    fclose(fp);
                    break;
                }
            }
            fclose(fp);
        }
    }

    closedir(dir);
    if (proc->pid == -1) {
        free(proc);
        proc = NULL;
    }

    return proc;
}

void process_destroy(Process *proc) {
    if (proc) {
        free(proc);
    }
}

pid_t process_get_pid(const Process *proc) {
    return proc ? proc->pid : -1;
}


void process_set_pid(Process *proc, pid_t pid) {
    if (proc != NULL) {
        proc->pid = pid;
    }
}


const char* process_get_name(const Process *proc) {
    return proc ? proc->name : NULL;
}


void process_set_name(Process *proc, const char *name) {
    if (proc && name) {
        strncpy(proc->name, name, sizeof(proc->name) - 1);
        proc->name[sizeof(proc->name) - 1] = '\0';
    }
}


ssize_t process_read_memory(const Process *proc, unsigned long addr, void *buf, size_t size) {
    if (!proc) return -1;

    struct iovec local[1];
    struct iovec remote[1];

    local[0].iov_base = buf;
    local[0].iov_len = size;
    remote[0].iov_base = (void *)addr;
    remote[0].iov_len = size;

    ssize_t nread = process_vm_readv(proc->pid, local, 1, remote, 1, 0); 
    return nread;
}


ssize_t process_write_memory(const Process *proc, unsigned long addr, const void *buf, size_t size) {
    if (!proc) return -1;

    struct iovec local[1];
    struct iovec remote[1];

    local[0].iov_base = (void *)buf;
    local[0].iov_len = size;
    remote[0].iov_base = (void *)addr;
    remote[0].iov_len = size;

    ssize_t nwritten = process_vm_writev(proc->pid, local, 1, remote, 1, 0);
    return nwritten;
}
