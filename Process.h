#ifndef PROCESS_H
#define PROCESS_H

#include <sys/types.h>
#include <sys/uio.h>

typedef struct {
    pid_t pid;
    char name[256];
} Process;


Process* process_create(const char *name);
void process_destroy(Process *proc);
pid_t process_get_pid(const Process *proc);
void process_set_pid(Process *proc, pid_t pid);
const char* process_get_name(const Process *proc);
void process_set_name(Process *proc, const char *name);
ssize_t process_read_memory(const Process *proc, unsigned long addr, void *buf, size_t size);
ssize_t process_write_memory(const Process *proc, unsigned long addr, const void *buf, size_t size);

#endif // PROCESS_H
