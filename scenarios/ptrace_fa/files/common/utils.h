#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>


int read_file(const char *path, unsigned char **buf, size_t *len);
char* get_absolute_path(const char* path);

static inline size_t align_to_word(size_t size) {
    return ((size + 7) / 8) * 8;
}

int procfs_proc_mem_write(long address, long pid, const void *payload, size_t len);
int procfs_proc_mem_read(long address, long pid, void *buf, size_t len);
int procfs_proc_mem_exec(long address, long pid);


#endif
