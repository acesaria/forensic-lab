#include "utils.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

int read_file(const char *path, unsigned char **buf, size_t *len) {
    struct stat st;
    int fd, saved_errno;
    void *data;

    if (stat(path, &st) < 0) {
        return -1;
    }

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    data = malloc(st.st_size);
    if (!data) {
        close(fd);
        errno = ENOMEM;
        return -1;
    }

    if (read(fd, data, st.st_size) != st.st_size) {
        saved_errno = errno;
        free(data);
        close(fd);
        errno = saved_errno;
        return -1;
    }

    close(fd);
    *buf = data;
    *len = st.st_size;
    return 0;
}

char* get_absolute_path(const char* path) {
    char* abs_path = realpath(path, NULL);
    if (!abs_path) {
        fprintf(stderr, "[!] Failed to resolve path: %s\n", path);
        fprintf(stderr, "[!] Error: %s\n", strerror(errno));
        return NULL;
    }
    return abs_path;
}

/*
  Write a payload to a specified process at a given offset using the procfs mem file.
  
  - address: The memory address to write to
  - pid: The pid of the target process
  - payload: Pointer to data to write
  - len: Number of bytes to write (IMPORTANT: don't use strlen!)
*/
int procfs_proc_mem_write(long address, long pid, const void *payload, size_t len) 
{
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "/proc/%ld/mem", pid);
    
    // Open for writing
    FILE *file = fopen(filepath, "r+");
    if (!file) {
        perror("fopen");
        return -1;
    }
    
    // Seek to target address
    if (fseek(file, address, SEEK_SET) != 0) {
        perror("fseek");
        fclose(file);
        return -1;
    }
    
    // Write payload (using len, NOT strlen!)
    size_t written = fwrite(payload, 1, len, file);
    fclose(file);
    
    if (written != len) {
        fprintf(stderr, "fwrite: wrote %zu bytes, expected %zu\n", written, len);
        return -1;
    }
    
    return 0;
}


/*
  Read data from a specified process at a given offset using the procfs mem file.
  
  - address: The memory address to read from
  - pid: The pid of the target process
  - buf: Buffer to store read data (will be modified)
  - len: Number of bytes to read
*/
int procfs_proc_mem_read(long address, long pid, void *buf, size_t len) 
{
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "/proc/%ld/mem", pid);
    
    // Open for reading
    FILE *file = fopen(filepath, "r");
    if (!file) {
        perror("fopen");
        return -1;
    }
    
    // Seek to target address
    if (fseek(file, address, SEEK_SET) != 0) {
        perror("fseek");
        fclose(file);
        return -1;
    }
    
    // Read data
    size_t nread = fread(buf, 1, len, file);
    fclose(file);
    
    if (nread != len) {
        fprintf(stderr, "fread: read %zu bytes, expected %zu\n", nread, len);
        return -1;
    }
    
    return 0;
}

