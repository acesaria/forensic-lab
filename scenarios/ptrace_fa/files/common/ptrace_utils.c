//
// Created by anto on 07/01/26.
//

#include "ptrace_utils.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#define MIN(a,b) ((a)<(b)?(a):(b))

int ptrace_attach(pid_t pid) {
    int status;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace ATTACH");
        return -1;
    }

    if (waitpid(pid, &status, WUNTRACED) == -1) {
        perror("waitpid");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    return 0;
}

int ptrace_detach(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        perror("ptrace DETACH");
        return -1;
    }
    return 0;
}

int ptrace_getregs(pid_t pid, struct user_regs_struct *regs) {
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) == -1) {
        perror("ptrace GETREGS");
        return -1;
    }
    return 0;
}

int ptrace_setregs(pid_t pid, const struct user_regs_struct *regs) {
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) == -1) {
        perror("ptrace SETREGS");
        return -1;
    }
    return 0;
}

/**
 * Legge memoria da processo remoto.
 */
int ptrace_read(pid_t pid, unsigned long addr, void *buf, size_t len) {
    unsigned char *dst = buf;
    for (size_t i = 0; i < len; i += 8) {
        size_t chunk = MIN(8, len - i);
        errno = 0;
        long word = ptrace(PTRACE_PEEKTEXT, pid, addr + i, NULL);
        if (word == -1 && errno) {
            perror("PEEKTEXT");
            return -1;
        }
        memcpy(dst + i, &word, chunk);
    }
    return 0;
}


/**
 * Scrive memoria in processo remoto.
 */
int ptrace_write(pid_t pid, unsigned long addr, const void *buf, size_t len) {
    const unsigned char *src = buf;
    for (size_t i = 0; i < len; i += 8) {
        size_t chunk = MIN(8, len - i);
        errno = 0;
        long word = ptrace(PTRACE_PEEKTEXT, pid, addr + i, NULL);
        if (word == -1 && errno) {
            perror("PEEKTEXT");
            return -1;
        }
        memcpy((char*)&word, src + i, chunk);  // Merge solo chunk byte
        if (ptrace(PTRACE_POKETEXT, pid, addr + i, word) == -1) {
            perror("POKETEXT");
            return -1;
        }
    }
    return 0;
}


int ptrace_cont(pid_t pid, int signal) {
    if (ptrace(PTRACE_CONT, pid, NULL, (void*)(long)signal) == -1) {
        perror("ptrace CONT");
        return -1;
    }
    return 0;
}

/**
 * Esegue singolo step (per syscall injection).
 */
int ptrace_step(pid_t pid) {
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) {
        return -1;
    }
    return waitpid(pid, NULL, 0) == pid ? 0 : -1;
}