//
// Created by anto on 07/01/26.
//

#ifndef PTRACE_UTILS_H
#define PTRACE_UTILS_H

#include <sys/types.h>
#include <sys/user.h>

// Attach/Detach
int ptrace_attach(pid_t pid);      // attach + wait
int ptrace_detach(pid_t pid);

// Registri
int ptrace_getregs(pid_t pid, struct user_regs_struct *regs);
int ptrace_setregs(pid_t pid, const struct user_regs_struct *regs);

// Memoria (read/write buffer completi)
int ptrace_read(pid_t pid, unsigned long addr, void *buf, size_t len);
int ptrace_write(pid_t pid, unsigned long addr, const void *buf, size_t len);

// Esecuzione
int ptrace_cont(pid_t pid, int signal);
int ptrace_step(pid_t pid);        // singlestep (serve per mmap syscall)

#endif /* PTRACE_UTILS_H */
