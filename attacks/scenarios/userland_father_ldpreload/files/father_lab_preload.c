/*
 * Lab-safe LD_PRELOAD harness inspired by Father as a forensic case study.
 *
 * Safety properties:
 * - no network code
 * - no shell/backdoor
 * - no privilege escalation
 * - no GnuPG/user-data tampering
 * - no hiding/interposition hooks
 *
 * The constructor emits one stderr marker so a benign process can be linked to
 * the preload library in logs while memory/disk artifacts remain observable.
 */

#include <unistd.h>

__attribute__((constructor))
static void father_lab_loaded(void) {
    static const char msg[] = "father_lab_preload_loaded\n";
    (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
}
