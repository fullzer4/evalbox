// =============================================================================
// Fileless Execution via memfd_create + execveat
// =============================================================================
//
// TECHNIQUE:
//   memfd_create() creates an anonymous file in RAM that can hold executable
//   code. Combined with execveat(), this allows executing code without ever
//   writing to the filesystem - a "fileless" attack that bypasses many
//   security controls.
//
// WHY IT'S DANGEROUS:
//   - Bypasses filesystem-based security (AppArmor file rules, Landlock)
//   - No file on disk = harder to detect and forensically analyze
//   - Used by real-world malware and APT groups
//   - Memory-only execution evades antivirus file scanning
//
// ATTACK VECTOR:
//   1. memfd_create() to create anonymous file descriptor
//   2. write() ELF binary or shellcode to the memfd
//   3. execveat() with AT_EMPTY_PATH to execute from fd directly
//   4. Malicious code runs without any filesystem trace
//
// WHY THIS PAYLOAD:
//   This payload attempts fileless execution. A secure sandbox must block
//   either memfd_create or execveat syscalls to prevent this attack vector.
//
// EXPECTED RESULT:
//   Sandbox should block memfd_create or execveat via seccomp (SIGSYS).
//   The current evalbox seccomp whitelist removes both syscalls.
//
// DETECTION:
//   - /proc/PID/exe pointing to "/memfd:NAME (deleted)" is suspicious
//   - eBPF/auditd can detect memfd_create + execveat sequences
//
// REFERENCES:
//   - https://www.aquasec.com/blog/intro-to-fileless-malware-in-containers/
//   - https://www.exploit-db.com/exploits/51693
//   - https://foxtrot-sq.medium.com/detecting-memfd-create-linux-fileless-malware
//
// =============================================================================

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

// memfd_create flags
#define MFD_CLOEXEC 0x0001U

// Minimal "exit 0" ELF binary (x86_64)
// This is a tiny valid ELF that just calls exit(0)
static const unsigned char elf_exit[] = {
    // ELF header
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,  // e_ident
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x3e, 0x00,                          // e_type, e_machine
    0x01, 0x00, 0x00, 0x00,                          // e_version
    0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,  // e_entry
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // e_phoff
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // e_shoff
    0x00, 0x00, 0x00, 0x00,                          // e_flags
    0x40, 0x00, 0x38, 0x00,                          // e_ehsize, e_phentsize
    0x01, 0x00, 0x00, 0x00,                          // e_phnum, e_shentsize
    0x00, 0x00, 0x00, 0x00,                          // e_shnum, e_shstrndx
    // Program header
    0x01, 0x00, 0x00, 0x00,                          // p_type (LOAD)
    0x05, 0x00, 0x00, 0x00,                          // p_flags (R|X)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // p_offset
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,  // p_vaddr
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,  // p_paddr
    0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // p_filesz
    0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // p_memsz
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // p_align
    // Code: mov eax, 60 (exit); xor edi, edi; syscall
    0xb8, 0x3c, 0x00, 0x00, 0x00,  // mov eax, 60
    0x31, 0xff,                    // xor edi, edi
    0x0f, 0x05                     // syscall
};

int main(void) {
    // Step 1: Create anonymous memory file
    int fd = syscall(SYS_memfd_create, "payload", MFD_CLOEXEC);

    if (fd < 0) {
        // memfd_create blocked - sandbox is secure
        return 1;
    }

    // Step 2: Write ELF binary to memory file
    if (write(fd, elf_exit, sizeof(elf_exit)) != sizeof(elf_exit)) {
        close(fd);
        return 1;
    }

    // Step 3: Execute from memory file descriptor
    // AT_EMPTY_PATH allows executing from fd without a path
    char *argv[] = { "memfd_payload", NULL };
    char *envp[] = { NULL };

    // execveat(fd, "", argv, envp, AT_EMPTY_PATH)
    syscall(SYS_execveat, fd, "", argv, envp, 0x1000 /* AT_EMPTY_PATH */);

    // If we get here, execveat was blocked
    close(fd);
    return 1;
}
