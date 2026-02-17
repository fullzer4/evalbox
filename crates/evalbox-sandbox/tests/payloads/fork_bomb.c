// =============================================================================
// Fork Bomb - Process Limit (max_pids) Validation
// =============================================================================
//
// WHAT IS A FORK BOMB:
//   A fork bomb is a denial-of-service attack that rapidly creates processes
//   until the system runs out of resources. The classic bash fork bomb is:
//   :(){ :|:& };:
//
// WHY IT'S DANGEROUS:
//   1. Exhausts process table entries (kernel memory)
//   2. Consumes all available PIDs
//   3. System becomes unresponsive
//   4. Can crash the entire host if not limited
//   5. Often used as first step in more complex attacks
//
// SANDBOX PROTECTION:
//   The sandbox uses cgroup pids.max or RLIMIT_NPROC to limit the number
//   of processes that can be created inside the sandbox. This prevents
//   fork bombs from affecting the host system.
//
// WHY THIS PAYLOAD:
//   This payload tests that the process limit is properly enforced.
//   It attempts to create many child processes. A secure sandbox must
//   limit this and cause fork() to fail with EAGAIN.
//
// EXPECTED RESULT:
//   fork() should fail after reaching the configured limit (e.g., 64 PIDs).
//   The payload returns 1 when the limit is reached (expected behavior).
//   Returns 0 if it creates 1000 processes (limit NOT enforced - BAD).
//
// REFERENCES:
//   - https://en.wikipedia.org/wiki/Fork_bomb
//   - cgroups pids controller: https://docs.kernel.org/admin-guide/cgroup-v2.html
//
// =============================================================================

#include <unistd.h>
#include <sys/wait.h>
#include <stdio.h>

int main(void) {
    int count = 0;

    // Try to fork many processes
    // A properly configured sandbox should stop us well before 1000
    for (int i = 0; i < 1000; i++) {
        pid_t pid = fork();

        if (pid < 0) {
            // Fork failed - limit reached (EXPECTED)
            // This is the secure behavior
            printf("Fork limit reached after %d forks\n", count);
            return 1;
        } else if (pid == 0) {
            // Child: just sleep (won't exit on its own)
            sleep(60);
            _exit(0);
        } else {
            // Parent: count successful forks
            count++;
        }
    }

    // If we reach here, the limit wasn't enforced - VULNERABLE!
    printf("ERROR: Created %d processes without limit\n", count);
    return 0;
}
