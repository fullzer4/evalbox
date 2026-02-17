// =============================================================================
// Success Payload - Control Test
// =============================================================================
//
// PURPOSE:
//   This is a control test payload that simply succeeds. It verifies that
//   the sandbox can execute basic programs correctly before testing that
//   dangerous operations are blocked.
//
// WHY WE NEED THIS:
//   1. Validates the sandbox execution environment works
//   2. Confirms payloads can be injected and executed
//   3. Baseline for comparing with blocked operations
//   4. Catches configuration errors early
//
// WHAT IT DOES:
//   1. Writes a success message to stdout
//   2. Returns exit code 0
//
// EXPECTED RESULT:
//   - Exit code: 0
//   - Stdout contains: "payload executed successfully"
//   - No signals
//
// IF THIS FAILS:
//   - Check that the sandbox can execute static binaries
//   - Verify /work directory is properly mounted
//   - Check that basic syscalls (write, exit) are whitelisted
//
// =============================================================================

#include <unistd.h>

int main(void) {
    const char msg[] = "payload executed successfully\n";
    write(1, msg, sizeof(msg) - 1);
    return 0;
}
