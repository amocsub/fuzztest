// Proof of Concept: NULL Pointer Dereference in Discord_ClientResult_SetError()
// Discord Social SDK v1.8.14587
//
// Demonstrates that calling Discord_ClientResult_SetError() on a zero-initialized
// Discord_ClientResult struct causes a SIGSEGV (crash) at address 0x8.
//
// The SDK provides setter functions for Discord_ClientResult but NO init function,
// unlike all other similar types (Discord_Activity, Discord_ActivityButton, etc.)
//
// Build:
//   gcc -g -I../../sdk/include poc_clientresult_crash.c \
//       -L../../build -ldiscord_partner_sdk \
//       -Wl,-rpath,../../build -o poc_crash
//
// Or with ASAN:
//   clang -fsanitize=address -g -I../../sdk/include poc_clientresult_crash.c \
//       -L../../build -ldiscord_partner_sdk \
//       -Wl,-rpath,../../build -o poc_crash_asan
//
// Run:
//   LD_LIBRARY_PATH=../../build ./poc_crash

#include "../../sdk/include/cdiscord.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    printf("Discord SDK ClientResult Crash PoC\n");
    printf("====================================\n\n");

    printf("[*] Checking for Init functions on other types...\n");
    // These all work fine because they have _Init functions:
    Discord_Activity act = {0};
    Discord_Activity_Init(&act);
    printf("    Discord_Activity_Init() - OK\n");

    Discord_ActivityButton btn = {0};
    Discord_ActivityButton_Init(&btn);
    printf("    Discord_ActivityButton_Init() - OK\n");
    Discord_ActivityButton_Drop(&btn);

    Discord_Activity_Drop(&act);

    printf("\n[*] Now testing Discord_ClientResult...\n");
    printf("    No Discord_ClientResult_Init() exists in the API!\n");
    printf("    Attempting zero-init + SetError...\n\n");

    // Zero-initialize (no Init function available)
    Discord_ClientResult result;
    memset(&result, 0, sizeof(result));

    const char* err_msg = "application error";
    Discord_String err_str;
    err_str.ptr  = (uint8_t*)err_msg;
    err_str.size = strlen(err_msg);

    printf("[!] Calling Discord_ClientResult_SetError()...\n");
    fflush(stdout);

    // CRASH HERE: SIGSEGV at address 0x000000000008
    // The internal std::string is uninitialized (null ptr), and SetError
    // tries to move-assign into it, reading the SSO flag at offset 8.
    Discord_ClientResult_SetError(&result, err_str);

    printf("[!] Should not reach here - expected SIGSEGV\n");
    return 0;
}
