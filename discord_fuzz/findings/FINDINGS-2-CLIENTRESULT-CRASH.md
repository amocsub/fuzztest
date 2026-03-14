# Security Finding #2: Null Pointer Dereference in Discord_ClientResult_SetError()

**Severity:** Medium (Denial of Service / Crash)
**Component:** Discord Social SDK v1.8.14587 (Linux x86-64)
**API Affected:** `Discord_ClientResult_SetError()` and all `Discord_ClientResult_Set*()` functions
**Found via:** Fuzzing (AFL++ with AddressSanitizer)
**Date:** 2026-03-14
**CWE:** CWE-476 (NULL Pointer Dereference)

---

## Summary

The C API of the Discord Social SDK exports setter functions for `Discord_ClientResult` (`Discord_ClientResult_SetError`, `Discord_ClientResult_SetResponseBody`, etc.) but does **not** provide a corresponding initialization function (`Discord_ClientResult_Init`). When a developer zero-initializes the struct and calls any setter, a **null pointer dereference (SIGSEGV)** occurs at offset `0x8` inside an internal `std::string` operation.

This causes a **crash** (Denial of Service) in any application that:
- Uses the C API directly, AND
- Attempts to construct a `ClientResult` to pass to its own test/mock callbacks

---

## Technical Details

### Root Cause

The `Discord_ClientResult` struct contains an internal `std::string` field (from LLVM libc++). When the struct is zero-initialized (`Discord_ClientResult result{}`), the string's internal SSO flag pointer is `NULL`. Calling `Discord_ClientResult_SetError()` triggers a **move assignment** into the uninitialized `std::string`, which reads the `__is_long()` bit at offset 8 from the null base pointer.

### Stack Trace (AddressSanitizer)

```
==30026==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000008
The signal is caused by a READ memory access.

#0  std::__1::basic_string::__is_long() const
    discord_partner_sdk/discord_common/.../libcxx/include/string:1575:33
#1  std::__1::basic_string::__move_assign()
    discord_partner_sdk/discord_common/.../libcxx/include/string:2456:7
#2  std::__1::basic_string::operator=(std::string&&)
    discord_partner_sdk/discord_common/.../libcxx/include/string:2482:5
#3  Discord_ClientResult_SetError()
    discord_partner_sdk/public/cdiscord.cpp:999:67
#4  main
    test_clientresult_crash.cc:19:5
```

**Crash address:** `0x000000000008` — offset 8 from NULL (SSO flag byte of `std::string`)

---

## Proof of Concept

```c
#include "cdiscord.h"
#include <string.h>

int main() {
    Discord_ClientResult result = {0};  // Zero-initialized - NO init function available

    const char* err_msg = "test error";
    Discord_String err = { (uint8_t*)err_msg, strlen(err_msg) };

    Discord_ClientResult_SetError(&result, err);  // CRASH: SIGSEGV at 0x8
    return 0;
}
```

**Reproduces consistently** with both the debug and release builds of `libdiscord_partner_sdk.so`.

---

## Impact

### Affected Scenario
1. **Direct C API users**: Developers writing game integrations in C (not C++) may attempt to initialize `Discord_ClientResult` on the stack/heap and use the setter functions, causing a crash.
2. **Unit testing**: Developers creating mock callbacks that construct synthetic `ClientResult` objects for testing will encounter this crash.
3. **Fuzzer-assisted discovery**: Any fuzzer (AFL, libFuzzer, OSS-Fuzz) targeting the C API will immediately trigger this crash, preventing further exploration of `ClientResult`-using code paths.

### Non-Exploitability Note
Under normal usage, `Discord_ClientResult*` objects are only provided by the SDK to application callbacks and are never constructed by the application. However, the **inconsistency in the API** (providing setters without an initializer) creates a footgun that will cause crashes for developers using the raw C API.

---

## Missing Parity

| Type | Has `_Init()` | Has `_Drop()` | Has `_Set*()` |
|------|--------------|--------------|--------------|
| `Discord_Activity` | ✅ `Discord_Activity_Init` | ✅ | ✅ |
| `Discord_ActivityButton` | ✅ `Discord_ActivityButton_Init` | ✅ | ✅ |
| `Discord_ActivityAssets` | ✅ `Discord_ActivityAssets_Init` | ✅ | ✅ |
| `Discord_ActivityParty` | ✅ `Discord_ActivityParty_Init` | ✅ | ✅ |
| **`Discord_ClientResult`** | ❌ **MISSING** | ✅ | ✅ |

All other similar types provide `_Init()` functions. `Discord_ClientResult` is the **only** type with setter functions but no corresponding initializer.

---

## Recommended Fix

Add a `Discord_ClientResult_Init()` function to properly initialize the struct:

```c
// Proposed addition to cdiscord.h
DISCORD_API void Discord_ClientResult_Init(Discord_ClientResult* self);

// And document that all setter functions require a properly initialized struct.
```

Additionally, the documentation should explicitly state:
> **Warning**: `Discord_ClientResult` objects must not be constructed directly. They are only provided by the SDK to callback functions.

---

## Discovery Methodology

```
Tool: AFL++ 4.09c with AddressSanitizer + UBSan
Compiler: afl-clang-fast++ (Clang 17 / Ubuntu)
SDK: Discord Social SDK v1.8.14587 Linux release + debug .so
Fuzzer config: Persistent mode, -M main / -S slave1
Runtime: ~9M executions across ~5 minutes
Finding: Crash in seed_result corpus element → confirmed reproducible
```

---

## Files

- `poc/poc_clientresult_crash.cc` — Standalone proof-of-concept that crashes
- `../corpus/seed_result` — AFL++ seed that triggered investigation
- `../fuzz_discord_activity.cc` — Full fuzzing harness
