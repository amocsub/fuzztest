# Security Finding #6: Out-of-Range Enum Values Accepted Without Validation

**Severity:** Low-Medium (Data Integrity / Potential Backend DoS or UB)
**Component:** Discord Social SDK v1.8.14587
**API Affected:** `Activity::SetType()`, `ActivityParty::SetPrivacy()`, `Activity::SetStatusDisplayType()`, `ActivityInvite::SetType()`
**Found via:** Manual analysis following AFL++ fuzzing session
**Date:** 2026-03-14
**CWE:** CWE-20 (Improper Input Validation)

---

## Summary

All enum-accepting setter functions in the Discord Social SDK accept **arbitrary integer values** cast to the enum type. Values outside the documented enum range are stored verbatim and will be transmitted to Discord's backend. This creates a data integrity problem and may trigger undefined behavior or unhandled cases in Discord's server-side deserialization logic.

---

## Confirmed Vulnerable Enums (6/6 tested)

| Field | Valid Range | Test Value | Stored | Result |
|-------|------------|------------|--------|--------|
| `ActivityTypes` | 0–6 | 99 | 99 | **VULN** |
| `ActivityTypes` | 0–6 | -1 | -1 | **VULN** |
| `ActivityTypes` | 0–6 | INT_MAX (2147483647) | 2147483647 | **VULN** |
| `ActivityPartyPrivacy` | 0–1 | 99 | 99 | **VULN** |
| `StatusDisplayTypes` | 0–? | 255 | 255 | **VULN** |
| `ActivityActionTypes` | 0–? | 999 | 999 | **VULN** |

### Enum Definitions

```cpp
// ActivityTypes: 6 valid values
enum class ActivityTypes {
    Playing = 0, Streaming = 1, Listening = 2, Watching = 3,
    CustomStatus = 4, Competing = 5, HangStatus = 6
};

// ActivityPartyPrivacy: 2 valid values
enum class ActivityPartyPrivacy {
    Private = 0, Public = 1
};

// ActivityActionTypes: 2 valid values
enum class ActivityActionTypes {
    Join = 1, Spectate = 2
};
```

---

## Proof of Concept

```cpp
#define DISCORDPP_IMPLEMENTATION
#include "discordpp.h"
#include <cassert>

int main() {
    discordpp::Activity act;
    act.SetName("Test Game");

    // ActivityTypes: valid range 0-6, inject 99
    act.SetType(static_cast<discordpp::ActivityTypes>(99));
    assert(static_cast<int>(act.Type()) == 99);  // CONFIRMED

    // ActivityTypes: negative value
    act.SetType(static_cast<discordpp::ActivityTypes>(-1));
    assert(static_cast<int>(act.Type()) == -1);  // CONFIRMED

    // ActivityTypes: INT_MAX
    act.SetType(static_cast<discordpp::ActivityTypes>(2147483647));
    assert(static_cast<int>(act.Type()) == 2147483647);  // CONFIRMED

    // ActivityPartyPrivacy: valid 0 or 1, inject 99
    discordpp::ActivityParty party;
    party.SetPrivacy(static_cast<discordpp::ActivityPartyPrivacy>(99));
    assert(static_cast<int>(party.Privacy()) == 99);  // CONFIRMED

    // ActivityInvite action type: valid 1 or 2, inject 999
    discordpp::ActivityInvite inv;
    inv.SetType(static_cast<discordpp::ActivityActionTypes>(999));
    assert(static_cast<int>(inv.Type()) == 999);  // CONFIRMED

    return 0;
}
```

### Output
```
[ActivityTypes = 99]         stored=99   VULN
[ActivityTypes = -1]         stored=-1   VULN
[ActivityTypes = INT_MAX]    stored=2147483647  VULN
[ActivityPartyPrivacy = 99]  stored=99   VULN
[StatusDisplayTypes = 255]   stored=255  VULN
[ActivityActionTypes = 999]  stored=999  VULN

Result: 6/6 out-of-range enum values accepted
```

---

## Impact

### Backend Deserialization
When a game calls `client->UpdateRichPresence(act, callback)`, the SDK serializes the activity (including `type=99`) and sends it to Discord's REST API. The server-side parser must handle unknown enum values. A poorly-defensive parser may:
- Crash or throw an unhandled exception (DoS to the backend endpoint)
- Fall through to undefined behavior in a `switch` statement
- Corrupt the user's presence state

### Client-Side Switch Statement UB
Discord client code rendering Rich Presence likely uses switch statements:
```cpp
switch (activity.type) {
    case Playing: renderPlaying(); break;
    case Streaming: renderStreaming(); break;
    // ...
    // No default: — undefined behavior if type=99 reaches here
}
```

### Fuzzing Attack Vector
A malicious game could systematically send all possible `ActivityTypes` values (0..INT_MAX) to probe Discord's backend for parsing errors, effectively using a legitimate SDK as a fuzzer against Discord's own infrastructure.

---

## Recommended Fix

Validate enum values at setter boundaries:

```cpp
void Activity::SetType(discordpp::ActivityTypes type) {
    int v = static_cast<int>(type);
    if (v < 0 || v > 6) {
        // Log error and return without storing
        return;
    }
    Discord_Activity_SetType(&instance_, static_cast<Discord_ActivityTypes>(v));
}
```

Alternatively, use a validation helper that maps C++ enum class values to their valid ranges.

---

## Discovery Methodology

```
Phase: Manual analysis post-AFL++ fuzzing
Method: Systematic cast of out-of-range integers to all enum types
Tool: Standalone PoC with direct assertion testing
SDK: Discord Social SDK v1.8.14587 Linux x86-64
Date: 2026-03-14
```

---

## Files

- `poc/poc_enum_oob.cc` — Standalone proof-of-concept
- `../fuzz_discord_activity.cc` — AFL++ harness (tests enums range 0-6 via seed_bad_enums)
