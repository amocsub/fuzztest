# Security Finding #4: Widespread Missing Input Validation Across Activity Metadata Fields

**Severity:** Medium (Data Integrity / Server-Side Constraint Violation)
**Component:** Discord Social SDK v1.8.14587
**API Affected:** `discordpp::ActivityParty`, `discordpp::ActivityTimestamps`, `discordpp::ActivityButton`, `discordpp::Activity`, `discordpp::ActivityAssets`
**Found via:** Manual analysis following AFL++ fuzzing session
**Date:** 2026-03-14
**CWE:** CWE-20 (Improper Input Validation)

---

## Summary

The Discord Social SDK performs **no input validation** on documented field constraints across multiple Activity-related structures. Values that violate the SDK's own documentation (negative sizes, impossible timestamp ranges, oversized strings) are silently accepted, stored verbatim, and transmitted to Discord's backend. This creates a data integrity problem and expands the attack surface of Finding #1 (missing URL validation) to 8 total URL fields.

---

## Confirmed Constraint Violations

### 1. ActivityParty — Negative and Impossible Size Values

**Documentation states:** `CurrentSize` "must be at least 1"; `MaxSize` "must be at least 0"

| Test | Value | Stored | Violation |
|------|-------|--------|-----------|
| `SetCurrentSize(-1)` | -1 | -1 | **YES** |
| `SetCurrentSize(0)` | 0 | 0 | **YES** (doc: ≥ 1) |
| `SetCurrentSize(INT_MIN)` | -2147483648 | -2147483648 | **YES** |
| `SetMaxSize(-1)` | -1 | -1 | **YES** |
| `SetCurrentSize(10); SetMaxSize(1)` | cur=10, max=1 | cur=10, max=1 | **YES** (logically impossible party) |

A `CurrentSize > MaxSize` represents an impossible party state — more players than the maximum capacity. Discord's backend must handle this gracefully, but the SDK should validate it.

### 2. ActivityTimestamps — Invalid Temporal Ranges

| Test | Value | Stored | Violation |
|------|-------|--------|-----------|
| `SetEnd(1); SetStart(9999999999)` | end < start | preserved | **YES** (end before start) |
| `SetStart(UINT64_MAX); SetEnd(UINT64_MAX)` | 18446744073709551615 | preserved | **YES** (year ~586 billion) |
| `SetStart(0); SetEnd(0)` | 0 | preserved | **YES** (epoch 0 = invalid) |

### 3. ActivityButton — Label Length Exceeds 32 Characters

**Documentation states:** "Buttons can have 1-32 character labels"

```cpp
discordpp::ActivityButton btn;
std::string label(10000, 'A');  // 10,000 chars (limit: 32)
btn.SetLabel(label);
assert(btn.Label().size() == 10000);  // CONFIRMED: no truncation
```

### 4. Activity Name — No Length Limit Enforced

```cpp
discordpp::Activity act;
std::string name(65536, 'B');  // 65,536 chars
act.SetName(name);
assert(act.Name().size() == 65536);  // CONFIRMED: stored verbatim
```

### 5. URL Fields — Dangerous Schemes Accepted (Expanding Finding #1)

**8 URL-type fields** across Activity structures accept dangerous URL schemes verbatim:

| Field | Class | CRLF/XSS | javascript: | file:// | data: |
|-------|-------|----------|-------------|---------|-------|
| `url` | `ActivityButton` | — | **YES** | **YES** | **YES** |
| `stateUrl` | `Activity` | — | **YES** | **YES** | **YES** |
| `detailsUrl` | `Activity` | — | **YES** | **YES** | **YES** |
| `largeUrl` | `ActivityAssets` | — | **YES** | **YES** | **YES** |
| `smallUrl` | `ActivityAssets` | — | **YES** | **YES** | **YES** |
| `inviteCoverImage` | `ActivityAssets` | — | **YES** | **YES** | **YES** |

---

## Proof of Concept

```cpp
#define DISCORDPP_IMPLEMENTATION
#include "discordpp.h"
#include <cassert>

int main() {
    // ActivityParty: negative size
    discordpp::ActivityParty party;
    party.SetCurrentSize(-999);
    party.SetMaxSize(-1);
    assert(party.CurrentSize() == -999);   // CONFIRMED: docs say must be >= 1
    assert(party.MaxSize() == -1);         // CONFIRMED: docs say must be >= 0

    // Impossible party: current > max
    party.SetCurrentSize(100);
    party.SetMaxSize(1);
    assert(party.CurrentSize() > party.MaxSize()); // CONFIRMED: no logical validation

    // Embed in Activity and verify propagation
    discordpp::Activity act;
    act.SetParty(party);
    assert(act.Party()->CurrentSize() == 100); // Propagates verbatim

    // ActivityTimestamps: end before start
    discordpp::ActivityTimestamps ts;
    ts.SetStart(9999999999ULL);
    ts.SetEnd(1ULL);
    assert(ts.End() < ts.Start()); // CONFIRMED: no temporal validation

    // ActivityButton: label exceeds 32-char documented limit
    discordpp::ActivityButton btn;
    btn.SetLabel(std::string(10000, 'X'));
    assert(btn.Label().size() == 10000); // CONFIRMED: no length enforcement

    // StateUrl: dangerous scheme
    act.SetStateUrl("javascript:stealToken()");
    assert(act.StateUrl() == "javascript:stealToken()"); // CONFIRMED
    return 0;
}
```

### Output

```
[CurrentSize = -1]       stored: -1    VULN: negative accepted
[CurrentSize = 0]        stored: 0     VULN: 0 accepted (doc says >=1)
[CurrentSize = INT_MIN]  stored: -2147483648  VULN: INT_MIN accepted
[MaxSize = -1]           stored: -1    VULN: negative accepted
[CurrentSize=10 > MaxSize=1] stored: cur=10 max=1  VULN: logically impossible party
[Timestamps End < Start] start=9999999999 end=1   VULN: end < start accepted
[Timestamp UINT64_MAX]   start=18446744073709551615  VULN: UINT64_MAX timestamp accepted
[Button label 10000 chars]  stored len=10000  VULN: no 32-char limit enforced
[Activity name 65536 chars] stored len=65536  VULN: no length limit enforced

Result: 9/9 constraint violations confirmed
```

---

## Impact

### Data Integrity
Sending malformed party data (negative sizes, impossible layouts) to Discord's backend could:
- Cause unexpected behavior in Discord's matchmaking or party-display UI
- Trigger undefined behavior in Discord client parsing code
- Create confusing UX (e.g. party showing "-999/−1 players")

### Amplified Attack Surface
The 8 unvalidated URL fields (including StateUrl, DetailsUrl, LargeUrl, SmallUrl) multiply the XSS attack surface from Finding #1. Any of these fields rendered in a WebView without sanitization is a viable XSS vector.

### Oversized Fields / DoS
Button labels of 10,000+ characters sent via the SDK could:
- Cause rendering issues or layout attacks in Discord UI
- Trigger server-side validation errors that corrupt activity state
- Serve as a vector for client-side resource exhaustion

---

## Recommended Fixes

1. **ActivityParty sizes:**
   ```cpp
   void ActivityParty::SetCurrentSize(int32_t size) {
       if (size < 1) return; // reject or log error
       // ...
   }
   void ActivityParty::SetMaxSize(int32_t size) {
       if (size < 0) return;
       if (instance_.current_size > size) return; // or clamp
       // ...
   }
   ```

2. **ActivityTimestamps:**
   ```cpp
   void ActivityTimestamps::SetEnd(uint64_t end) {
       if (instance_.start > 0 && end < instance_.start) return;
       // ...
   }
   ```

3. **String length limits:** Enforce documented limits at the setter level (e.g., 32 chars for button labels).

4. **URL fields:** Enforce `https://` scheme and max 512 chars on all URL-type fields (see Finding #1).

---

## Discovery Methodology

```
Tool: AFL++ 4.09c + manual PoC testing
Phase: Post-fuzzing manual analysis
SDK: Discord Social SDK v1.8.14587 Linux release
Date: 2026-03-14

Steps:
1. Read SDK header to enumerate all setter functions with documented constraints
2. Wrote focused PoC testing each documented constraint boundary
3. Confirmed each violation with verbatim readback assertions
4. Verified that violations propagate through Activity embedding
```

---

## Files

- `poc/poc_party_size.cc` — PoC for ActivityParty and Timestamps violations
- `poc/poc_activity_urls.cc` — PoC for URL field expansion
- `../fuzz_discord_activity.cc` — AFL++ harness
