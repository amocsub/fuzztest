// PoC: URI Scheme Injection via SetCustomSchemeParam
// The customSchemeParam is injected into: <value>:/authorize/callback
// Injecting "://" or "evil.com" could produce malformed or hijacked redirect URIs
#define DISCORDPP_IMPLEMENTATION
#include "/home/user/fuzztest/discord_fuzz/sdk/include/discordpp.h"
#include <cstdio>
#include <string>
#include <vector>

int main() {
    printf("=== CustomSchemeParam URI Injection PoC ===\n\n");
    int vulns = 0;

    struct Test { std::string input; std::string risk; };
    std::vector<Test> tests = {
        {"evil.com/authorize/callback?stolen=",  "open redirect - appends to legit scheme"},
        {"mygame://evil.com",                    "scheme://host hijack"},
        {"mygame\r\nLocation: https://evil.com", "CRLF + redirect injection"},
        {"mygame\x00hidden",                     "null byte truncation"},
        {"mygame://normal://evil.com",           "double-scheme confusion"},
        {"javascript",                           "produces javascript:/authorize/callback (XSS)"},
        {"data",                                 "produces data:/authorize/callback"},
        {std::string(512, 'A'),                  "512 char scheme (overflow?)"},
    };

    discordpp::AuthorizationArgs args;
    args.SetClientId(1482163567053766686ULL);

    for (auto& t : tests) {
        args.SetCustomSchemeParam(t.input);
        auto stored = args.CustomSchemeParam();
        bool vuln = stored && (*stored == t.input);
        if (vuln) vulns++;
        printf("[%s] %-50s  stored=%s\n",
               vuln ? "VULN" : "SAFE",
               t.risk.c_str(),
               vuln ? "verbatim" : "sanitized");
    }

    printf("\nResult: %d/%zu injection vectors in CustomSchemeParam\n", vulns, tests.size());
    return vulns > 0 ? 1 : 0;
}
