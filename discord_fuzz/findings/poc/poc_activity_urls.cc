// PoC: URL validation in Activity StateUrl and DetailsUrl fields
#define DISCORDPP_IMPLEMENTATION
#include "/home/user/fuzztest/discord_fuzz/sdk/include/discordpp.h"
#include <cstdio>
#include <string>
#include <vector>

int main() {
    printf("=== Activity StateUrl/DetailsUrl URL Validation PoC ===\n\n");

    struct Test { std::string field; std::string url; std::string risk; };
    std::vector<Test> tests = {
        {"StateUrl",    "javascript:stealToken()",                   "XSS"},
        {"StateUrl",    "file:///etc/passwd",                        "LFI"},
        {"StateUrl",    "data:text/html,<script>alert(1)</script>",  "XSS via data URI"},
        {"DetailsUrl",  "javascript:document.cookie",                "XSS"},
        {"DetailsUrl",  "//evil-phishing.com/fake",                  "phishing"},
        {"LargeUrl",    "javascript:alert(1)",                       "XSS"},
        {"SmallUrl",    "data:image/svg+xml,<svg/onload=alert(1)>",  "XSS via SVG"},
        {"InviteCover", "file:///etc/shadow",                        "LFI"},
    };

    int vulns = 0;
    for (auto& t : tests) {
        discordpp::Activity act;
        act.SetName("Test Game");

        if (t.field == "StateUrl")    act.SetStateUrl(t.url);
        else if (t.field == "DetailsUrl") act.SetDetailsUrl(t.url);

        std::optional<std::string> stored;
        if (t.field == "StateUrl")    stored = act.StateUrl();
        else if (t.field == "DetailsUrl") stored = act.DetailsUrl();
        else if (t.field == "LargeUrl" || t.field == "SmallUrl" || t.field == "InviteCover") {
            discordpp::ActivityAssets assets;
            if (t.field == "LargeUrl")    assets.SetLargeUrl(t.url);
            else if (t.field == "SmallUrl") assets.SetSmallUrl(t.url);
            else assets.SetInviteCoverImage(t.url);

            if (t.field == "LargeUrl")    stored = assets.LargeUrl();
            else if (t.field == "SmallUrl") stored = assets.SmallUrl();
            else stored = assets.InviteCoverImage();
        }

        bool vuln = stored && (*stored == t.url);
        if (vuln) vulns++;
        printf("[%s] %s  stored=%s  %s\n",
               vuln ? "VULN" : "SAFE",
               t.field.c_str(), vuln ? "verbatim" : "sanitized",
               t.risk.c_str());
    }

    printf("\nResult: %d/%zu URL fields accept dangerous schemes\n", vulns, tests.size());
    return vulns > 0 ? 1 : 0;
}
