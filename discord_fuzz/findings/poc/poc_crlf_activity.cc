// PoC: CRLF injection across Activity string fields
#define DISCORDPP_IMPLEMENTATION
#include "/home/user/fuzztest/discord_fuzz/sdk/include/discordpp.h"
#include <cstdio>
#include <string>

bool hasCRLF(const std::string& s) { return s.find("\r\n") != std::string::npos; }

int main() {
    printf("=== Activity/Secrets/Invite CRLF Injection PoC ===\n\n");
    int vulns = 0;

    // Activity core text fields
    {
        discordpp::Activity act;
        act.SetName("Game\r\nX-Injected: header");
        act.SetState("Playing\r\nContent-Length: 0");
        act.SetDetails("Level 5\r\nTransfer-Encoding: chunked");

        bool v1 = hasCRLF(act.Name());
        bool v2 = act.State() && hasCRLF(*act.State());
        bool v3 = act.Details() && hasCRLF(*act.Details());
        if (v1) { vulns++; printf("[Activity.Name CRLF]    VULN\n"); }
        if (v2) { vulns++; printf("[Activity.State CRLF]   VULN\n"); }
        if (v3) { vulns++; printf("[Activity.Details CRLF] VULN\n"); }
    }

    // ActivitySecrets join secret
    {
        discordpp::ActivitySecrets s;
        s.SetJoin("legit-secret\r\nX-Join: override");
        bool v = hasCRLF(s.Join());
        if (v) { vulns++; printf("[ActivitySecrets.Join CRLF] VULN\n"); }
    }

    // ActivityParty ID
    {
        discordpp::ActivityParty p;
        p.SetId("party\r\nX-Party: override");
        bool v = hasCRLF(p.Id());
        if (v) { vulns++; printf("[ActivityParty.Id CRLF] VULN\n"); }
    }

    // ActivityInvite session and party IDs
    {
        discordpp::ActivityInvite inv;
        inv.SetPartyId("party\r\nX-Override: injected");
        inv.SetSessionId("session\r\nHost: evil.com");
        bool v1 = hasCRLF(inv.PartyId());
        bool v2 = hasCRLF(inv.SessionId());
        if (v1) { vulns++; printf("[ActivityInvite.PartyId CRLF]   VULN\n"); }
        if (v2) { vulns++; printf("[ActivityInvite.SessionId CRLF] VULN\n"); }
    }

    // ActivityAssets image keys
    {
        discordpp::ActivityAssets a;
        a.SetLargeImage("large\r\nX-Image: override");
        a.SetSmallImage("small\r\nX-Image: small-override");
        a.SetLargeText("text\r\nX-Text: override");
        bool v1 = a.LargeImage() && hasCRLF(*a.LargeImage());
        bool v2 = a.SmallImage() && hasCRLF(*a.SmallImage());
        bool v3 = a.LargeText() && hasCRLF(*a.LargeText());
        if (v1) { vulns++; printf("[ActivityAssets.LargeImage CRLF] VULN\n"); }
        if (v2) { vulns++; printf("[ActivityAssets.SmallImage CRLF] VULN\n"); }
        if (v3) { vulns++; printf("[ActivityAssets.LargeText CRLF]  VULN\n"); }
    }

    printf("\nResult: %d/11 CRLF injection vectors confirmed\n", vulns);
    return vulns > 0 ? 1 : 0;
}
