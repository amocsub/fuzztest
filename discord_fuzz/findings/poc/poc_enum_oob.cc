// PoC: Out-of-range enum values stored verbatim
#define DISCORDPP_IMPLEMENTATION
#include "/home/user/fuzztest/discord_fuzz/sdk/include/discordpp.h"
#include <cstdio>
#include <cstring>

int main() {
    printf("=== Out-of-Range Enum Value Acceptance PoC ===\n\n");
    int vulns = 0;

    // ActivityTypes: valid range 0-6
    // 0=Playing, 1=Streaming, 2=Listening, 3=Watching, 4=CustomStatus, 5=Competing, 6=HangStatus
    {
        discordpp::Activity act;
        act.SetName("Test");

        // Cast invalid value as enum
        act.SetType(static_cast<discordpp::ActivityTypes>(99));
        int stored = static_cast<int>(act.Type());
        bool v = (stored == 99);
        if (v) vulns++;
        printf("[ActivityTypes = 99]  stored=%d  %s\n", stored,
               v ? "VULN: out-of-range ActivityType accepted" : "OK: rejected");

        act.SetType(static_cast<discordpp::ActivityTypes>(-1));
        stored = static_cast<int>(act.Type());
        v = (stored == -1);
        if (v) vulns++;
        printf("[ActivityTypes = -1]  stored=%d  %s\n", stored,
               v ? "VULN: negative ActivityType accepted" : "OK: rejected");

        act.SetType(static_cast<discordpp::ActivityTypes>(2147483647));
        stored = static_cast<int>(act.Type());
        v = (stored == 2147483647);
        if (v) vulns++;
        printf("[ActivityTypes = INT_MAX]  stored=%d  %s\n", stored,
               v ? "VULN: INT_MAX ActivityType accepted" : "OK: rejected");
    }

    // ActivityPartyPrivacy: valid 0=Private, 1=Public
    {
        discordpp::ActivityParty p;
        p.SetPrivacy(static_cast<discordpp::ActivityPartyPrivacy>(99));
        int stored = static_cast<int>(p.Privacy());
        bool v = (stored == 99);
        if (v) vulns++;
        printf("[ActivityPartyPrivacy = 99]  stored=%d  %s\n", stored,
               v ? "VULN: out-of-range privacy accepted" : "OK: rejected");
    }

    // StatusDisplayTypes enum
    {
        discordpp::Activity act;
        act.SetStatusDisplayType(static_cast<discordpp::StatusDisplayTypes>(255));
        auto stored = act.StatusDisplayType();
        bool v = stored && (static_cast<int>(*stored) == 255);
        if (v) vulns++;
        printf("[StatusDisplayTypes = 255]  stored=%d  %s\n",
               stored ? static_cast<int>(*stored) : -1,
               v ? "VULN: out-of-range StatusDisplayType accepted" : "OK: rejected");
    }

    // ActivityInvite action type
    {
        discordpp::ActivityInvite inv;
        inv.SetType(static_cast<discordpp::ActivityActionTypes>(999));
        int stored = static_cast<int>(inv.Type());
        bool v = (stored == 999);
        if (v) vulns++;
        printf("[ActivityActionTypes = 999]  stored=%d  %s\n", stored,
               v ? "VULN: out-of-range action type accepted" : "OK: rejected");
    }

    printf("\nResult: %d/6 out-of-range enum values accepted\n", vulns);
    return vulns > 0 ? 1 : 0;
}
