// PoC: No validation of ActivityParty size constraints
#define DISCORDPP_IMPLEMENTATION
#include "/home/user/fuzztest/discord_fuzz/sdk/include/discordpp.h"
#include <cstdio>

int main() {
    printf("=== ActivityParty Size Validation PoC ===\n\n");

    discordpp::ActivityParty party;
    int vulns = 0;

    // Docs say CurrentSize "must be at least 1"
    party.SetCurrentSize(-1);
    int32_t cs = party.CurrentSize();
    bool v1 = (cs == -1);
    if (v1) vulns++;
    printf("[CurrentSize = -1]     stored: %d  %s\n", cs, v1 ? "VULN: negative accepted" : "OK: rejected");

    party.SetCurrentSize(0);
    cs = party.CurrentSize();
    bool v2 = (cs == 0);
    if (v2) vulns++;
    printf("[CurrentSize = 0]      stored: %d  %s\n", cs, v2 ? "VULN: 0 accepted (doc says >=1)" : "OK: rejected");

    party.SetCurrentSize(-2147483648);  // INT_MIN
    cs = party.CurrentSize();
    bool v3 = (cs == -2147483648);
    if (v3) vulns++;
    printf("[CurrentSize = INT_MIN] stored: %d  %s\n", cs, v3 ? "VULN: INT_MIN accepted" : "OK: rejected");

    // Docs say MaxSize "must be at least 0"
    party.SetMaxSize(-1);
    int32_t ms = party.MaxSize();
    bool v4 = (ms == -1);
    if (v4) vulns++;
    printf("[MaxSize = -1]         stored: %d  %s\n", ms, v4 ? "VULN: negative accepted" : "OK: rejected");

    // MaxSize < CurrentSize - logical inconsistency
    party.SetCurrentSize(10);
    party.SetMaxSize(1);
    bool v5 = (party.CurrentSize() > party.MaxSize());
    if (v5) vulns++;
    printf("[CurrentSize=10 > MaxSize=1]  stored: cur=%d max=%d  %s\n",
           party.CurrentSize(), party.MaxSize(),
           v5 ? "VULN: current > max accepted (logically impossible party)" : "OK: rejected");

    // Timestamps: end < start
    discordpp::ActivityTimestamps ts;
    ts.SetStart(9999999999ULL);
    ts.SetEnd(1ULL);  // End before start
    bool v6 = (ts.End() < ts.Start());
    if (v6) vulns++;
    printf("[Timestamps End < Start]      start=%llu end=%llu  %s\n",
           (unsigned long long)ts.Start(), (unsigned long long)ts.End(),
           v6 ? "VULN: end < start accepted" : "OK: rejected");

    printf("\nResult: %d/6 constraint violations confirmed\n", vulns);
    return vulns > 0 ? 1 : 0;
}
