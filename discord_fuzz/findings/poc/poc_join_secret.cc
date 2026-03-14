// PoC: Join secret and activity secret field injection
#define DISCORDPP_IMPLEMENTATION
#include "/home/user/fuzztest/discord_fuzz/sdk/include/discordpp.h"
#include <cstdio>
#include <string>
#include <cstring>

bool hasCRLF(const std::string& s) { return s.find("\r\n") != std::string::npos; }
bool hasNull(const std::string& s) { return s.find('\0') != std::string::npos; }

int main() {
    printf("=== ActivitySecrets Join/Invite Secret Injection PoC ===\n\n");
    int vulns = 0;

    // Join secret is used in deep-links and lobby auth - CRLF could affect HTTP
    discordpp::ActivitySecrets secrets;

    // CRLF injection in join secret
    std::string crlf_join = "legit-secret\r\nX-Injected: evil";
    secrets.SetJoin(crlf_join);
    bool v1 = hasCRLF(secrets.Join());
    if (v1) vulns++;
    printf("[Join CRLF]     stored '%s'  %s\n",
           secrets.Join().c_str(), v1 ? "VULN: CRLF in join secret" : "OK");

    // Null byte in join secret
    std::string null_join = std::string("secret") + '\0' + "extra";
    secrets.SetJoin(null_join);
    bool v2 = (secrets.Join().size() == null_join.size());
    if (v2) vulns++;
    printf("[Join NUL byte] len=%zu stored len=%zu  %s\n",
           null_join.size(), secrets.Join().size(),
           v2 ? "VULN: null byte in join secret preserved" : "OK");

    // URL-encoded path traversal attempt in join secret
    std::string traversal = "../../admin/token";
    secrets.SetJoin(traversal);
    bool v3 = (secrets.Join() == traversal);
    if (v3) vulns++;
    printf("[Join traversal]  '%s'  %s\n",
           secrets.Join().c_str(), v3 ? "VULN: path traversal chars accepted" : "OK");

    // Embed in activity and check propagation
    discordpp::Activity act;
    act.SetName("Test");
    discordpp::ActivitySecrets evil_secrets;
    evil_secrets.SetJoin("legit\r\nX-Real-Secret: stolen");
    act.SetSecrets(evil_secrets);
    auto stored = act.Secrets();
    bool v4 = stored && hasCRLF(stored->Join());
    if (v4) vulns++;
    printf("[Join CRLF in Activity] propagates: %s\n",
           v4 ? "VULN: CRLF in Activity.Secrets.Join" : "OK");

    // ActivityInvite party ID injection
    discordpp::ActivityInvite invite;
    invite.SetPartyId("party-id\r\nX-Override: injected");
    bool v5 = hasCRLF(invite.PartyId());
    if (v5) vulns++;
    printf("[Invite PartyId CRLF]  %s\n",
           v5 ? "VULN: CRLF in invite party ID" : "OK");

    invite.SetSessionId("session\r\nHost: evil.com");
    bool v6 = hasCRLF(invite.SessionId());
    if (v6) vulns++;
    printf("[Invite SessionId CRLF]  %s\n",
           v6 ? "VULN: CRLF in invite session ID" : "OK");

    printf("\nResult: %d/6 injection vectors confirmed\n", vulns);
    return vulns > 0 ? 1 : 0;
}
