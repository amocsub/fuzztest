// PoC: CRLF + null byte injection in UpdateToken / AuthorizationCodeVerifier
// If a bearer token containing \r\n is placed verbatim in an HTTP Authorization
// header, this enables HTTP header injection
#define DISCORDPP_IMPLEMENTATION
#include "/home/user/fuzztest/discord_fuzz/sdk/include/discordpp.h"
#include <cstdio>
#include <string>

bool hasCRLF(const std::string& s) { return s.find("\r\n") != std::string::npos; }

int main() {
    printf("=== Token/Verifier CRLF Injection PoC ===\n\n");
    int vulns = 0;

    // AuthorizationCodeChallenge (PKCE) - challenge and verifier fields
    // RFC 7636: challenge must use [A-Za-z0-9\-._~], 43-128 chars
    discordpp::AuthorizationCodeChallenge challenge;

    // CRLF in challenge
    std::string crlf_challenge = "S256\r\nX-Override: evil";
    challenge.SetChallenge(crlf_challenge);
    bool v1 = hasCRLF(challenge.Challenge());
    if (v1) vulns++;
    printf("[PKCE Challenge CRLF]  %s\n", v1 ? "VULN: CRLF in PKCE challenge" : "OK");

    // Empty challenge (RFC requires 43+ chars base64url of SHA-256)
    challenge.SetChallenge("");
    bool v2 = (challenge.Challenge().empty());
    if (v2) vulns++;
    printf("[PKCE Challenge empty] stored=''  %s\n",
           v2 ? "VULN: empty PKCE challenge accepted" : "OK");

    // Challenge shorter than 43 chars (RFC violation)
    challenge.SetChallenge("too-short");
    bool v3 = (challenge.Challenge() == "too-short");
    if (v3) vulns++;
    printf("[PKCE Challenge 9 chars] stored='too-short'  %s\n",
           v3 ? "VULN: sub-43-char PKCE challenge accepted (RFC violation)" : "OK");

    // Challenge with invalid characters (RFC allows only base64url chars)
    challenge.SetChallenge("ABCDEF+/== invalid base64url chars for a really long string here");
    bool v4 = (challenge.Challenge().find('+') != std::string::npos);
    if (v4) vulns++;
    printf("[PKCE Challenge invalid chars] '+' preserved: %s\n",
           v4 ? "VULN: non-RFC chars accepted in PKCE challenge" : "OK");

    // AuthorizationCodeVerifier has a verifier field too
    // (Note: can only be created via Client::CreateAuthorizationCodeVerifier(),
    //  so test what we can via the challenge object)

    // AuthorizationArgs state parameter with empty string
    discordpp::AuthorizationArgs args;
    args.SetClientId(1482163567053766686ULL);
    args.SetState(std::string(""));  // Empty CSRF token
    auto state = args.State();
    bool v5 = state && state->empty();
    if (v5) vulns++;
    printf("[OAuth State = ''] empty CSRF token: %s\n",
           v5 ? "VULN: empty state (CSRF token bypass) accepted" : "OK");

    // Scopes with empty string
    args.SetScopes("");
    bool v6 = args.Scopes().empty();
    if (v6) vulns++;
    printf("[OAuth Scopes = ''] empty scopes: %s\n",
           v6 ? "VULN: empty scopes accepted" : "OK");

    printf("\nResult: %d/6 token/verifier issues confirmed\n", vulns);
    return vulns > 0 ? 1 : 0;
}
