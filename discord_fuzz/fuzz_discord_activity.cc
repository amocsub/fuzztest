// AFL++ fuzzing harness for Discord Social SDK
// Targets Activity, ActivityAssets, ActivityInvite, AuthorizationArgs,
// ClientCreateOptions, and related data-processing APIs.
//
// Build:  bash build.sh
// Run:    afl-fuzz -i corpus -o findings -- ./build/fuzz_discord_activity @@
//
// App ID: 1482163567053766686

#include <cassert>
#include <climits>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include "sdk/include/cdiscord.h"
// Pull in both declarations AND implementations (single-header style)
#define DISCORDPP_IMPLEMENTATION
#include "sdk/include/discordpp.h"

// ---------------------------------------------------------------------------
// Helper: split a flat byte buffer into N roughly-equal string slices
// ---------------------------------------------------------------------------
static std::vector<std::string> SplitInput(const uint8_t* data, size_t size,
                                           size_t n) {
    std::vector<std::string> parts(n);
    if (size == 0 || n == 0) return parts;
    size_t chunk = size / n;
    size_t rem   = size % n;
    size_t off   = 0;
    for (size_t i = 0; i < n; ++i) {
        size_t len = chunk + (i < rem ? 1 : 0);
        if (off + len > size) len = size - off;
        parts[i].assign(reinterpret_cast<const char*>(data + off), len);
        off += len;
    }
    return parts;
}

// ---------------------------------------------------------------------------
// Fuzz Activity + ActivityAssets + ActivityTimestamps + ActivityParty +
//      ActivitySecrets + ActivityButton
// ---------------------------------------------------------------------------
static void FuzzActivity(const std::vector<std::string>& s) {
    discordpp::Activity act;

    act.SetName(s[0]);
    act.SetType(static_cast<discordpp::ActivityTypes>(
        static_cast<uint8_t>(s[0].empty() ? 0 : (uint8_t)s[0][0]) % 7));
    if (!s[1].empty()) act.SetState(s[1]);
    if (!s[2].empty()) act.SetDetails(s[2]);
    if (!s[3].empty()) act.SetStateUrl(s[3]);
    if (!s[4].empty()) act.SetDetailsUrl(s[4]);

    // Assets
    discordpp::ActivityAssets assets;
    if (!s[5].empty())  assets.SetLargeImage(s[5]);
    if (!s[6].empty())  assets.SetLargeText(s[6]);
    if (!s[7].empty())  assets.SetSmallImage(s[7]);
    if (!s[8].empty())  assets.SetSmallText(s[8]);
    if (!s[9].empty())  assets.SetLargeUrl(s[9]);
    if (!s[10].empty()) assets.SetSmallUrl(s[10]);
    if (!s[11].empty()) assets.SetInviteCoverImage(s[11]);
    act.SetAssets(std::move(assets));

    // Timestamps
    discordpp::ActivityTimestamps ts;
    uint64_t start = 0, end = 0;
    if (s[12].size() >= 8) memcpy(&start, s[12].data(), 8);
    if (s[13].size() >= 8) memcpy(&end,   s[13].data(), 8);
    if (start) ts.SetStart(start);
    if (end)   ts.SetEnd(end);
    act.SetTimestamps(std::move(ts));

    // Party
    discordpp::ActivityParty party;
    if (!s[14].empty()) party.SetId(s[14]);
    int32_t cur = 0, max_sz = 0;
    if (s[15].size() >= 4) memcpy(&cur,    s[15].data(), 4);
    if (s[16].size() >= 4) memcpy(&max_sz, s[16].data(), 4);
    party.SetCurrentSize(cur);
    party.SetMaxSize(max_sz);
    party.SetPrivacy(static_cast<discordpp::ActivityPartyPrivacy>(
        !s[17].empty() ? (uint8_t)s[17][0] % 2 : 0));
    act.SetParty(std::move(party));

    // Secrets
    discordpp::ActivitySecrets secrets;
    secrets.SetJoin(s[18]);
    act.SetSecrets(std::move(secrets));

    // Buttons (AddButton, not SetButtons)
    discordpp::ActivityButton btn;
    btn.SetLabel(s[19]);
    btn.SetUrl(s[20]);
    act.AddButton(std::move(btn));

    // Read-back
    (void)act.Name();
    (void)act.State();
    (void)act.Details();
    (void)act.ApplicationId();
    (void)act.Equals(act);
    (void)act.GetButtons();
}

// ---------------------------------------------------------------------------
// Fuzz ActivityInvite
// ---------------------------------------------------------------------------
static void FuzzActivityInvite(const std::vector<std::string>& s) {
    discordpp::ActivityInvite inv;

    uint64_t sender_id = 0, channel_id = 0, msg_id = 0, app_id = 0;
    if (s[0].size() >= 8) memcpy(&sender_id,  s[0].data(), 8);
    if (s[1].size() >= 8) memcpy(&channel_id, s[1].data(), 8);
    if (s[2].size() >= 8) memcpy(&msg_id,     s[2].data(), 8);
    if (s[3].size() >= 8) memcpy(&app_id,     s[3].data(), 8);

    inv.SetSenderId(sender_id);
    inv.SetChannelId(channel_id);
    inv.SetMessageId(msg_id);
    inv.SetApplicationId(app_id);
    inv.SetType(static_cast<discordpp::ActivityActionTypes>(
        !s[4].empty() ? (uint8_t)s[4][0] % 3 : 0));
    inv.SetPartyId(s[5]);
    inv.SetSessionId(s[6]);
    inv.SetIsValid(!s[7].empty() && s[7][0] != 0);

    (void)inv.SenderId();
    (void)inv.PartyId();
    (void)inv.IsValid();
}

// ---------------------------------------------------------------------------
// Fuzz AuthorizationArgs + AuthorizationCodeChallenge
// ---------------------------------------------------------------------------
static void FuzzAuthArgs(const std::vector<std::string>& s) {
    discordpp::AuthorizationCodeChallenge challenge;
    challenge.SetChallenge(s[0]);
    challenge.SetMethod(discordpp::AuthenticationCodeChallengeMethod::S256);
    (void)challenge.Challenge();
    (void)challenge.Method();

    discordpp::AuthorizationArgs args;
    args.SetClientId(1482163567053766686ULL);
    args.SetScopes(s[2]);
    if (!s[3].empty()) args.SetState(s[3]);
    if (!s[4].empty()) args.SetNonce(s[4]);
    if (!s[5].empty()) args.SetCustomSchemeParam(s[5]);
    args.SetCodeChallenge(challenge);

    (void)args.Scopes();
    (void)args.ClientId();
    (void)args.State();
    (void)args.Nonce();
}

// ---------------------------------------------------------------------------
// Fuzz Activity edge cases — extreme lengths, NULs, invalid enum values,
// integer overflow on party size, adding many buttons
// ---------------------------------------------------------------------------
static void FuzzActivityEdgeCases(const std::vector<std::string>& s) {
    discordpp::Activity act;

    act.SetName(s[0]);

    if (!s[1].empty()) act.SetState(s[1]);
    if (!s[2].empty()) act.SetDetails(s[2]);

    // Intentionally oversized asset strings (SDK limits: LargeImage/SmallImage
    // max 300 chars, LargeText/SmallText 2-128 chars, URLs 1-256 chars)
    discordpp::ActivityAssets assets;
    assets.SetLargeImage(s[3]);
    assets.SetLargeText(s[4]);
    assets.SetSmallImage(s[5]);
    assets.SetSmallText(s[6]);
    act.SetAssets(std::move(assets));

    // Secrets with special chars
    discordpp::ActivitySecrets secrets;
    secrets.SetJoin(s[7]);
    act.SetSecrets(std::move(secrets));

    // Party with extreme int values (INT_MIN, INT_MAX, negative)
    discordpp::ActivityParty party;
    int32_t cur = 0, max_sz = 0;
    if (s[8].size() >= 4) memcpy(&cur,    s[8].data(), 4);
    if (s[9].size() >= 4) memcpy(&max_sz, s[9].data(), 4);
    party.SetCurrentSize(cur);
    party.SetMaxSize(max_sz);
    act.SetParty(std::move(party));

    // Add more than 2 buttons (SDK says max 2 — test what happens with 3+)
    for (size_t i = 10; i < s.size() && i < 14; i += 2) {
        discordpp::ActivityButton btn;
        btn.SetLabel(s[i]);
        if (i + 1 < s.size()) btn.SetUrl(s[i + 1]);
        act.AddButton(std::move(btn));
    }

    (void)act.Name();
    (void)act.GetButtons();
    (void)act.Equals(act);
}

// ---------------------------------------------------------------------------
// Fuzz DeviceAuthorizationArgs
// ---------------------------------------------------------------------------
static void FuzzDeviceAuthArgs(const std::vector<std::string>& s) {
    discordpp::DeviceAuthorizationArgs args;
    uint64_t client_id = 1482163567053766686ULL;
    if (s[0].size() >= 8) memcpy(&client_id, s[0].data(), 8);
    args.SetClientId(client_id);
    args.SetScopes(s[1]);

    (void)args.ClientId();
    (void)args.Scopes();
}

// ---------------------------------------------------------------------------
// Fuzz ClientCreateOptions
// ---------------------------------------------------------------------------
static void FuzzClientCreateOptions(const std::vector<std::string>& s) {
    discordpp::ClientCreateOptions opts;
    opts.SetApiBase(s[0]);
    opts.SetWebBase(s[1]);

    (void)opts.ApiBase();
    (void)opts.WebBase();
}

// ---------------------------------------------------------------------------
// Fuzz Activity clone / copy / move semantics
// This exercises reference counting and potential use-after-free
// ---------------------------------------------------------------------------
static void FuzzActivityCopyMoveSemantics(const std::vector<std::string>& s) {
    // Create and populate
    discordpp::Activity a1;
    a1.SetName(s[0]);
    if (!s[1].empty()) a1.SetState(s[1]);

    discordpp::ActivitySecrets sec;
    sec.SetJoin(s[2]);
    a1.SetSecrets(std::move(sec));

    discordpp::ActivityButton btn;
    btn.SetLabel(s[3]);
    btn.SetUrl(s[4]);
    a1.AddButton(std::move(btn));

    // Copy construct
    discordpp::Activity a2(a1);
    (void)a2.Name();
    (void)a2.GetButtons();

    // Move construct
    discordpp::Activity a3(std::move(a2));
    (void)a3.Name();
    (void)a3.GetButtons();

    // Copy assign
    discordpp::Activity a4;
    a4 = a1;
    (void)a4.Name();

    // Equality check across copies
    (void)a1.Equals(a4);
    (void)a3.Equals(a1);

    // Move assign
    discordpp::Activity a5;
    a5 = std::move(a4);
    (void)a5.Name();
}

// ---------------------------------------------------------------------------
// Main AFL / libFuzzer entry point
// ---------------------------------------------------------------------------
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;

    // First byte selects which API surface to exercise
    uint8_t selector = data[0];
    const uint8_t* payload = data + 1;
    size_t         psize   = size - 1;

    switch (selector % 7) {
        case 0: {
            auto s = SplitInput(payload, psize, 21);
            FuzzActivity(s);
            break;
        }
        case 1: {
            auto s = SplitInput(payload, psize, 8);
            FuzzActivityInvite(s);
            break;
        }
        case 2: {
            auto s = SplitInput(payload, psize, 6);
            FuzzAuthArgs(s);
            break;
        }
        case 3: {
            auto s = SplitInput(payload, psize, 14);
            FuzzActivityEdgeCases(s);
            break;
        }
        case 4: {
            auto s = SplitInput(payload, psize, 2);
            FuzzDeviceAuthArgs(s);
            break;
        }
        case 5: {
            auto s = SplitInput(payload, psize, 2);
            FuzzClientCreateOptions(s);
            break;
        }
        case 6: {
            auto s = SplitInput(payload, psize, 5);
            FuzzActivityCopyMoveSemantics(s);
            break;
        }
    }

    return 0;
}

// Standalone main for manual / non-AFL testing
#ifndef __AFL_FUZZ_TESTCASE_BUF
int main(int argc, char** argv) {
    if (argc > 1) {
        FILE* f = fopen(argv[1], "rb");
        if (!f) return 1;
        fseek(f, 0, SEEK_END);
        long fsz = ftell(f);
        rewind(f);
        std::vector<uint8_t> buf(fsz);
        (void)fread(buf.data(), 1, fsz, f);
        fclose(f);
        LLVMFuzzerTestOneInput(buf.data(), buf.size());
    } else {
        std::vector<uint8_t> buf;
        int c;
        while ((c = fgetc(stdin)) != EOF) buf.push_back(static_cast<uint8_t>(c));
        if (!buf.empty())
            LLVMFuzzerTestOneInput(buf.data(), buf.size());
    }
    return 0;
}
#endif
