using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Recto.Shared.Capability;
using Recto.Shared.Protocol.V04;
using Xunit;

namespace Recto.Shared.Tests.Capability;

/// <summary>
/// The phone signs a profile card's master attestation only over bytes it has
/// read back against the card (<see cref="ProfileSigningInput"/>): the signing
/// input must be exactly the bootloader's canonical JSON for that card's kind,
/// naming the card's own ids, its request id, a time beside the card's, and
/// this phone's own master key - and its SHA-256 must be the envelope hash the
/// card carries. The golden inputs below were produced by Python's
/// <c>json.dumps(sort_keys=True, separators=(",", ":"))</c>, the encoder
/// <c>recto/bootloader/server.py</c> builds them with, so they also pin
/// byte-parity with the server.
/// </summary>
public class ProfileSigningInputTests
{
    private const string Master =
        "726aae54cc998268f75e6d621e7586f27c0799c063b16d7e46a0d1259d9f0255a8ad9a66b172dd642946289642a1d2c0e18973a87d42f97a01a333c8fc93f09b";
    private const string OtherMaster =
        "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
    private const string Child =
        "97bb66d0fc830e8604252daa8692dfa0ffea76be053b63ced9a2bb0ba16a2414dbecea11dff3f9a717750b81b07cffceb612b374f9c382a1a43740832d6c8689";
    private const string ProfileId = "3f2b6c1e-8a4d-4f0e-9b7a-2c5d1e6f7a80";
    private const long At = 1762500000L;

    // --- golden inputs (Python json.dumps, sort_keys, compact) -------------

    private const string AddId = "0b6a2f3e-5d1c-4e8f-a9b0-7c6d5e4f3a21";
    private const string AddJson =
        "{\"action\":\"profile_add_device\",\"added_at_unix\":1762500000,\"master_pubkey_hex\":\"" + Master
        + "\",\"new_phone_id\":\"phone-new-7c1d\",\"profile_id\":\"" + ProfileId + "\",\"request_id\":\"" + AddId + "\"}";
    private const string AddB64u =
        "eyJhY3Rpb24iOiJwcm9maWxlX2FkZF9kZXZpY2UiLCJhZGRlZF9hdF91bml4IjoxNzYyNTAwMDAwLCJtYXN0ZXJfcHVia2V5X2hleCI6IjcyNmFhZTU0Y2M5OTgyNjhmNzVlNmQ2MjFlNzU4NmYyN2MwNzk5YzA2M2IxNmQ3ZTQ2YTBkMTI1OWQ5ZjAyNTVhOGFkOWE2NmIxNzJkZDY0Mjk0NjI4OTY0MmExZDJjMGUxODk3M2E4N2Q0MmY5N2EwMWEzMzNjOGZjOTNmMDliIiwibmV3X3Bob25lX2lkIjoicGhvbmUtbmV3LTdjMWQiLCJwcm9maWxlX2lkIjoiM2YyYjZjMWUtOGE0ZC00ZjBlLTliN2EtMmM1ZDFlNmY3YTgwIiwicmVxdWVzdF9pZCI6IjBiNmEyZjNlLTVkMWMtNGU4Zi1hOWIwLTdjNmQ1ZTRmM2EyMSJ9";
    private const string AddHash = "5TzQ5RqnE5D8x3ffGheEjxufhm4wyO2ph8dhksSd4Cc";

    private const string RevId = "9d8c7b6a-5f4e-4d3c-b2a1-0f9e8d7c6b5a";
    private const string RevJson =
        "{\"action\":\"profile_revoke_device\",\"master_pubkey_hex\":\"" + Master
        + "\",\"phone_id_to_revoke\":\"phone-old-2e9a\",\"profile_id\":\"" + ProfileId + "\",\"request_id\":\"" + RevId
        + "\",\"revoked_at_unix\":1762500000}";
    private const string RevB64u =
        "eyJhY3Rpb24iOiJwcm9maWxlX3Jldm9rZV9kZXZpY2UiLCJtYXN0ZXJfcHVia2V5X2hleCI6IjcyNmFhZTU0Y2M5OTgyNjhmNzVlNmQ2MjFlNzU4NmYyN2MwNzk5YzA2M2IxNmQ3ZTQ2YTBkMTI1OWQ5ZjAyNTVhOGFkOWE2NmIxNzJkZDY0Mjk0NjI4OTY0MmExZDJjMGUxODk3M2E4N2Q0MmY5N2EwMWEzMzNjOGZjOTNmMDliIiwicGhvbmVfaWRfdG9fcmV2b2tlIjoicGhvbmUtb2xkLTJlOWEiLCJwcm9maWxlX2lkIjoiM2YyYjZjMWUtOGE0ZC00ZjBlLTliN2EtMmM1ZDFlNmY3YTgwIiwicmVxdWVzdF9pZCI6IjlkOGM3YjZhLTVmNGUtNGQzYy1iMmExLTBmOWU4ZDdjNmI1YSIsInJldm9rZWRfYXRfdW5peCI6MTc2MjUwMDAwMH0";
    private const string RevHash = "BWyyPXxlOupBRjI7Sj0Cbf8xR1B0XADkg3GeMPWK8gg";

    private const string PcId = "c0ffee00-1111-4222-8333-444455556666";
    private const string PcJson =
        "{\"candidate_profile_id\":\"" + PcId + "\",\"derivation_coin_type\":1,\"derivation_index\":3,"
        + "\"derivation_purpose\":1919247220,\"display_name\":\"Caf\\u00e9 pseudonym\",\"kind\":\"personal:child\","
        + "\"master_pubkey_hex\":\"" + Master + "\",\"scim_provider\":null,\"theme_hint\":null}";
    private const string PcB64u =
        "eyJjYW5kaWRhdGVfcHJvZmlsZV9pZCI6ImMwZmZlZTAwLTExMTEtNDIyMi04MzMzLTQ0NDQ1NTU1NjY2NiIsImRlcml2YXRpb25fY29pbl90eXBlIjoxLCJkZXJpdmF0aW9uX2luZGV4IjozLCJkZXJpdmF0aW9uX3B1cnBvc2UiOjE5MTkyNDcyMjAsImRpc3BsYXlfbmFtZSI6IkNhZlx1MDBlOSBwc2V1ZG9ueW0iLCJraW5kIjoicGVyc29uYWw6Y2hpbGQiLCJtYXN0ZXJfcHVia2V5X2hleCI6IjcyNmFhZTU0Y2M5OTgyNjhmNzVlNmQ2MjFlNzU4NmYyN2MwNzk5YzA2M2IxNmQ3ZTQ2YTBkMTI1OWQ5ZjAyNTVhOGFkOWE2NmIxNzJkZDY0Mjk0NjI4OTY0MmExZDJjMGUxODk3M2E4N2Q0MmY5N2EwMWEzMzNjOGZjOTNmMDliIiwic2NpbV9wcm92aWRlciI6bnVsbCwidGhlbWVfaGludCI6bnVsbH0";
    private const string PcHash = "1sFv1DpoGjrwM_3NA7gJxDDkon_8xNJyCE0BLmH2QmE";
    private const string PcFullSha256Hex = "7a8d3f878a3ee40f31010ec9370990708c6006c94fe9ea64d555cbf4e99becb7";

    // --- card builders -----------------------------------------------------

    private static PendingRequest AddCard(string b64u, string hash, string? requestId = null,
        string profileId = ProfileId, string newPhoneId = "phone-new-7c1d", long requestedAt = At)
        => new(requestId ?? AddId, PendingRequestKind.ProfileAddDevice, "recto", "profile",
            new PendingRequestContext(0, "(external-agent)", requestedAt, "add a device",
                PayloadHashB64u: hash, CapPayloadB64: b64u,
                AddevProfileId: profileId, AddevNewPhoneId: newPhoneId));

    private static PendingRequest RevCard(string b64u, string hash, string? requestId = null,
        string phoneToRevoke = "phone-old-2e9a", long requestedAt = At)
        => new(requestId ?? RevId, PendingRequestKind.ProfileRevokeDevice, "recto", "profile",
            new PendingRequestContext(0, "(external-agent)", requestedAt, "revoke a device",
                PayloadHashB64u: hash, CapPayloadB64: b64u,
                RevdevProfileId: ProfileId, RevdevPhoneIdToRevoke: phoneToRevoke));

    private static PendingRequest PcCard(string b64u, string hash, int index = 3, string displayName = "Café pseudonym",
        string? themeHint = null)
        => new("pc-request", PendingRequestKind.ProfileCreate, "recto", "profile",
            new PendingRequestContext(0, "(external-agent)", At, "create a profile",
                PayloadHashB64u: hash, CapPayloadB64: b64u,
                CandidateProfileId: PcId, CandidateKind: "personal:child", CandidateDisplayName: displayName,
                CandidateDerivationPurpose: 1919247220L, CandidateDerivationCoinType: 1, CandidateDerivationIndex: index,
                CandidateThemeHint: themeHint, CandidateScimProvider: null));

    /// <summary>A variant input with its own matching envelope hash, so a refusal comes from
    /// the content check under test and not from the hash check.</summary>
    private static (string B64u, string Hash) Encode(string text)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        return (B64u(bytes), B64u(SHA256.HashData(bytes)));
    }

    private static string B64u(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static void Refused(ProfileSigningInput.Verdict v)
    {
        Assert.False(v.Ok);
        Assert.Null(v.Digest);
        Assert.False(string.IsNullOrWhiteSpace(v.Refusal));
    }

    // --- the golden inputs pass, and the digest is the bytes' SHA-256 ----------

    [Fact]
    public void GoldenInputs_AreTheCanonicalJsonOfTheirText()
    {
        Assert.Equal(AddB64u, Encode(AddJson).B64u);
        Assert.Equal(AddHash, Encode(AddJson).Hash);
        Assert.Equal(RevB64u, Encode(RevJson).B64u);
        Assert.Equal(PcB64u, Encode(PcJson).B64u);
    }

    [Fact]
    public void AddDevice_TheBootloadersInputForThisCard_IsSigned()
    {
        var v = ProfileSigningInput.AddDevice(AddCard(AddB64u, AddHash), Master);
        Assert.True(v.Ok, v.Refusal);
        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(AddJson)), v.Digest);
    }

    [Fact]
    public void AddDevice_OwnMasterKeyInUpperCaseHex_StillMatches()
    {
        Assert.True(ProfileSigningInput.AddDevice(AddCard(AddB64u, AddHash), Master.ToUpperInvariant()).Ok);
    }

    [Fact]
    public void RevokeDevice_TheBootloadersInputForThisCard_IsSigned()
    {
        var v = ProfileSigningInput.RevokeDevice(RevCard(RevB64u, RevHash), Master);
        Assert.True(v.Ok, v.Refusal);
        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(RevJson)), v.Digest);
    }

    [Fact]
    public void ProfileCreate_ThePartialForThisCard_IsSignedWithTheChildKeyAdded()
    {
        var v = ProfileSigningInput.ProfileCreate(PcCard(PcB64u, PcHash), Master, Child);
        Assert.True(v.Ok, v.Refusal);
        Assert.Equal(PcFullSha256Hex, Convert.ToHexString(v.Digest!).ToLowerInvariant());
    }

    // --- add device: every way the bytes can differ from the card is refused -------

    [Fact]
    public void AddDevice_BytesThatAreNotAJsonObject_AreRefused()
    {
        var (b64u, hash) = Encode("eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiJ4In0");
        Refused(ProfileSigningInput.AddDevice(AddCard(b64u, hash), Master));
    }

    [Fact]
    public void AddDevice_BytesThatAreNotBase64url_AreRefused()
    {
        Refused(ProfileSigningInput.AddDevice(AddCard("not*base64", AddHash), Master));
    }

    [Fact]
    public void AddDevice_AnExtraKey_IsRefused()
    {
        var (b64u, hash) = Encode(AddJson.Replace("\"action\":", "\"aa\":1,\"action\":"));
        Refused(ProfileSigningInput.AddDevice(AddCard(b64u, hash), Master));
    }

    [Fact]
    public void AddDevice_AMissingKey_IsRefused()
    {
        var (b64u, hash) = Encode(AddJson.Replace("\"added_at_unix\":1762500000,", ""));
        Refused(ProfileSigningInput.AddDevice(AddCard(b64u, hash), Master));
    }

    [Fact]
    public void AddDevice_ADuplicatedKey_IsRefused()
    {
        var (b64u, hash) = Encode(AddJson.Replace("{\"action\":\"profile_add_device\",",
            "{\"action\":\"profile_add_device\",\"action\":\"profile_add_device\","));
        Refused(ProfileSigningInput.AddDevice(AddCard(b64u, hash), Master));
    }

    [Fact]
    public void AddDevice_AnotherAction_IsRefused()
    {
        var (b64u, hash) = Encode(AddJson.Replace("profile_add_device", "profile_revoke_device"));
        Refused(ProfileSigningInput.AddDevice(AddCard(b64u, hash), Master));
    }

    [Fact]
    public void AddDevice_ARevokeCardsInput_IsRefused()
    {
        Refused(ProfileSigningInput.AddDevice(AddCard(RevB64u, RevHash, requestId: RevId), Master));
    }

    [Fact]
    public void AddDevice_AnotherProfile_IsRefused()
    {
        Refused(ProfileSigningInput.AddDevice(AddCard(AddB64u, AddHash, profileId: "another-profile"), Master));
    }

    [Fact]
    public void AddDevice_AnotherNewPhone_IsRefused()
    {
        Refused(ProfileSigningInput.AddDevice(AddCard(AddB64u, AddHash, newPhoneId: "phone-other"), Master));
    }

    [Fact]
    public void AddDevice_AnotherRequestId_IsRefused()
    {
        Refused(ProfileSigningInput.AddDevice(AddCard(AddB64u, AddHash, requestId: "another-request"), Master));
    }

    [Fact]
    public void AddDevice_AnotherMasterKey_IsRefused()
    {
        Refused(ProfileSigningInput.AddDevice(AddCard(AddB64u, AddHash), OtherMaster));
    }

    [Fact]
    public void AddDevice_ATimeFarFromTheCards_IsRefused()
    {
        Refused(ProfileSigningInput.AddDevice(AddCard(AddB64u, AddHash, requestedAt: At + 3600), Master));
    }

    [Fact]
    public void AddDevice_ATimeWrittenAsAString_IsRefused()
    {
        var (b64u, hash) = Encode(AddJson.Replace(":1762500000,", ":\"1762500000\","));
        Refused(ProfileSigningInput.AddDevice(AddCard(b64u, hash), Master));
    }

    [Fact]
    public void AddDevice_ANonCanonicalEncodingOfTheSameFields_IsRefused()
    {
        var (spaced, spacedHash) = Encode(AddJson.Replace("\",\"", "\", \""));
        Refused(ProfileSigningInput.AddDevice(AddCard(spaced, spacedHash), Master));

        // the same six fields, keys out of order
        var reordered = "{\"request_id\":\"" + AddId + "\",\"action\":\"profile_add_device\",\"added_at_unix\":1762500000,"
            + "\"master_pubkey_hex\":\"" + Master + "\",\"new_phone_id\":\"phone-new-7c1d\",\"profile_id\":\"" + ProfileId + "\"}";
        var (b64u, hash) = Encode(reordered);
        Refused(ProfileSigningInput.AddDevice(AddCard(b64u, hash), Master));
    }

    [Fact]
    public void AddDevice_AnEnvelopeHashOfOtherBytes_IsRefused()
    {
        Refused(ProfileSigningInput.AddDevice(AddCard(AddB64u, RevHash), Master));
    }

    [Fact]
    public void AddDevice_OnAnotherKindOfCard_IsRefused()
    {
        var card = AddCard(AddB64u, AddHash) with { Kind = PendingRequestKind.ProfileRevokeDevice };
        Refused(ProfileSigningInput.AddDevice(card, Master));
    }

    // --- revoke device -----------------------------------------------------

    [Fact]
    public void RevokeDevice_AnAddCardsInput_IsRefused()
    {
        Refused(ProfileSigningInput.RevokeDevice(RevCard(AddB64u, AddHash, requestId: AddId), Master));
    }

    [Fact]
    public void RevokeDevice_AnotherPhoneToRevoke_IsRefused()
    {
        Refused(ProfileSigningInput.RevokeDevice(RevCard(RevB64u, RevHash, phoneToRevoke: "phone-other"), Master));
    }

    [Fact]
    public void RevokeDevice_AnotherMasterKey_IsRefused()
    {
        Refused(ProfileSigningInput.RevokeDevice(RevCard(RevB64u, RevHash), OtherMaster));
    }

    // --- profile create ----------------------------------------------------

    [Fact]
    public void ProfileCreate_APartialThatAlreadyNamesAChildKey_IsRefused()
    {
        var (b64u, hash) = Encode(PcJson.Replace("\"derivation_coin_type\"", "\"child_pubkey_hex\":\"" + Child + "\",\"derivation_coin_type\""));
        Refused(ProfileSigningInput.ProfileCreate(PcCard(b64u, hash), Master, Child));
    }

    [Fact]
    public void ProfileCreate_ADerivationIndexOtherThanTheCards_IsRefused()
    {
        Refused(ProfileSigningInput.ProfileCreate(PcCard(PcB64u, PcHash, index: 4), Master, Child));
    }

    [Fact]
    public void ProfileCreate_ADisplayNameOtherThanTheCards_IsRefused()
    {
        Refused(ProfileSigningInput.ProfileCreate(PcCard(PcB64u, PcHash, displayName: "Another name"), Master, Child));
    }

    [Fact]
    public void ProfileCreate_AThemeOtherThanTheCards_IsRefused()
    {
        Refused(ProfileSigningInput.ProfileCreate(PcCard(PcB64u, PcHash, themeHint: "neutral-dark"), Master, Child));
    }

    [Fact]
    public void ProfileCreate_AnExtraKey_IsRefused()
    {
        var (b64u, hash) = Encode(PcJson.Replace("\"candidate_profile_id\"", "\"action\":\"x\",\"candidate_profile_id\""));
        Refused(ProfileSigningInput.ProfileCreate(PcCard(b64u, hash), Master, Child));
    }

    [Fact]
    public void ProfileCreate_AnotherMasterKey_IsRefused()
    {
        Refused(ProfileSigningInput.ProfileCreate(PcCard(PcB64u, PcHash), OtherMaster, Child));
    }

    [Fact]
    public void ProfileCreate_AChildKeyThatIsNotAPublicKey_IsRefused()
    {
        Refused(ProfileSigningInput.ProfileCreate(PcCard(PcB64u, PcHash), Master, "abc"));
    }

    // --- the page: every master-signed profile card goes through the check ------

    [Theory]
    [InlineData("ApproveProfileCreateAsync", "ProfileSigningInput.ProfileCreate(")]
    [InlineData("ApproveProfileAddDeviceAsync", "ProfileSigningInput.AddDevice(")]
    [InlineData("ApproveProfileRevokeDeviceAsync", "ProfileSigningInput.RevokeDevice(")]
    public void EachProfileApproval_ChecksTheInputBeforeTheMasterSigns(string method, string check)
    {
        var body = MethodBody(HomePage(), method);
        var checkAt = body.IndexOf(check, StringComparison.Ordinal);
        var signAt = body.IndexOf("EthSigner.SignDigestAsync(", StringComparison.Ordinal);
        Assert.True(checkAt >= 0, $"{method} does not call {check}");
        Assert.True(signAt > checkAt, $"{method} signs before {check}");
        // the digest signed is the check's, never one hashed from the wire bytes in the page
        Assert.DoesNotContain("SHA256.HashData(", body);
    }

    internal static string HomePage()
    {
        var dir = new DirectoryInfo(System.AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Recto.Shared", "Pages", "Home.razor")))
        {
            dir = dir.Parent;
        }
        Assert.NotNull(dir);
        return File.ReadAllText(Path.Combine(dir!.FullName, "Recto.Shared", "Pages", "Home.razor"));
    }

    /// <summary>The body of the method DECLARED with this name (an access modifier opens the
    /// line), never a call site that names it first.</summary>
    internal static string MethodBody(string source, string method)
    {
        var decl = System.Text.RegularExpressions.Regex.Match(source,
            @"^[ \t]*(?:public|private|internal|protected)\b[^\n;=]*\b" + method + @"\(",
            System.Text.RegularExpressions.RegexOptions.Multiline);
        Assert.True(decl.Success, $"{method} is not declared");
        var open = source.IndexOf('{', decl.Index);
        var depth = 0;
        for (var i = open; i < source.Length; i++)
        {
            if (source[i] == '{') depth++;
            else if (source[i] == '}' && --depth == 0) return source.Substring(open, i - open + 1);
        }
        throw new InvalidOperationException($"{method} has no closing brace");
    }
}
