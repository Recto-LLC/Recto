using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace Recto.Shared.Capability;

/// <summary>One signed term a card shows in words: its label and its value.</summary>
public sealed record SignedTerm(string Label, string Value);

/// <summary>One signed list a card shows value by value. An empty one limits nothing, and the card says "any".</summary>
public sealed record SignedList(string Label, IReadOnlyList<string> Values);

/// <summary>
/// AUDIT DETAILS v2 (2026-08-13) &mdash; the capability_request card's
/// view-model, computed entirely from the decoded
/// <see cref="CapabilityClaims"/> (i.e. from the exact
/// <c>cap_payload_b64</c> bytes the phone signs).
/// <para>
/// LAW (sign-what-you-see): the card renders claims ONLY from the
/// payload bytes it signs. Transport facts (cap_agent_id, AppContext)
/// are NOT fields here &mdash; the render arm shows them in a visually
/// separate section marked unsigned. A contradiction inside the signed
/// payload (a UUID in the purpose text that is not the signed
/// subject's) produces a <see cref="Warnings"/> entry the
/// render arm must show with styling that cannot be suppressed.
/// </para>
/// <para>
/// Lives in Recto.Shared/Capability (not as a page-private record) so
/// the per-field unit tests + the cross-check red-build reach it
/// without a Blazor render harness; Home.razor consumes it thin.
/// </para>
/// </summary>
public sealed record CapabilityAuditView(
    // 1 — subject split: stop rendering Sub as one opaque string.
    string RawSub,
    string ActingAgent,
    string? OnBehalfOfUser,
    // 2 — actions: full allow list + counts. The render label is
    // "Allowed actions" — NEVER "Allow extra" (that name leaked the
    // internal groups-vs-extra split onto a trust surface).
    IReadOnlyList<string> AllowedActions,
    IReadOnlyList<string> DeniedActions,
    IReadOnlyList<string> Groups,
    int AllowedCount,
    int DeniedCount,
    int GroupCount,
    // 3 — scope
    IReadOnlyList<string> ScopeServices,
    IReadOnlyList<string> ScopeRepos,
    IReadOnlyList<string> ScopeEnv,
    // 4 — tier (kept from v1)
    int Tier,
    long? TierCeiling,
    // 5 — validity: iat -> exp as "requested Xs ago · Ys left" so
    // transit consumption is visible (a card that arrives with 20s of
    // its 60s budget already spent SAYS so).
    long Iat,
    long Exp,
    string RequestedAgo,
    string TimeLeft,
    string ExpiresLocal,
    // 6 — pre-approval tense: this is what the operator's approval
    // will MAKE true, not a fact that already holds.
    string WillIssueAs,
    // 7 — request id
    string Jti,
    bool SingleUse,
    // 8 — registry pin
    string RegistryVersion,
    // 9 — cross-check verdicts (empty = consistent)
    IReadOnlyList<string> Warnings,
    // headline
    string PurposeShort,
    string PurposeFull,
    // 10 — audience (2026-10-04): WHERE the grant can be spent. Signed,
    // and until now signed unseen. A consumer names one audience per
    // verifier (a cluster, an executor), so the card must say which one
    // the tap is for. Empty = the claims name none.
    IReadOnlyList<string> Audience,
    // 11 — payload pin (2026-10-04): cap.scope.payload_sha256, the
    // fingerprint of the exact payload the grant is bound to. Null when
    // the claims carry no pin (or carry it as anything but a string).
    string? PayloadPin,
    // 12 — the purpose in the order it is read: one part when it fits the
    // card at a glance, else a part at a time. Together they are the whole.
    IReadOnlyList<string> PurposeParts,
    // 13 — the signed terms most grants do not carry, shown when they do:
    // a use count other than one, limits, a later start, a parent, and the
    // entity a scope extension binds the grant to.
    IReadOnlyList<SignedTerm> Terms,
    // 14 — where the grant reaches, list by list; one row when no list limits it.
    IReadOnlyList<SignedList> ScopeRows)
{
    private const int PurposeMax = 240;
    private const int GlanceActionsMax = 3;
    private const int PinShortChars = 12;

    /// <summary>A start within this many seconds of now is not a later start: two clocks are never exactly alike.</summary>
    public const long ClockSkewSeconds = 120;

    /// <summary>The purpose up to <paramref name="parts"/> of its parts, with an ellipsis while some is left.</summary>
    public string PurposeUpTo(int parts)
    {
        var shown = Math.Clamp(parts, 1, PurposeParts.Count);
        return string.Concat(PurposeParts.Take(shown)) + (shown < PurposeParts.Count ? "..." : string.Empty);
    }

    /// <summary>The allowed actions the card shows at a glance; the rest are under Actions.</summary>
    public IReadOnlyList<string> GlanceActions => AllowedActions.Take(GlanceActionsMax).ToList();

    /// <summary>The pin's first characters for the card's at-a-glance line
    /// (the full value renders under Audit details). Null when there is no pin.</summary>
    public string? PayloadPinShort => PayloadPin is null
        ? null
        : PayloadPin.Length > PinShortChars ? PayloadPin.Substring(0, PinShortChars) + "..." : PayloadPin;

    private static readonly Regex UuidRegex = new(
        "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        RegexOptions.Compiled);

    public static CapabilityAuditView From(CapabilityClaims claims)
        => From(claims, DateTimeOffset.UtcNow);

    /// <summary>
    /// <paramref name="now"/> is injectable so validity strings and
    /// the freshness math are deterministic under test.
    /// </summary>
    public static CapabilityAuditView From(CapabilityClaims claims, DateTimeOffset now)
    {
        var (agent, user) = ParseSub(claims.Sub);
        long? ceiling = TierWeightCeilings.ForTier(claims.Cap.Tier);

        var nowUnix = now.ToUnixTimeSeconds();
        var agoSeconds = nowUnix - claims.Iat;
        var leftSeconds = claims.Exp - nowUnix;
        var requestedAgo = agoSeconds < -ClockSkewSeconds
            ? "dated " + FormatSpan(-agoSeconds) + " ahead"
            : FormatSpan(Math.Max(0, agoSeconds)) + " ago";
        var timeLeft = leftSeconds <= 0 ? "expired" : FormatSpan(leftSeconds) + " left";
        var expiresLocal = DateTimeOffset.FromUnixTimeSeconds(claims.Exp)
            .ToLocalTime().ToString("yyyy-MM-dd HH:mm");

        var parts = SplitParts(VisibleText.OfProse(claims.Purpose), PurposeMax);
        var shownAgent = VisibleText.Of(agent);

        return new CapabilityAuditView(
            RawSub: claims.Sub,
            ActingAgent: shownAgent,
            OnBehalfOfUser: user is null ? null : VisibleText.Of(user),
            AllowedActions: Visible(claims.Cap.AllowActions),
            DeniedActions: Visible(claims.Cap.DenyActions),
            Groups: Visible(claims.Cap.Groups),
            AllowedCount: claims.Cap.AllowActions.Count,
            DeniedCount: claims.Cap.DenyActions.Count,
            GroupCount: claims.Cap.Groups.Count,
            ScopeServices: Visible(claims.Cap.Scope.Services),
            ScopeRepos: Visible(claims.Cap.Scope.Repos),
            ScopeEnv: Visible(claims.Cap.Scope.Env),
            Tier: claims.Cap.Tier,
            TierCeiling: ceiling,
            Iat: claims.Iat,
            Exp: claims.Exp,
            RequestedAgo: requestedAgo,
            TimeLeft: timeLeft,
            ExpiresLocal: expiresLocal,
            WillIssueAs: VisibleText.Of(claims.Iss),
            Jti: VisibleText.Of(claims.Jti),
            SingleUse: claims.MaxUses == 1,
            RegistryVersion: VisibleText.Of(claims.Cap.RegistryVersion),
            Warnings: CrossCheck(claims, shownAgent),
            PurposeShort: parts.Count > 1 ? parts[0] + "..." : parts[0],
            PurposeFull: claims.Purpose,
            Audience: Visible(claims.Aud),
            PayloadPin: claims.Cap.Scope.PayloadSha256 is { } pin ? VisibleText.Of(pin) : null,
            PurposeParts: parts,
            Terms: TermsOf(claims, nowUnix),
            ScopeRows: ScopeRowsOf(claims.Cap.Scope));
    }

    private static string Visible(string value) => value.Length == 0 ? "(empty)" : VisibleText.Of(value);

    private static IReadOnlyList<string> Visible(IReadOnlyList<string> values)
        => values.Any(v => v.Length == 0 || VisibleText.HasHidden(v)) ? values.Select(Visible).ToList() : values;

    private static IReadOnlyList<SignedList> ScopeRowsOf(CapabilityScope scope)
        => scope.Services.Count + scope.Repos.Count + scope.Env.Count == 0
            ? new[] { new SignedList("Scope", Array.Empty<string>()) }
            : new[]
            {
                new SignedList("Services", Visible(scope.Services)),
                new SignedList("Repos", Visible(scope.Repos)),
                new SignedList("Environments", Visible(scope.Env)),
            };

    /// <summary>The text in parts of at most <paramref name="max"/> characters, a surrogate pair never split; always at least one part.</summary>
    private static IReadOnlyList<string> SplitParts(string text, int max)
    {
        var parts = new List<string>();
        var at = 0;
        while (text.Length - at > max)
        {
            var length = char.IsHighSurrogate(text[at + max - 1]) ? max - 1 : max;
            parts.Add(text.Substring(at, length));
            at += length;
        }
        parts.Add(text[at..]);
        return parts;
    }

    private static IReadOnlyList<SignedTerm> TermsOf(CapabilityClaims claims, long nowUnix)
    {
        var terms = new List<SignedTerm>();
        void Add(string label, string? value)
        {
            if (value is not null) terms.Add(new SignedTerm(label, Visible(value)));
        }

        if (claims.MaxUses is not { } uses)
            Add("Uses", "any number until it ends");
        else if (uses != 1)
            Add("Uses", uses.ToString(System.Globalization.CultureInfo.InvariantCulture));
        if (claims.Nbf > nowUnix + ClockSkewSeconds)
            Add("Not valid before", DateTimeOffset.FromUnixTimeSeconds(claims.Nbf).ToLocalTime().ToString("yyyy-MM-dd HH:mm"));
        foreach (var (window, limits) in new[]
                 {
                     ("Limit per hour", claims.Cap.Limits.PerHour),
                     ("Limit per day", claims.Cap.Limits.PerDay),
                     ("Limit per session", claims.Cap.Limits.PerSession),
                 })
        {
            foreach (var (name, limit) in limits.OrderBy(l => l.Key, StringComparer.Ordinal)) Add(window, $"{name}: {limit}");
        }
        Add("Child of grant", claims.ParentCap);
        Add("Signs as profile", claims.ParentProfile);
        Add("Creates for owner", claims.Cap.Scope.CreateForOwner);
        Add("Chat room", claims.Cap.Scope.ChatRoomId);
        Add("Target user", claims.Cap.Scope.TargetUserId);
        Add("Pairing code", claims.Cap.Scope.PairingCode);
        return terms;
    }

    /// <summary>
    /// Splits the canonical <c>agent:&lt;id&gt;@user:&lt;id&gt;</c>
    /// subject into its acting-agent and on-behalf-of-user halves.
    /// Subjects without the <c>@user:</c> marker (v1 single-part
    /// subjects like <c>agent:darwin@staging</c>, where the @ is part
    /// of the agent's own name) come back as (sub, null) &mdash; the
    /// split only fires on the explicit marker, never on a bare @.
    /// </summary>
    public static (string Agent, string? User) ParseSub(string sub)
    {
        const string marker = "@user:";
        var idx = sub.IndexOf(marker, StringComparison.Ordinal);
        if (idx < 0)
        {
            return (sub, null);
        }
        var agent = sub.Substring(0, idx);
        var user = sub.Substring(idx + marker.Length);
        if (agent.Length == 0 || user.Length == 0)
        {
            return (sub, null);
        }
        return (agent, "user:" + user);
    }

    /// <summary>All UUID-shaped tokens in <paramref name="text"/>.</summary>
    public static IReadOnlyList<string> ExtractUuids(string text)
        => UuidRegex.Matches(text).Select(m => m.Value).ToList();

    /// <summary>
    /// The purpose-vs-claims consistency check (field 9). A UUID the free
    /// text names must be one the signed SUBJECT names. A UUID carried only
    /// by another claim - a scope list, the audience, a target - says who or
    /// what the grant reaches, never who acts, so it is named as that rather
    /// than passed. The 2026-08-13 live incident is the fixture. Each
    /// mismatch yields one warning naming BOTH values. The free text is read
    /// as a person reads it (<see cref="VisibleText.FoldedForMatch"/>): another
    /// dash, a look-alike letter, a mark or a line break spells the same UUID.
    /// </summary>
    public static IReadOnlyList<string> CrossCheck(CapabilityClaims claims, string actingAgent)
    {
        var purposeUuids = ExtractUuids(VisibleText.FoldedForMatch(claims.Purpose));
        if (purposeUuids.Count == 0)
        {
            return Array.Empty<string>();
        }

        var subject = new HashSet<string>(ExtractUuids(claims.Sub), StringComparer.OrdinalIgnoreCase);
        var warnings = new List<string>();
        foreach (var uuid in purposeUuids.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (subject.Contains(uuid))
            {
                continue;
            }
            var carriers = CarriersOf(claims, uuid);
            warnings.Add(carriers.Count == 0
                ? $"Purpose text names {uuid}, but no signed claim carries it — " +
                  $"the signed subject is {actingAgent}. Verify before approving."
                : $"Purpose text names {uuid}, which is signed only as {string.Join(", ", carriers)} — " +
                  $"the signed subject is {actingAgent}. Verify before approving.");
        }
        return warnings;
    }

    private static IReadOnlyList<string> CarriersOf(CapabilityClaims claims, string uuid)
    {
        var scope = claims.Cap.Scope;
        return new (string Name, IEnumerable<string?> Values)[]
            {
                ("the issuer", new[] { claims.Iss }),
                ("the request id", new[] { claims.Jti }),
                ("the audience", claims.Aud),
                ("the parent grant", new[] { claims.ParentCap }),
                ("the profile", new[] { claims.ParentProfile }),
                ("the owner created for", new[] { scope.CreateForOwner }),
                ("the chat room", new[] { scope.ChatRoomId }),
                ("the target user", new[] { scope.TargetUserId }),
                ("a scope service", scope.Services),
                ("a scope repo", scope.Repos),
                ("a scope env", scope.Env),
                ("a group", claims.Cap.Groups),
                ("an allowed action", claims.Cap.AllowActions),
                ("a denied action", claims.Cap.DenyActions),
            }
            .Where(c => c.Values.Any(v => v is not null
                && ExtractUuids(v).Contains(uuid, StringComparer.OrdinalIgnoreCase)))
            .Select(c => c.Name)
            .ToList();
    }

    /// <summary>Compact humane span: 42s · 3m 10s · 2h 5m · 3d 4h.</summary>
    public static string FormatSpan(long totalSeconds)
    {
        if (totalSeconds < 60)
        {
            return $"{totalSeconds}s";
        }
        if (totalSeconds < 3600)
        {
            return $"{totalSeconds / 60}m {totalSeconds % 60}s";
        }
        if (totalSeconds < 86400)
        {
            return $"{totalSeconds / 3600}h {(totalSeconds % 3600) / 60}m";
        }
        return $"{totalSeconds / 86400}d {(totalSeconds % 86400) / 3600}h";
    }
}
