using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests.Services;

/// <summary>
/// A resume re-verifies by itself after one kind of stop only: a reply the
/// pinned key signed that was merely out of date. The line that does not
/// move: a changed or unverifiable key is refused as before, with no
/// refetch, and no resume restarts polling for it.
/// </summary>
public class ResumePolicyTests
{
    // --- the decision ---------------------------------------------------------

    [Fact]
    public void AStaleOnlyStop_ReverifiesOnResume()
    {
        Assert.True(ResumePolicy.ShouldReverifyOnResume(pollingStopped: true, stoppedOnStaleOnly: true, reverifying: false));
    }

    [Fact]
    public void AnIdentityStop_StaysStopped()
    {
        // A changed key, an unsigned card, a bootloader that did not answer: the person taps, the app does not.
        Assert.False(ResumePolicy.ShouldReverifyOnResume(pollingStopped: true, stoppedOnStaleOnly: false, reverifying: false));
    }

    [Fact]
    public void RunningPolling_IsLeftAlone()
    {
        Assert.False(ResumePolicy.ShouldReverifyOnResume(pollingStopped: false, stoppedOnStaleOnly: true, reverifying: false));
        Assert.False(ResumePolicy.ShouldReverifyOnResume(pollingStopped: false, stoppedOnStaleOnly: false, reverifying: false));
    }

    [Fact]
    public void ACheckAlreadyInFlight_IsNotStartedTwice()
    {
        Assert.False(ResumePolicy.ShouldReverifyOnResume(pollingStopped: true, stoppedOnStaleOnly: true, reverifying: true));
    }

    [Fact]
    public void TheThreeTitles_AreDifferentWords()
    {
        Assert.Equal("Server identity changed.", ResumePolicy.IdentityChangedTitle);
        Assert.Equal("Out-of-date reply from the bootloader.", ResumePolicy.OutOfDateTitle);
        Assert.Equal("Could not check the bootloader.", ResumePolicy.NoAnswerTitle);
    }

    // --- both directions of the refetch rule, as the page uses it ---------------

    private static AttestationResult Stale => AttestationResult.Stale("token expired");
    private static AttestationResult WrongKey => AttestationResult.Fail("signature does not verify under the pinned key");
    private static AttestationResult Good => AttestationResult.Ok();

    [Fact]
    public async Task OnlyAnExpiredReply_EarnsTheOneRefetch()
    {
        var fetches = 0;
        var judged = await StaleEnvelopeRetry.JudgeAsync(
            "old",
            r => r == "old" ? Stale : Good,
            _ => { fetches++; return Task.FromResult(Result.Success("fresh")); },
            CancellationToken.None);

        Assert.Equal(1, fetches);
        Assert.True(judged.Verdict.Verified);
        Assert.Equal("fresh", judged.Response);
    }

    [Fact]
    public async Task AReplyStaleTwice_IsRefusedAsStale_AndFetchedOnce()
    {
        var fetches = 0;
        var judged = await StaleEnvelopeRetry.JudgeAsync(
            "old",
            _ => Stale,
            _ => { fetches++; return Task.FromResult(Result.Success("still old")); },
            CancellationToken.None);

        Assert.Equal(1, fetches);
        Assert.False(judged.Verdict.Verified);
        Assert.True(judged.Verdict.Expired);       // the one stop a resume re-verifies after
    }

    [Fact]
    public async Task AChangedKey_IsRefusedAtOnce_WithNoRefetch_AndIsNotAStaleStop()
    {
        var fetches = 0;
        var judged = await StaleEnvelopeRetry.JudgeAsync(
            "another key's reply",
            _ => WrongKey,
            _ => { fetches++; return Task.FromResult(Result.Success("anything")); },
            CancellationToken.None);

        Assert.Equal(0, fetches);
        Assert.False(judged.Verdict.Verified);
        Assert.False(judged.Verdict.Expired);
        Assert.False(ResumePolicy.ShouldReverifyOnResume(true, stoppedOnStaleOnly: judged.Verdict.Expired, false));
    }

    [Fact]
    public async Task AStaleReply_ThenAnotherKeys_IsRefused_AndIsNotAStaleStop()
    {
        var judged = await StaleEnvelopeRetry.JudgeAsync(
            "old",
            r => r == "old" ? Stale : WrongKey,
            _ => Task.FromResult(Result.Success("another key's reply")),
            CancellationToken.None);

        Assert.False(judged.Verdict.Verified);
        Assert.False(judged.Verdict.Expired);
        Assert.False(ResumePolicy.ShouldReverifyOnResume(true, stoppedOnStaleOnly: judged.Verdict.Expired, false));
    }

    // --- the page ---------------------------------------------------------------

    private static string Home()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Recto", "MauiProgram.cs"))) dir = dir.Parent;
        Assert.NotNull(dir);
        return File.ReadAllText(Path.Combine(dir!.FullName, "Recto.Shared", "Pages", "Home.razor")).Replace("\r\n", "\n");
    }

    [Fact]
    public void BothBanners_SayWhenTheBootloaderWasLastHeard()
    {
        var home = Home();
        const string line = "Last heard from the bootloader: @LastHeard.Describe(_lastHeardAt, DateTimeOffset.UtcNow)";

        var identity = home.Substring(home.IndexOf("@if (!string.IsNullOrEmpty(_identityError))", StringComparison.Ordinal));
        identity = identity.Substring(0, identity.IndexOf("@if (!string.IsNullOrEmpty(_pollingError))", StringComparison.Ordinal));
        Assert.Contains(line, identity);

        var polling = home.Substring(home.IndexOf("@if (!string.IsNullOrEmpty(_pollingError))", StringComparison.Ordinal));
        polling = polling.Substring(0, polling.IndexOf("HandleRetryPollAsync", StringComparison.Ordinal));
        Assert.Contains(line, polling);
    }

    [Fact]
    public void OnlyTheTwoNoAnswerSites_CarryTheNoAnswerTitle()
    {
        var home = Home();
        var sites = Regex.Matches(
            home,
            @"_identityError = \$""The bootloader did not answer the identity check: \{[^}]+\}"";\s*"
            + @"_identityErrorTitle = ResumePolicy\.NoAnswerTitle;\s*StopPolling\(\);");
        Assert.Equal(2, sites.Count);
        Assert.Equal(2, Regex.Matches(home, @"ResumePolicy\.NoAnswerTitle").Count);
    }

    [Fact]
    public void ARefusalAboutTheKey_KeepsTheIdentityTitle_AndIsNeverAStaleStop()
    {
        var home = Home();

        // The default title is the identity one, and every new message returns to it and forgets "stale only".
        Assert.Contains("@(_identityErrorTitle ?? ResumePolicy.IdentityChangedTitle)", home);
        Assert.Contains("set { _identityErrorValue = value; _identityErrorTitle = null; _stoppedOnStaleOnly = false; }", home);

        // "Stale only" is set in exactly two places, each right after the out-of-date title.
        Assert.Equal(2, Regex.Matches(home, @"_stoppedOnStaleOnly = true;").Count);
        Assert.Equal(2, Regex.Matches(
            home, @"_identityErrorTitle = ResumePolicy\.OutOfDateTitle;\s*_stoppedOnStaleOnly = true;").Count);

        // The two refusals about the key itself set a message and nothing after it but the stop.
        foreach (var opening in new[]
                 {
                     "_identityError = \"Cards arrived that the bootloader did not sign \"",
                     "_identityError = \"The server behind this address could not prove it is your bootloader \"",
                 })
        {
            var at = home.IndexOf(opening, StringComparison.Ordinal);
            Assert.True(at > 0, opening);
            var until = home.IndexOf("StopPolling();", at, StringComparison.Ordinal);
            var between = home.Substring(at, until - at);
            Assert.DoesNotContain("_identityErrorTitle", between);
            Assert.DoesNotContain("_stoppedOnStaleOnly", between);
        }
    }

    [Fact]
    public void AResume_AsksThePolicy_AndRunsTheFullCheck()
    {
        var home = Home();
        var resumed = home.Substring(home.IndexOf("private void OnAppResumed()", StringComparison.Ordinal));
        resumed = resumed.Substring(0, resumed.IndexOf("private void KickPushTokenSync", StringComparison.Ordinal));

        Assert.Contains("ResumePolicy.ShouldReverifyOnResume(", resumed);
        Assert.Contains("stoppedOnStaleOnly: _stoppedOnStaleOnly", resumed);
        Assert.Contains("await HandleReverifyClickAsync();", resumed);
        // Polling is never started from the resume itself: only the check's own success starts it.
        Assert.DoesNotContain("StartPolling()", resumed);
        Assert.Single(Regex.Matches(resumed, @"HandleReverifyClickAsync\(\)"));
    }

    [Fact]
    public void TheVerifiers_AreNotEditedByThis()
    {
        // The refetch rule lives in StaleEnvelopeRetry: a verdict that is not Expired returns before any fetch.
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Recto", "MauiProgram.cs"))) dir = dir.Parent;
        var retry = File.ReadAllText(Path.Combine(dir!.FullName, "Recto.Shared", "Services", "StaleEnvelopeRetry.cs"));
        Assert.Contains("Expired", retry);
        Assert.Single(Regex.Matches(retry, @"await refetch\("));
    }
}
