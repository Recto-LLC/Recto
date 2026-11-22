using System;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests.Services;

/// <summary>
/// Which screen a showing prompt belongs to, and whether that screen is
/// gone. This is the rule the Android key service asks before it takes a
/// single-flight pass back (<c>IsGone</c> there calls
/// <see cref="PromptHost{TScreen}.IsGone"/> with the activity's own reads),
/// run here on the rule itself with a screen object that has the same three
/// facts an activity has.
/// </summary>
public class PromptHostTests
{
    // --- the rule ---

    [Fact]
    public void AShowingPromptsScreen_IsNotGone()
    {
        var screen = new Screen();
        var host = new PromptHost<Screen>(screen);

        Assert.False(Gone(host, current: screen));
        Assert.Same(screen, host.Watched);
    }

    [Fact]
    public void ADestroyForGood_IsGone_AndSaysSoToTheWatch()
    {
        var screen = new Screen();
        var host = new PromptHost<Screen>(screen);

        screen.IsDestroyed = true;
        var ended = host.Destroyed(screen, forConfigurationChange: false);

        Assert.True(ended);
        Assert.True(Gone(host, current: screen));
        // Told once: a second report of the same destroy ends nothing twice.
        Assert.False(host.Destroyed(screen, forConfigurationChange: false));
    }

    [Fact]
    public void ADestroyForAConfigurationChange_IsNeverGone_BeforeTheNewScreenExists()
    {
        // The old object is destroyed and is no longer current - every fact the rule reads of it says
        // "gone" - and the prompt is alive. This is the case that reclaimed a live prompt's pass.
        var old = new Screen();
        var host = new PromptHost<Screen>(old);

        // Android's order: the flags are set, then the watch hears.
        old.IsChangingConfigurations = true;
        old.IsDestroyed = true;
        var ended = host.Destroyed(old, forConfigurationChange: true);

        Assert.False(ended);
        Assert.True(host.IsRebuilding);
        Assert.False(Gone(host, current: old));
        Assert.False(Gone(host, current: null));
        Assert.False(Gone(host, current: new Screen()));
    }

    [Fact]
    public void AfterAConfigurationChange_TheNewScreenIsTheWatchedOne_AndIsNotGone()
    {
        var old = new Screen();
        var host = new PromptHost<Screen>(old);
        host.Destroyed(old, forConfigurationChange: true);
        old.IsDestroyed = true;

        var rebuilt = new Screen();
        host.Created(rebuilt);

        Assert.Same(rebuilt, host.Watched);
        Assert.False(host.IsRebuilding);
        Assert.False(Gone(host, current: rebuilt));
        // The old object's facts are never read again.
        Assert.Equal(0, old.ReadsAfterRebuild);
    }

    [Fact]
    public void TheRebuiltScreen_DestroyedForGood_IsGone()
    {
        var old = new Screen();
        var host = new PromptHost<Screen>(old);
        host.Destroyed(old, forConfigurationChange: true);
        var rebuilt = new Screen();
        host.Created(rebuilt);

        // The old one's destroy, reported again, is nothing; the new one's is the end.
        Assert.False(host.Destroyed(old, forConfigurationChange: false));
        Assert.False(Gone(host, current: rebuilt));
        rebuilt.IsDestroyed = true;
        Assert.True(host.Destroyed(rebuilt, forConfigurationChange: false));
        Assert.True(Gone(host, current: rebuilt));
    }

    [Fact]
    public void TwoConfigurationChangesInARow_AreFollowed()
    {
        var first = new Screen();
        var host = new PromptHost<Screen>(first);
        host.Destroyed(first, forConfigurationChange: true);
        var second = new Screen();
        host.Created(second);
        host.Destroyed(second, forConfigurationChange: true);
        Assert.False(Gone(host, current: second));
        var third = new Screen();
        host.Created(third);

        Assert.Same(third, host.Watched);
        Assert.False(Gone(host, current: third));
    }

    [Fact]
    public void AScreenCreatedWhenNoRebuildIsNoted_IsNotTakenAsThePrompts()
    {
        var screen = new Screen();
        var host = new PromptHost<Screen>(screen);

        host.Created(new Screen());

        Assert.Same(screen, host.Watched);
    }

    [Fact]
    public void AnotherScreensDestroy_IsNothingToThisPrompt()
    {
        var screen = new Screen();
        var host = new PromptHost<Screen>(screen);

        Assert.False(host.Destroyed(new Screen(), forConfigurationChange: false));
        Assert.False(host.Destroyed(new Screen(), forConfigurationChange: true));

        Assert.False(host.IsRebuilding);
        Assert.False(Gone(host, current: screen));
    }

    [Theory]
    [InlineData(true, false, true)]
    [InlineData(false, true, true)]
    [InlineData(false, false, false)]
    public void WithNoEventSeen_TheWatchedScreensOwnFactsDecide(bool destroyed, bool finishing, bool gone)
    {
        // The reclaim's own reading, for a destroy the watch never heard of.
        var screen = new Screen { IsDestroyed = destroyed, IsFinishing = finishing };
        var host = new PromptHost<Screen>(screen);

        Assert.Equal(gone, Gone(host, current: screen));
    }

    [Fact]
    public void AWatchedScreenThatIsNoLongerTheCurrentOne_IsGone()
    {
        var screen = new Screen();
        var host = new PromptHost<Screen>(screen);

        Assert.True(Gone(host, current: new Screen()));
        Assert.True(Gone(host, current: null));
    }

    // --- the rule under the single flight, wired as the key service wires it ---

    [Fact]
    public void AConfigurationChangeUnderAPrompt_ThenASecondSigning_IsRefused_AndThePromptIsNotEnded()
    {
        var flight = new SingleFlight();
        var old = new Screen();
        var current = old;
        var abandoned = 0;
        var host = new PromptHost<Screen>(old);
        var pass = flight.TryEnter();
        pass!.Watch(() => Gone(host, current), () => abandoned++);

        // The activity is rebuilt under the showing prompt: Android's order, the flags then the event.
        old.IsChangingConfigurations = true;
        old.IsDestroyed = true;
        Assert.False(host.Destroyed(old, forConfigurationChange: true));

        // A second signing in the gap, before the new activity exists: refused.
        Assert.Null(flight.TryEnter());

        var rebuilt = new Screen();
        // MAUI's order: the app's current activity is the new one before the watch hears it was created.
        current = rebuilt;
        host.Created(rebuilt);

        // And after it: still refused. The first prompt is alive and holds the flight.
        Assert.Null(flight.TryEnter());
        Assert.Equal(0, abandoned);
        Assert.True(flight.IsHeld);

        // The prompt's own ending frees it, as always.
        pass.Dispose();
        Assert.NotNull(flight.TryEnter());
    }

    [Fact]
    public void ATrueDestroyUnderAPrompt_ThenASecondSigning_TakesThePassBack_AndEndsTheFirst()
    {
        var flight = new SingleFlight();
        var screen = new Screen();
        Screen? current = screen;
        var abandoned = 0;
        var host = new PromptHost<Screen>(screen);
        var pass = flight.TryEnter();
        pass!.Watch(() => Gone(host, current), () => abandoned++);

        // The activity is destroyed for good and the lifecycle event never reached the watch.
        screen.IsDestroyed = true;
        current = new Screen();

        var second = flight.TryEnter();

        Assert.NotNull(second);
        Assert.Equal(1, abandoned);
    }

    [Fact]
    public void ATrueDestroy_AfterAConfigurationChange_IsStillReclaimed()
    {
        var flight = new SingleFlight();
        var old = new Screen();
        var host = new PromptHost<Screen>(old);
        Screen? current = old;
        var abandoned = 0;
        var pass = flight.TryEnter();
        pass!.Watch(() => Gone(host, current), () => abandoned++);
        host.Destroyed(old, forConfigurationChange: true);
        var rebuilt = new Screen();
        // MAUI's order: the app's current activity is the new one before the watch hears it was created.
        current = rebuilt;
        host.Created(rebuilt);
        Assert.Null(flight.TryEnter());

        // Now the rebuilt activity is finished.
        rebuilt.IsFinishing = true;

        Assert.NotNull(flight.TryEnter());
        Assert.Equal(1, abandoned);
    }

    // --- the window before the watch hears ---

    [Fact]
    public void ASigningBetweenTheFlagsAndTheDestroyEvent_IsRefused_AndThePromptIsNotEnded()
    {
        // Android sets "changing configurations", then "destroyed", and calls the watch only at the end of
        // the destroy. A signing on another thread in that gap reads the old activity as destroyed, and
        // still current, with no rebuild noted; it must not take the live prompt's pass.
        var flight = new SingleFlight();
        var old = new Screen();
        var abandoned = 0;
        var host = new PromptHost<Screen>(old);
        var current = old;
        var pass = flight.TryEnter();
        pass!.Watch(() => Gone(host, current), () => abandoned++);

        old.IsChangingConfigurations = true;
        old.IsDestroyed = true;

        // The old activity is still the current one, and reads destroyed: refused all the same.
        Assert.Null(flight.TryEnter());
        Assert.Equal(0, abandoned);
        Assert.True(host.IsRebuilding);

        // Then the watch hears, and the new activity is taken as the prompt's.
        Assert.False(host.Destroyed(old, forConfigurationChange: true));
        var rebuilt = new Screen();
        // MAUI's order: the app's current activity is the new one before the watch hears it was created.
        current = rebuilt;
        host.Created(rebuilt);
        Assert.Same(rebuilt, host.Watched);
        Assert.Null(flight.TryEnter());
        Assert.Equal(0, abandoned);
    }

    [Fact]
    public void AFlagSeenBeforeTheWatchHears_TakesTheNextScreenCreated()
    {
        var old = new Screen { IsChangingConfigurations = true, IsDestroyed = true };
        var host = new PromptHost<Screen>(old);

        Assert.False(Gone(host, current: old));
        var rebuilt = new Screen();
        host.Created(rebuilt);

        Assert.Same(rebuilt, host.Watched);
        Assert.False(Gone(host, current: rebuilt));
    }

    [Fact]
    public void AWatchedScreenChangedWhileTheReadsRan_IsNotGone()
    {
        // The old screen reads destroyed; while it is read, the main thread hears the configuration-change
        // destroy and the new screen is taken. The "gone" read is of a screen no longer watched: refused.
        var old = new Screen { IsDestroyed = true };
        var host = new PromptHost<Screen>(old);
        var rebuilt = new Screen();
        old.OnRead = () =>
        {
            old.OnRead = null;
            host.Destroyed(old, forConfigurationChange: true);
            host.Created(rebuilt);
        };

        Assert.False(Gone(host, current: rebuilt));
        Assert.Same(rebuilt, host.Watched);
        Assert.False(Gone(host, current: rebuilt));
    }

    [Fact]
    public void ARebuildNotedWhileTheReadsRan_IsNotGone()
    {
        var old = new Screen { IsDestroyed = true };
        var host = new PromptHost<Screen>(old);
        old.OnRead = () =>
        {
            old.OnRead = null;
            host.Destroyed(old, forConfigurationChange: true);
        };

        Assert.False(Gone(host, current: null));
        Assert.True(host.IsRebuilding);
    }

    [Fact]
    public void ATrueDestroyWithNoFlag_IsStillGone_AfterTheSecondLook()
    {
        var screen = new Screen { IsDestroyed = true };
        var host = new PromptHost<Screen>(screen);

        Assert.True(Gone(host, current: screen));
    }

    // --- the current screen is read by the rule, after the watched one ---

    [Fact]
    public void ARebuildFinishedBeforeTheCurrentScreenIsRead_IsNotGone()
    {
        // The signing thread takes the watched screen (old), and before it reads the app's current screen
        // the whole rebuild completes: MAUI makes the new screen current, the watch hears both events. The
        // current read is the new screen, which is not the old one the rule holds - and the last look
        // under the lock sees the watched screen has changed. Not gone.
        var old = new Screen();
        var host = new PromptHost<Screen>(old);
        var rebuilt = new Screen();
        var current = old;

        var gone = GoneReading(host, () =>
        {
            old.IsChangingConfigurations = true;
            old.IsDestroyed = true;
            host.Destroyed(old, forConfigurationChange: true);
            current = rebuilt;
            host.Created(rebuilt);
            return current;
        });

        Assert.False(gone);
        Assert.Same(rebuilt, host.Watched);
        Assert.False(Gone(host, current: rebuilt));
    }

    [Fact]
    public void ACurrentScreenReadEarlierThanTheRebuild_CannotReachTheRule()
    {
        // The stale value of the mend's finding: "old" was the current screen when a signing started, and
        // the rebuild has finished since. The rule reads the current screen itself, when it runs, so what it
        // reads is the new one; the old value is never handed in.
        var old = new Screen();
        var host = new PromptHost<Screen>(old);
        var reads = 0;
        Screen? current = old;
        old.IsChangingConfigurations = true;
        old.IsDestroyed = true;
        host.Destroyed(old, forConfigurationChange: true);
        var rebuilt = new Screen();
        current = rebuilt;
        host.Created(rebuilt);

        Assert.False(GoneReading(host, () =>
        {
            reads++;
            return current;
        }));
        Assert.Equal(1, reads);
    }

    [Fact]
    public void TheCurrentScreen_IsReadOnlyAfterTheWatchedScreenIsTaken()
    {
        // While a rebuild is noted, the rule answers without reading the current screen at all.
        var old = new Screen();
        var host = new PromptHost<Screen>(old);
        host.Destroyed(old, forConfigurationChange: true);
        var reads = 0;

        Assert.False(GoneReading(host, () =>
        {
            reads++;
            return null;
        }));
        Assert.Equal(0, reads);
    }

    // --- the backstop ---

    [Fact]
    public void ARebuildWithNoNewScreen_CountsAsGone_AfterTheLimit()
    {
        var clock = new StepClock();
        var old = new Screen();
        var host = new PromptHost<Screen>(old, clock);
        old.IsChangingConfigurations = true;
        old.IsDestroyed = true;
        host.Destroyed(old, forConfigurationChange: true);

        clock.Advance(PromptHost<Screen>.RebuildLimit - TimeSpan.FromMilliseconds(1));
        Assert.False(Gone(host, current: null));

        clock.Advance(TimeSpan.FromMilliseconds(1));
        Assert.True(Gone(host, current: null));

        // Gone for good: a screen created late is not taken, and the answer stays.
        host.Created(new Screen());
        Assert.Same(old, host.Watched);
        Assert.True(Gone(host, current: null));
    }

    [Fact]
    public void AFlagTheWatchNeverHears_CountsAsGone_AfterTheLimit()
    {
        // No lifecycle event reaches the host (the watch could not register): the flag on the screen
        // alone holds the pass only until the limit.
        var clock = new StepClock();
        var flight = new SingleFlight();
        var old = new Screen { IsChangingConfigurations = true, IsDestroyed = true };
        var host = new PromptHost<Screen>(old, clock);
        var abandoned = 0;
        var pass = flight.TryEnter();
        pass!.Watch(() => Gone(host, null), () => abandoned++);

        Assert.Null(flight.TryEnter());
        clock.Advance(PromptHost<Screen>.RebuildLimit);

        Assert.NotNull(flight.TryEnter());
        Assert.Equal(1, abandoned);
    }

    [Fact]
    public void ARebuildFinishedInTime_IsNeverCutShortByTheLimit()
    {
        var clock = new StepClock();
        var old = new Screen();
        var host = new PromptHost<Screen>(old, clock);
        host.Destroyed(old, forConfigurationChange: true);
        clock.Advance(TimeSpan.FromSeconds(1));
        var rebuilt = new Screen();
        host.Created(rebuilt);

        clock.Advance(PromptHost<Screen>.RebuildLimit * 3);

        Assert.False(Gone(host, current: rebuilt));
    }

    // --- helpers ---

    /// <summary>The rule, asked exactly as the key service asks it.</summary>
    private static bool Gone(PromptHost<Screen> host, Screen? current)
        => host.IsGone(
            watched => watched.ReadChanging(host),
            watched => watched.ReadDestroyed(host),
            watched => watched.ReadFinishing(host),
            () => current);

    /// <summary>The rule, with the current screen read when the rule reads it.</summary>
    private static bool GoneReading(PromptHost<Screen> host, Func<Screen?> current)
        => host.IsGone(
            watched => watched.ReadChanging(host),
            watched => watched.ReadDestroyed(host),
            watched => watched.ReadFinishing(host),
            current);

    /// <summary>A clock that moves only when told.</summary>
    private sealed class StepClock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }

    /// <summary>A screen with the four facts an activity has.</summary>
    private sealed class Screen
    {
        public bool IsChangingConfigurations { get; set; }
        public bool IsDestroyed { get; set; }
        public bool IsFinishing { get; set; }

        /// <summary>Run on a "destroyed" read: what the main thread does meanwhile.</summary>
        public Action? OnRead { get; set; }

        public bool ReadChanging(PromptHost<Screen> host)
        {
            Count(host);
            return IsChangingConfigurations;
        }

        /// <summary>How often this screen was read while it was not the watched one.</summary>
        public int ReadsAfterRebuild { get; private set; }

        public bool ReadDestroyed(PromptHost<Screen> host)
        {
            Count(host);
            OnRead?.Invoke();
            return IsDestroyed;
        }

        public bool ReadFinishing(PromptHost<Screen> host)
        {
            Count(host);
            return IsFinishing;
        }

        private void Count(PromptHost<Screen> host)
        {
            if (!ReferenceEquals(host.Watched, this))
            {
                ReadsAfterRebuild++;
            }
        }
    }
}
