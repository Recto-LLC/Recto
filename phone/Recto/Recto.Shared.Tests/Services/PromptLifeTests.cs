using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests.Services;

/// <summary>
/// The whole life a showing prompt is given. The Android key service starts
/// one when it asks the prompt, holds it with the prompt's other objects and
/// lets the single-flight pass go when it is over; these run the life itself
/// on a clock that moves only when told.
/// </summary>
public class PromptLifeTests
{
    [Fact]
    public void TheLimitIsThreeMinutes_AndTheAnswerSaysNothingWasSigned()
    {
        Assert.Equal(TimeSpan.FromMinutes(3), PromptLife.Limit);
        Assert.Equal("The approval was not answered in time. Nothing was signed.", PromptLife.LapsedMessage);
    }

    [Fact]
    public void BeforeTheLimit_NothingHappens()
    {
        var clock = new StepClock();
        var lapsed = 0;
        using var life = new PromptLife(() => lapsed++, clock);

        clock.Advance(PromptLife.Limit - TimeSpan.FromMilliseconds(1));

        Assert.Equal(0, lapsed);
        Assert.False(life.IsOver);
    }

    [Fact]
    public void AtTheLimit_TheLapseRunsOnce_AndTheLifeIsOver()
    {
        var clock = new StepClock();
        var lapsed = 0;
        using var life = new PromptLife(() => lapsed++, clock);

        clock.Advance(PromptLife.Limit);
        clock.Advance(PromptLife.Limit);

        Assert.Equal(1, lapsed);
        Assert.True(life.IsOver);
    }

    [Fact]
    public void APromptThatEndsInTime_NeverLapses()
    {
        var clock = new StepClock();
        var lapsed = 0;
        var life = new PromptLife(() => lapsed++, clock);

        clock.Advance(TimeSpan.FromSeconds(30));
        life.Dispose();
        life.Dispose();
        clock.Advance(PromptLife.Limit * 2);

        Assert.Equal(0, lapsed);
        Assert.Equal(0, clock.LiveTimers);
    }

    [Fact]
    public void ALapseThatThrows_StillLeavesTheLifeOver()
    {
        var clock = new StepClock();
        using var life = new PromptLife(() => throw new InvalidOperationException("boom"), clock);

        clock.Advance(PromptLife.Limit);

        Assert.True(life.IsOver);
    }

    [Fact]
    public void APromptWhoseEndingNeverComes_FreesTheFlight_AndAnswersTheCaller()
    {
        // The rebuilt screen reads alive, the prompt's ending was lost with its fragment: nothing but the
        // life ends it. Wired as the key service wires it: the lapse answers the caller and releases the
        // pass, and a signing at the limit itself does not take the pass first.
        var clock = new StepClock();
        var flight = new SingleFlight();
        var pass = flight.TryEnter()!;
        var answer = new TaskCompletionSource<string>();
        var lapseDue = false;
        using var life = new PromptLife(() => lapseDue = true, clock);
        pass.Watch(
            () => life.IsOverBy(PromptLife.Grace),
            () => answer.TrySetResult(life.WordsForAnEnding(LostWords)));

        Assert.Null(flight.TryEnter());
        clock.Advance(PromptLife.Limit);

        // The lapse is due (on Android, queued to the main thread); a signing now is still refused and
        // the caller is not answered by it.
        Assert.True(lapseDue);
        Assert.Null(flight.TryEnter());
        Assert.False(answer.Task.IsCompleted);

        // The lapse runs: it answers in its own words and releases.
        answer.TrySetResult(PromptLife.LapsedMessage);
        pass.Dispose();
        Assert.Equal(PromptLife.LapsedMessage, answer.Task.Result);
        Assert.NotNull(flight.TryEnter());
    }

    [Fact]
    public void ALapseThatNeverRan_IsTakenBackAfterTheGrace_InTheLapsesWords()
    {
        var clock = new StepClock();
        var flight = new SingleFlight();
        var pass = flight.TryEnter()!;
        var words = new List<string>();
        using var life = new PromptLife(() => { }, clock);
        pass.Watch(() => life.IsOverBy(PromptLife.Grace), () => words.Add(life.WordsForAnEnding(LostWords)));

        clock.Advance(PromptLife.Limit);
        Assert.Null(flight.TryEnter());
        clock.Advance(PromptLife.Grace - TimeSpan.FromMilliseconds(1));
        Assert.Null(flight.TryEnter());
        clock.Advance(TimeSpan.FromMilliseconds(1));

        Assert.NotNull(flight.TryEnter());
        Assert.Equal(new[] { PromptLife.LapsedMessage }, words);
    }

    [Fact]
    public void AnEndingBeforeTheLimit_IsAnsweredInItsOwnWords()
    {
        var clock = new StepClock();
        using var life = new PromptLife(() => { }, clock);

        clock.Advance(PromptLife.Limit - TimeSpan.FromMilliseconds(1));
        Assert.Equal(LostWords, life.WordsForAnEnding(LostWords));
        clock.Advance(TimeSpan.FromMilliseconds(1));
        Assert.Equal(PromptLife.LapsedMessage, life.WordsForAnEnding(LostWords));
    }

    // --- after a lapse, the flight is held a moment ---

    private static readonly TimeSpan DismissDelay = TimeSpan.FromMilliseconds(750);

    [Fact]
    public void AfterALapse_TheFlightIsHeldAMoment_ThenFreed()
    {
        // The lapse asks the old prompt to close and releases its pass; the prompt may still deliver its own
        // ending a moment later. Held that moment, the ending lands on no one, never on a new prompt.
        var clock = new StepClock();
        var flight = new SingleFlight();
        var pass = flight.TryEnter()!;
        var abandoned = 0;
        pass.Watch(() => true, () => abandoned++);

        pass.Linger(DismissDelay, clock);
        pass.Dispose();

        Assert.True(flight.IsHeld);
        Assert.Null(flight.TryEnter());
        clock.Advance(DismissDelay - TimeSpan.FromMilliseconds(1));
        Assert.Null(flight.TryEnter());
        // Refused, never "abandoned": the holder has already ended.
        Assert.Equal(0, abandoned);

        clock.Advance(TimeSpan.FromMilliseconds(1));
        Assert.False(flight.IsHeld);
        Assert.NotNull(flight.TryEnter());
        Assert.Equal(0, clock.LiveTimers);
    }

    [Fact]
    public void ASecondReleaseWhileHeldAMoment_DoesNotCutItShort()
    {
        var clock = new StepClock();
        var flight = new SingleFlight();
        var pass = flight.TryEnter()!;
        pass.Linger(DismissDelay, clock);
        pass.Dispose();

        pass.Dispose();

        Assert.Null(flight.TryEnter());
        clock.Advance(DismissDelay);
        Assert.NotNull(flight.TryEnter());
    }

    [Fact]
    public void APassNotAskedToLinger_FreesTheFlightAtOnce()
    {
        var flight = new SingleFlight();
        var pass = flight.TryEnter()!;

        pass.Dispose();

        Assert.NotNull(flight.TryEnter());
    }

    [Fact]
    public void TheGraceIsTenSeconds()
    {
        Assert.Equal(TimeSpan.FromSeconds(10), PromptLife.Grace);
    }

    // The key service's own words for a prompt whose screen went away (PromptLostMessage there).
    private const string LostWords = "The biometric prompt was closed before it was answered. Nothing was signed. Try again.";
    /// <summary>A clock that moves only when told, and fires its timers when it passes them.</summary>
    private sealed class StepClock : TimeProvider
    {
        private readonly List<StepTimer> _timers = new();
        private DateTimeOffset _now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        public int LiveTimers
        {
            get { lock (_timers) { return _timers.FindAll(t => !t.Disposed).Count; } }
        }

        public override DateTimeOffset GetUtcNow() => _now;

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new StepTimer(callback, state, _now + dueTime);
            lock (_timers)
            {
                _timers.Add(timer);
            }
            return timer;
        }

        public void Advance(TimeSpan by)
        {
            _now += by;
            List<StepTimer> due;
            lock (_timers)
            {
                due = _timers.FindAll(t => !t.Disposed && !t.Fired && t.Due <= _now);
            }
            foreach (var timer in due)
            {
                timer.Fire();
            }
        }

        private sealed class StepTimer : ITimer
        {
            private readonly TimerCallback _callback;
            private readonly object? _state;

            public StepTimer(TimerCallback callback, object? state, DateTimeOffset due)
            {
                _callback = callback;
                _state = state;
                Due = due;
            }

            public DateTimeOffset Due { get; }
            public bool Fired { get; private set; }
            public bool Disposed { get; private set; }

            public void Fire()
            {
                Fired = true;
                _callback(_state);
            }

            public bool Change(TimeSpan dueTime, TimeSpan period) => false;

            public void Dispose() => Disposed = true;

            public ValueTask DisposeAsync()
            {
                Dispose();
                return default;
            }
        }
    }
}
