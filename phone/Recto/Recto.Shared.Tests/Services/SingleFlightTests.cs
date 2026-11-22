using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests.Services;

/// <summary>
/// One at a time, the second refused. The Android key service holds one of
/// these around the biometric prompt (pinned from its source in
/// <see cref="BootloaderHandlerPinningTests"/>).
/// </summary>
public class SingleFlightTests
{
    [Fact]
    public void TheFirstEnters_AndASecondIsRefusedWhileItIsHeld()
    {
        var flight = new SingleFlight();

        using var first = flight.TryEnter();

        Assert.NotNull(first);
        Assert.True(flight.IsHeld);
        Assert.Null(flight.TryEnter());
        Assert.Null(flight.TryEnter());
        Assert.True(flight.IsHeld);
    }

    [Fact]
    public void ReleasingThePass_FreesTheFlightForTheNext()
    {
        var flight = new SingleFlight();
        var first = flight.TryEnter();

        first!.Dispose();

        Assert.False(flight.IsHeld);
        using var second = flight.TryEnter();
        Assert.NotNull(second);
    }

    [Fact]
    public void ReleasingTwice_IsReleasingOnce()
    {
        var flight = new SingleFlight();
        var first = flight.TryEnter();

        first!.Dispose();
        first.Dispose();

        Assert.False(flight.IsHeld);
    }

    [Fact]
    public void ALateReleaseFromAnEarlierHolder_DoesNotFreeALaterOne()
    {
        var flight = new SingleFlight();
        var first = flight.TryEnter();
        first!.Dispose();
        var second = flight.TryEnter();
        Assert.NotNull(second);

        // The first prompt's ending arrives again, after the second signing was let in.
        first.Dispose();

        Assert.True(flight.IsHeld);
        Assert.Null(flight.TryEnter());
        second!.Dispose();
        Assert.False(flight.IsHeld);
    }

    [Fact]
    public void ARefusedAttempt_HoldsNothing()
    {
        var flight = new SingleFlight();
        var first = flight.TryEnter();
        Assert.Null(flight.TryEnter());

        first!.Dispose();

        // The refused attempt left nothing behind to release.
        Assert.False(flight.IsHeld);
    }

    [Fact]
    public void OfManyAtOnce_ExactlyOneEnters()
    {
        var flight = new SingleFlight();
        var entered = 0;
        using var start = new ManualResetEventSlim();

        var threads = Enumerable.Range(0, 16).Select(_ => new Thread(() =>
        {
            start.Wait();
            if (flight.TryEnter() is not null)
            {
                Interlocked.Increment(ref entered);
            }
        })).ToList();
        threads.ForEach(t => t.Start());
        start.Set();
        threads.ForEach(t => t.Join());

        Assert.Equal(1, entered);
        Assert.True(flight.IsHeld);
    }

    // --- a holder that is gone does not hold for ever ---

    [Fact]
    public void AHolderThatIsStillThere_IsNotTakenFrom()
    {
        var flight = new SingleFlight();
        var abandoned = 0;
        var first = flight.TryEnter();
        first!.Watch(() => false, () => abandoned++);

        Assert.Null(flight.TryEnter());
        Assert.Equal(0, abandoned);
        Assert.True(flight.IsHeld);
    }

    [Fact]
    public void AnAbandonedHolder_IsEnded_AndTheNewcomerEnters()
    {
        // The leak this closes: an ending that is never delivered left the flight held, and every later
        // entry refused, for the life of the process.
        var flight = new SingleFlight();
        var gone = false;
        var abandoned = 0;
        var first = flight.TryEnter();
        first!.Watch(() => gone, () => abandoned++);
        Assert.Null(flight.TryEnter());

        gone = true;
        using var second = flight.TryEnter();

        Assert.NotNull(second);
        Assert.Equal(1, abandoned);
        Assert.True(flight.IsHeld);
        // The newcomer holds it now; a third is refused as usual.
        Assert.Null(flight.TryEnter());
    }

    [Fact]
    public void TheAbandonAction_RunsAtMostOnce_AndItsOwnReleaseIsHarmless()
    {
        var flight = new SingleFlight();
        var abandoned = 0;
        SingleFlight.Pass? first = flight.TryEnter();
        // As the key service does: the action releases the holder's own pass.
        first!.Watch(() => true, () => { abandoned++; first.Dispose(); });

        var second = flight.TryEnter();
        Assert.NotNull(second);
        second!.Dispose();
        var third = flight.TryEnter();

        Assert.NotNull(third);
        Assert.Equal(1, abandoned);
        // The first holder's late release frees nothing that is not its own.
        first.Dispose();
        Assert.True(flight.IsHeld);
    }

    [Fact]
    public void AnAbandonActionThatThrows_StillFreesTheFlight()
    {
        var flight = new SingleFlight();
        var first = flight.TryEnter();
        first!.Watch(() => true, () => throw new InvalidOperationException("the holder is already torn down"));

        using var second = flight.TryEnter();

        Assert.NotNull(second);
    }

    [Fact]
    public void AHolderThatCannotBeAsked_IsTreatedAsAbandoned()
    {
        // A flight stuck shut is the worse fault.
        var flight = new SingleFlight();
        var abandoned = 0;
        var first = flight.TryEnter();
        first!.Watch(() => throw new ObjectDisposedException("activity"), () => abandoned++);

        using var second = flight.TryEnter();

        Assert.NotNull(second);
        Assert.Equal(1, abandoned);
    }

    [Fact]
    public void AnUnwatchedHolder_IsNeverTakenFrom()
    {
        var flight = new SingleFlight();
        using var first = flight.TryEnter();

        Assert.Null(flight.TryEnter());
        Assert.True(flight.IsHeld);
    }

    [Fact]
    public void AReleasedPass_IsNoLongerAsked()
    {
        var flight = new SingleFlight();
        var asked = 0;
        var first = flight.TryEnter();
        first!.Watch(() => { asked++; return false; }, () => { });
        first.Dispose();

        using var second = flight.TryEnter();
        Assert.Null(flight.TryEnter());

        Assert.NotNull(second);
        Assert.Equal(0, asked);
    }

    [Fact]
    public void TwoFlights_AreIndependent()
    {
        var one = new SingleFlight();
        var other = new SingleFlight();

        using var held = one.TryEnter();

        using var free = other.TryEnter();
        Assert.NotNull(free);
    }
}
