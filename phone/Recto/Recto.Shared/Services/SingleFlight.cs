using System;
using System.Threading;

namespace Recto.Shared.Services;

/// <summary>
/// One at a time, and the second is refused, never queued.
/// <see cref="TryEnter"/> answers a pass while nothing holds the flight and
/// null while something does; the flight is free again when the pass is
/// released. Releasing a pass twice is the same as releasing it once, and a
/// pass can only ever free the flight it was given for: a late release from
/// an earlier holder cannot free a later one's.
/// <para>
/// A HOLDER THAT IS GONE DOES NOT HOLD FOR EVER. A holder may say how to
/// tell that it has been abandoned and what to do then
/// (<see cref="Pass.Watch"/>). When the flight is held, <see cref="TryEnter"/>
/// asks the holder; an abandoned holder is ended - its own action runs, once
/// - and the flight is taken by the newcomer. Without this, a holder whose
/// ending is never delivered would refuse every later entry for the life of
/// the process. A holder that cannot be asked (its test throws) is treated
/// as abandoned: a flight stuck shut is the worse fault.
/// </para>
/// <para>
/// The Android key service holds one of these, process-wide, around the
/// biometric prompt: the prompt library keeps one callback per activity and
/// returns without showing when a prompt is already up, so a second signing
/// started under a showing prompt would take over its callback and leave the
/// first caller unanswered. Its pass watches the activity the prompt
/// belongs to now, followed across a configuration change (<see cref="PromptHost{TScreen}"/>).
/// </para>
/// </summary>
public sealed class SingleFlight
{
    private Pass? _holder;

    /// <summary>True while a pass is out.</summary>
    public bool IsHeld => Volatile.Read(ref _holder) is not null;

    /// <summary>
    /// A pass when the flight was free, or was held by a holder that has
    /// been abandoned; null when it is held by one that has not.
    /// </summary>
    public Pass? TryEnter()
    {
        var pass = new Pass(this);
        if (Interlocked.CompareExchange(ref _holder, pass, null) is null)
        {
            return pass;
        }
        var holder = Volatile.Read(ref _holder);
        if (holder is not null)
        {
            if (!holder.IsAbandoned())
            {
                return null;
            }
            holder.Abandon();
        }
        return Interlocked.CompareExchange(ref _holder, pass, null) is null ? pass : null;
    }

    /// <summary>The right to the flight, until it is released.</summary>
    public sealed class Pass : IDisposable
    {
        private readonly SingleFlight _flight;
        private Func<bool>? _isAbandoned;
        private Action? _abandon;
        private TimeProvider? _lingerClock;
        private TimeSpan _lingerFor;
        private ITimer? _lingering;

        internal Pass(SingleFlight flight) => _flight = flight;

        /// <summary>
        /// How to tell this holder has been abandoned, and what to do when it
        /// has: <paramref name="abandon"/> runs at most once, and the pass is
        /// released after it whatever it does. A pass that is never watched
        /// is never taken from its holder.
        /// </summary>
        public void Watch(Func<bool> isAbandoned, Action abandon)
        {
            // The action first, the test published last: a TryEnter on another
            // thread that sees the test also sees the action it ends with.
            _abandon = abandon;
            Volatile.Write(ref _isAbandoned, isAbandoned);
        }

        internal bool IsAbandoned()
        {
            var test = Volatile.Read(ref _isAbandoned);
            if (test is null)
            {
                return false;
            }
            try
            {
                return test();
            }
            catch
            {
                return true;
            }
        }

        internal void Abandon()
        {
            var abandon = Interlocked.Exchange(ref _abandon, null);
            try
            {
                abandon?.Invoke();
            }
            catch
            {
                // The flight is freed all the same.
            }
            Dispose();
        }

        /// <summary>
        /// Asks that the flight be held a moment longer after this pass is
        /// released: when it is, the flight is freed only
        /// <paramref name="hold"/> later. A holder ended from outside (its
        /// prompt ran out of time) may still hear its prompt's own late
        /// ending; held a moment, that ending lands on no one. While the
        /// flight is held so, a newcomer is refused, never let in and never
        /// told the holder was abandoned.
        /// </summary>
        public void Linger(TimeSpan hold, TimeProvider? clock = null)
        {
            _lingerFor = hold;
            Volatile.Write(ref _lingerClock, clock ?? TimeProvider.System);
        }

        public void Dispose()
        {
            _isAbandoned = null;
            _abandon = null;
            if (Volatile.Read(ref _lingering) is not null)
            {
                // Already released, and held a moment: the timer frees it.
                return;
            }
            var clock = Interlocked.Exchange(ref _lingerClock, null);
            if (clock is not null && _lingerFor > TimeSpan.Zero)
            {
                // Kept in a field: a timer nothing references can be collected
                // before it fires, and the flight would then never be freed.
                ITimer timer;
                try
                {
                    timer = clock.CreateTimer(_ => Free(), null, _lingerFor, Timeout.InfiniteTimeSpan);
                }
                catch
                {
                    // A timer that cannot be made must never leave the flight held: free it now.
                    Free();
                    return;
                }
                if (Interlocked.CompareExchange(ref _lingering, timer, null) is not null)
                {
                    timer.Dispose();
                }
                return;
            }
            Free();
        }

        /// <summary>Frees the flight only while this pass is the one holding it.</summary>
        private void Free()
        {
            Interlocked.CompareExchange(ref _flight._holder, null, this);
            Interlocked.Exchange(ref _lingering, null)?.Dispose();
        }
    }
}
