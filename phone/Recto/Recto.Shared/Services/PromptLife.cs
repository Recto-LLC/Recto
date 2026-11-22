using System;
using System.Threading;

namespace Recto.Shared.Services;

/// <summary>
/// The whole life a showing biometric prompt is given. Past
/// <see cref="Limit"/> from the moment it is asked, the signing is ended
/// whatever the prompt is doing: the caller is answered
/// <see cref="LapsedMessage"/>, nothing is signed, everything it holds is
/// released - the single-flight pass included - and the prompt is asked to
/// close.
/// <para>
/// WHY. Every other way a prompt ends rests on its ending reaching the app.
/// When the screen is rebuilt under the prompt (a change of language, font
/// size or keyboard), the app's activity does not restore the prompt's
/// fragment, so the prompt's ending may never arrive, while the rebuilt
/// screen reads as alive. Without a limit that one prompt would hold the
/// flight, and refuse every approval, for the life of the process. With it
/// the phone is never stuck for longer than this.
/// </para>
/// </summary>
public sealed class PromptLife : IDisposable
{
    /// <summary>How long a prompt may stand from the moment it is asked.</summary>
    public static readonly TimeSpan Limit = TimeSpan.FromMinutes(3);

    /// <summary>What the caller is told when the limit ends a signing.</summary>
    public const string LapsedMessage = "The approval was not answered in time. Nothing was signed.";

    private readonly TimeProvider _clock;
    private readonly DateTimeOffset _deadline;
    private Action? _lapse;
    private ITimer? _timer;

    /// <summary>
    /// Starts the prompt's life now. <paramref name="lapse"/> runs once, on a
    /// timer thread, when the limit is reached and the life was not ended
    /// first by <see cref="Dispose"/>.
    /// </summary>
    public PromptLife(Action lapse, TimeProvider? clock = null, TimeSpan? limit = null)
    {
        _lapse = lapse ?? throw new ArgumentNullException(nameof(lapse));
        _clock = clock ?? TimeProvider.System;
        var span = limit ?? Limit;
        _deadline = _clock.GetUtcNow() + span;
        var timer = _clock.CreateTimer(_ => Lapse(), null, span, Timeout.InfiniteTimeSpan);
        if (Interlocked.CompareExchange(ref _timer, timer, null) is not null || Volatile.Read(ref _lapse) is null)
        {
            // Ended (or lapsed) while the timer was being made.
            timer.Dispose();
        }
    }

    /// <summary>
    /// How long past the limit a pass may still be held before the next
    /// signing takes it back. The lapse ends a prompt at the limit; this is
    /// only the backstop for a lapse that never ran (its main thread never
    /// came round), so it must never race the lapse at the limit itself.
    /// </summary>
    public static readonly TimeSpan Grace = TimeSpan.FromSeconds(10);

    /// <summary>True once the limit is reached.</summary>
    public bool IsOver => _clock.GetUtcNow() >= _deadline;

    /// <summary>True once the limit and <paramref name="grace"/> past it are reached.</summary>
    public bool IsOverBy(TimeSpan grace) => _clock.GetUtcNow() >= _deadline + grace;

    /// <summary>
    /// The words a signing ended from outside is answered with: the lapse's
    /// own once the limit is reached - the prompt ran out of time, whatever
    /// else is true - and <paramref name="otherwise"/> before it.
    /// </summary>
    public string WordsForAnEnding(string otherwise) => IsOver ? LapsedMessage : otherwise;

    private void Lapse()
    {
        var lapse = Interlocked.Exchange(ref _lapse, null);
        try
        {
            lapse?.Invoke();
        }
        catch
        {
            // The pass is still taken back by the next signing, Grace past the limit.
        }
    }

    /// <summary>The prompt has ended: the limit no longer applies. Safe to call twice.</summary>
    public void Dispose()
    {
        Volatile.Write(ref _lapse, null);
        Interlocked.Exchange(ref _timer, NoTimer.Instance)?.Dispose();
    }

    /// <summary>Stands in for a timer already disposed, so a late constructor never keeps one running.</summary>
    private sealed class NoTimer : ITimer
    {
        public static readonly NoTimer Instance = new();

        public bool Change(TimeSpan dueTime, TimeSpan period) => false;

        public void Dispose() { }

        public System.Threading.Tasks.ValueTask DisposeAsync() => default;
    }
}
