using System;

namespace Recto.Shared.Services;

/// <summary>
/// Which screen a showing prompt belongs to, kept true across the screen
/// being rebuilt.
/// <para>
/// A prompt is shown on one screen object (on Android, an activity). The
/// system can rebuild that object under the prompt for a configuration
/// change - language, font size, layout direction, a keyboard - and the
/// prompt lives through it: the old object is destroyed, a new one is
/// created, and the prompt answers as before. A screen destroyed for any
/// other reason takes the prompt's answer with it.
/// </para>
/// <para>
/// So "is this prompt's screen gone?" cannot be asked of the object the
/// prompt was first shown on. This follows the screen: a destroy for a
/// configuration change is noted and the next screen created becomes the
/// watched one; only a destroy that is not for a configuration change, or a
/// watched screen that reads as destroyed, finishing or no longer current,
/// counts as gone. The platform's own reads are passed in, so the rule
/// itself is plain code with no platform type in it.
/// </para>
/// <para>
/// THE PLATFORM'S FLAG COMES FIRST. Android marks an activity as changing
/// configurations, then as destroyed, and tells the lifecycle watch only at
/// the end of the destroy. A signing asked in that window would read the old
/// activity as destroyed with no rebuild yet noted. So the screen's own
/// "changing configurations" is read before anything else and, when true,
/// the screen is not gone; and a "gone" read is checked again under the lock
/// before it is answered, so a rebuild noted while the platform was being
/// read wins.
/// </para>
/// <para>
/// A REBUILD THAT NEVER FINISHES DOES NOT HOLD FOR EVER. A rebuild noted for
/// longer than <see cref="RebuildLimit"/> with no new screen created counts
/// as gone: a prompt whose screen was never rebuilt cannot answer, and a
/// flight held for ever would refuse every approval.
/// </para>
/// </summary>
/// <typeparam name="TScreen">The platform's screen object.</typeparam>
public sealed class PromptHost<TScreen> where TScreen : class
{
    /// <summary>How long a noted rebuild may stand with no new screen before it counts as gone.</summary>
    public static readonly TimeSpan RebuildLimit = TimeSpan.FromSeconds(10);

    // The lifecycle events arrive on the main thread; IsGone is asked from
    // whatever thread starts the next signing. One lock keeps the facts read
    // together as they were written together. No platform read runs under it.
    private readonly object _gate = new();
    private readonly TimeProvider _clock;
    private TScreen _watched;
    private bool _rebuilding;
    private DateTimeOffset _rebuildingSince;
    private bool _destroyed;

    public PromptHost(TScreen shownOn, TimeProvider? clock = null)
    {
        _watched = shownOn ?? throw new ArgumentNullException(nameof(shownOn));
        _clock = clock ?? TimeProvider.System;
    }

    /// <summary>The screen the prompt belongs to now.</summary>
    public TScreen Watched
    {
        get { lock (_gate) { return _watched; } }
    }

    /// <summary>True between a configuration-change destroy and the next screen's creation.</summary>
    public bool IsRebuilding
    {
        get { lock (_gate) { return _rebuilding; } }
    }

    /// <summary>
    /// A screen was destroyed. Answers true when it was the watched screen
    /// and the destroy was for good: the prompt's answer will not come, and
    /// the caller should end the signing. A destroy for a configuration
    /// change answers false and is noted, and the backstop's time starts
    /// from it; a destroy of any other screen is nothing to this prompt.
    /// </summary>
    public bool Destroyed(TScreen screen, bool forConfigurationChange)
    {
        lock (_gate)
        {
            if (!ReferenceEquals(screen, _watched) || _destroyed)
            {
                return false;
            }
            if (forConfigurationChange)
            {
                _rebuilding = true;
                _rebuildingSince = _clock.GetUtcNow();
                return false;
            }
            _destroyed = true;
            return true;
        }
    }

    /// <summary>
    /// A screen was created. While a rebuild is noted, it becomes the
    /// watched screen; otherwise it is nothing to this prompt.
    /// </summary>
    public void Created(TScreen screen)
    {
        lock (_gate)
        {
            if (_rebuilding && !_destroyed && screen is not null)
            {
                _watched = screen;
                _rebuilding = false;
            }
        }
    }

    /// <summary>
    /// True when the prompt's screen can no longer deliver the prompt's
    /// answer. Never true while a rebuild is noted and younger than
    /// <see cref="RebuildLimit"/>, nor while the watched screen reads as
    /// changing configurations: the prompt is alive, and the screen it will
    /// answer on is about to be created. Otherwise true when the watched
    /// screen was destroyed for good, or reads as destroyed, finishing, or
    /// not the current screen - and still so once the reads are done.
    /// </summary>
    /// <param name="isChangingConfigurations">The platform's "this screen is being rebuilt for a configuration change".</param>
    /// <param name="isDestroyed">The platform's "this screen is destroyed".</param>
    /// <param name="isFinishing">The platform's "this screen is finishing".</param>
    /// <param name="current">
    /// Reads the app's current screen, as the platform has it. Read here,
    /// after the watched screen is taken from the lock, never before: a value
    /// read earlier can predate a rebuild that has since finished, and would
    /// make the new screen read as "not current".
    /// </param>
    public bool IsGone(
        Func<TScreen, bool> isChangingConfigurations,
        Func<TScreen, bool> isDestroyed,
        Func<TScreen, bool> isFinishing,
        Func<TScreen?> current)
    {
        TScreen watched;
        lock (_gate)
        {
            if (_destroyed)
            {
                return true;
            }
            if (_rebuilding)
            {
                return RebuildExpired();
            }
            watched = _watched;
        }

        // The platform's reads run outside the lock: they may call into it.
        if (isChangingConfigurations(watched))
        {
            // Rebuilt under the prompt; the lifecycle watch has not heard yet.
            // Noted here, so the next screen created is taken and the
            // backstop's time runs even if the watch never hears.
            Note(watched);
            return false;
        }
        var gone = isDestroyed(watched) || isFinishing(watched) || !ReferenceEquals(current(), watched);
        if (!gone)
        {
            return false;
        }
        // Asked again, once the reads are done: a rebuild noted, or a new
        // screen taken, while they ran is the prompt living on.
        if (isChangingConfigurations(watched))
        {
            Note(watched);
            return false;
        }
        lock (_gate)
        {
            if (_destroyed)
            {
                return true;
            }
            return !_rebuilding && ReferenceEquals(watched, _watched);
        }
    }

    /// <summary>Notes a rebuild of <paramref name="screen"/> seen on the screen itself, when it is still the watched one.</summary>
    private void Note(TScreen screen)
    {
        lock (_gate)
        {
            if (!_destroyed && !_rebuilding && ReferenceEquals(screen, _watched))
            {
                _rebuilding = true;
                _rebuildingSince = _clock.GetUtcNow();
            }
        }
    }

    /// <summary>
    /// Under the lock, with a rebuild noted: true, and gone for good, once
    /// the rebuild has stood for <see cref="RebuildLimit"/>.
    /// </summary>
    private bool RebuildExpired()
    {
        if (_clock.GetUtcNow() - _rebuildingSince < RebuildLimit)
        {
            return false;
        }
        _destroyed = true;
        return true;
    }
}
