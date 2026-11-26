namespace Recto.Shared.Services;

/// <summary>
/// What the app does by itself when it returns to the foreground with polling
/// stopped. One case only: the stop was for a reply that the pinned key
/// signed and that was merely out of date, twice in a row - usually a phone
/// clock since corrected, or an app frozen for a long time. Then the full
/// identity check runs once, as if the person had tapped "Re-verify server".
/// <para>
/// Every other stop - a key that changed, a reply the pinned key did not
/// sign, a bootloader that did not answer, a pairing with no pinned key -
/// stays stopped until the person taps. A resume never restarts polling
/// without the check passing in full.
/// </para>
/// </summary>
public static class ResumePolicy
{
    /// <summary>The title the banner carries by default: a refusal about the server's identity.</summary>
    public const string IdentityChangedTitle = "Server identity changed.";

    /// <summary>The title when the pinned key signed the reply and it was only out of date.</summary>
    public const string OutOfDateTitle = "Out-of-date reply from the bootloader.";

    /// <summary>The title when the bootloader did not answer the identity check at all.</summary>
    public const string NoAnswerTitle = "Could not check the bootloader.";

    /// <param name="pollingStopped">No poll loop is running.</param>
    /// <param name="stoppedOnStaleOnly">The stop was for an out-of-date reply and nothing else.</param>
    /// <param name="reverifying">An identity check is already in flight.</param>
    public static bool ShouldReverifyOnResume(bool pollingStopped, bool stoppedOnStaleOnly, bool reverifying)
        => pollingStopped && stoppedOnStaleOnly && !reverifying;
}
