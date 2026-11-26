namespace Recto.Shared.Services;

/// <summary>
/// The one notification a push wake shows. The bootloader sends these exact
/// words with every wake (<c>recto/bootloader/push.py</c>: WAKE_TITLE,
/// WAKE_BODY, WAKE_MARKER, WAKE_COLLAPSE_ID); the phone's system draws them.
/// They name no card, no service, no agent and no count, and the app never
/// reads anything else from a push: a wake only says "fetch your queue over
/// the paired channel".
/// </summary>
public static class PushWakeNotice
{
    public const string Title = "Recto";
    public const string Body = "Something is waiting for your approval in Recto.";

    /// <summary>The data key and value an open app sees on a wake.</summary>
    public const string MarkerKey = "recto";
    public const string Marker = "pending_wake";

    /// <summary>The Android notification channel the wake is posted on, and the id every wake collapses under.</summary>
    public const string ChannelId = "recto_pending";
    public const string ChannelName = "Approvals waiting";
    public const string ChannelDescription = "Tells you that something is waiting for your approval. It never says what.";
}
