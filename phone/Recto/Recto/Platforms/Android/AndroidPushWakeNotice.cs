using Android;
using Android.App;
using Android.Content;
using Android.Content.PM;
using Recto.Shared.Services;

namespace Recto.Platforms.AndroidImpl;

/// <summary>
/// What Android needs to SHOW a push wake. The bootloader's wake carries a
/// notification with one fixed sentence (<see cref="PushWakeNotice"/>); the
/// system draws it when the app is not in front, on the channel made here,
/// and only once the person has allowed notifications (Android 13 and later
/// ask at run time).
/// <para>
/// Nothing here reads a push's content, and nothing here needs Firebase: in a
/// build with no google-services.json there is no token, so no wake arrives,
/// the permission is not asked, and the app runs as it did.
/// </para>
/// </summary>
public static class AndroidPushWakeNotice
{
    private const int PermissionRequestCode = 4125;

    /// <summary>
    /// Makes the channel once. Safe on every start: an existing channel keeps
    /// whatever the person set for it in system settings.
    /// </summary>
    public static void EnsureChannel(Context context)
    {
        try
        {
            if (!OperatingSystem.IsAndroidVersionAtLeast(26)) return;
            if (context.GetSystemService(Context.NotificationService) is not NotificationManager manager) return;
            if (manager.GetNotificationChannel(PushWakeNotice.ChannelId) is not null) return;
            var channel = new NotificationChannel(
                PushWakeNotice.ChannelId, PushWakeNotice.ChannelName, NotificationImportance.High)
            {
                Description = PushWakeNotice.ChannelDescription,
            };
            // No dot and no number on the app's icon: a wake never says how many.
            channel.SetShowBadge(false);
            manager.CreateNotificationChannel(channel);
        }
        catch
        {
            // A start must not fail on a notification channel; polling still finds every card.
        }
    }

    /// <summary>
    /// Asks for the notification permission where Android asks at run time
    /// (13 and later), when it is not yet granted and push is set up in this
    /// build. Android itself stops showing the question after it is refused.
    /// </summary>
    public static void RequestPermission(Activity activity)
    {
        try
        {
            if (!OperatingSystem.IsAndroidVersionAtLeast(33)) return;
            if (activity.CheckSelfPermission(Manifest.Permission.PostNotifications) == Permission.Granted) return;
            if (!PushIsSetUp(activity)) return;
            activity.RequestPermissions(new[] { Manifest.Permission.PostNotifications }, PermissionRequestCode);
        }
        catch
        {
            // Without the permission nothing is shown; the app and its polling are unaffected.
        }
    }

    /// <summary>True when the person opened the app by tapping the wake's notification.</summary>
    public static bool IsWakeTap(Intent? intent)
    {
        try
        {
            return intent?.GetStringExtra(PushWakeNotice.MarkerKey) == PushWakeNotice.Marker;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>The app is in front: the notification has done its work.</summary>
    public static void ClearShown(Context context)
    {
        try
        {
            (context.GetSystemService(Context.NotificationService) as NotificationManager)?.CancelAll();
        }
        catch
        {
            // Nothing depends on it.
        }
    }

    // Firebase starts only in a build that carries google-services.json.
    private static bool PushIsSetUp(Context context)
    {
        try
        {
            return Firebase.FirebaseApp.GetApps(context).Count > 0;
        }
        catch
        {
            return false;
        }
    }
}
