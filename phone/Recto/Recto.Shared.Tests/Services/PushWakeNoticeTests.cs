using System;
using System.IO;
using System.Text.RegularExpressions;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests.Services;

/// <summary>
/// A push wake shows one fixed notification. The words are the bootloader's
/// constants, the phone reads nothing else from a push, and a build with no
/// Firebase configuration is unchanged.
/// </summary>
public class PushWakeNoticeTests
{
    [Fact]
    public void TheWords_AreFixed()
    {
        Assert.Equal("Recto", PushWakeNotice.Title);
        Assert.Equal("Something is waiting for your approval in Recto.", PushWakeNotice.Body);
        Assert.Equal("recto", PushWakeNotice.MarkerKey);
        Assert.Equal("pending_wake", PushWakeNotice.Marker);
        Assert.Equal("recto_pending", PushWakeNotice.ChannelId);
    }

    [Fact]
    public void TheBootloaderSends_ThePhonesWordsAndChannel()
    {
        var push = File.ReadAllText(Path.Combine(RepoRoot(), "recto", "bootloader", "push.py"));

        Assert.Contains($"WAKE_TITLE = \"{PushWakeNotice.Title}\"", push);
        Assert.Contains($"WAKE_BODY = \"{PushWakeNotice.Body}\"", push);
        Assert.Contains($"WAKE_MARKER = \"{PushWakeNotice.Marker}\"", push);
        Assert.Contains($"WAKE_COLLAPSE_ID = \"{PushWakeNotice.ChannelId}\"", push);
        Assert.Contains($"\"data\": {{\"{PushWakeNotice.MarkerKey}\": WAKE_MARKER}}", push);
        // The sentence is a constant: nothing is formatted into it.
        Assert.DoesNotMatch(new Regex(@"WAKE_(TITLE|BODY)\s*=\s*f[""']"), push);
        Assert.DoesNotMatch(new Regex(@"WAKE_(TITLE|BODY)\s*(\+|%|\.format)"), push);
    }

    [Fact]
    public void TheChannelsOwnWords_NameNoCardServiceOrCount()
    {
        foreach (var text in new[] { PushWakeNotice.Title, PushWakeNotice.Body, PushWakeNotice.ChannelName, PushWakeNotice.ChannelDescription })
        {
            Assert.DoesNotContain("{", text);
            Assert.DoesNotMatch(new Regex(@"\d"), text);
        }
    }

    [Fact]
    public void Android_MakesTheChannel_AsksThePermission_AndATapOnlySignals()
    {
        var notice = Android("AndroidPushWakeNotice.cs");
        Assert.Contains("new NotificationChannel(", notice);
        Assert.Contains("PushWakeNotice.ChannelId, PushWakeNotice.ChannelName, NotificationImportance.High", notice);
        Assert.Contains("channel.SetShowBadge(false);", notice);              // no dot and no number on the icon
        Assert.Contains("OperatingSystem.IsAndroidVersionAtLeast(33)", notice);
        Assert.Contains("Manifest.Permission.PostNotifications", notice);
        // The permission is asked only where push is set up: a build with no Firebase configuration asks nothing.
        var ask = notice.Substring(notice.IndexOf("public static void RequestPermission", StringComparison.Ordinal));
        ask = ask.Substring(0, ask.IndexOf("public static bool IsWakeTap", StringComparison.Ordinal));
        Assert.True(ask.IndexOf("if (!PushIsSetUp(activity)) return;", StringComparison.Ordinal)
            < ask.IndexOf("activity.RequestPermissions(", StringComparison.Ordinal));
        Assert.Contains("Firebase.FirebaseApp.GetApps(context).Count > 0", notice);

        Assert.Contains("AndroidPushWakeNotice.EnsureChannel(this);", Android("MainApplication.cs"));
        var activity = Android("MainActivity.cs");
        Assert.Contains("AndroidPushWakeNotice.RequestPermission(this);", activity);
        Assert.Contains("if (AndroidPushWakeNotice.IsWakeTap(intent))", activity);
        Assert.Contains("android.permission.POST_NOTIFICATIONS", Android("AndroidManifest.xml"));

        // Nothing of a push is read but the one marker; no notification is built from a message's content.
        var service = Android("RectoFirebaseMessagingService.cs");
        foreach (var source in new[] { notice, activity, service })
        {
            Assert.DoesNotContain("GetNotification()", source);
            Assert.DoesNotContain(".Data[", source);
            Assert.DoesNotContain("NotificationCompat", source);
            Assert.DoesNotContain("SetContentText", source);
        }
        Assert.Single(Regex.Matches(notice + activity + service, @"GetStringExtra\("));
    }

    [Fact]
    public void TheBuild_StillNeedsNoFirebaseConfiguration()
    {
        var project = File.ReadAllText(Path.Combine(PhoneRoot(), "Recto", "Recto.csproj"));
        Assert.Contains("Condition=\"Exists('Platforms\\Android\\google-services.json')\"", project);
        Assert.False(File.Exists(Path.Combine(PhoneRoot(), "Recto", "Platforms", "Android", "google-services.json")));
    }

    [Fact]
    public void Ios_KeepsItsEntitlementsAndBackgroundMode()
    {
        var ios = Path.Combine(PhoneRoot(), "Recto", "Platforms", "iOS");
        Assert.Contains("aps-environment", File.ReadAllText(Path.Combine(ios, "Entitlements.plist")));
        Assert.Contains("aps-environment", File.ReadAllText(Path.Combine(ios, "Entitlements.Release.plist")));
        Assert.Contains("remote-notification", File.ReadAllText(Path.Combine(ios, "Info.plist")));
        // Pairing asks for the alert permission; the wake's handler reads nothing from the push.
        Assert.Contains("UNAuthorizationOptions.Alert", File.ReadAllText(Path.Combine(ios, "IosApnsPushTokenService.cs")));
        var handler = File.ReadAllText(Path.Combine(ios, "AppDelegate.cs"));
        handler = handler.Substring(handler.IndexOf("public void DidReceiveRemoteNotification", StringComparison.Ordinal));
        Assert.DoesNotContain("userInfo[", handler);
        Assert.Contains("InMemoryPushWakeSignal.SignalWakeGlobal();", handler);
    }

    private static string Android(string file)
        => File.ReadAllText(Path.Combine(PhoneRoot(), "Recto", "Platforms", "Android", file));

    private static string PhoneRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Recto", "MauiProgram.cs"))) dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "recto", "bootloader", "push.py"))) dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
