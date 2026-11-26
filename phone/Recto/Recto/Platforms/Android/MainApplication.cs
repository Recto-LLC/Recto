using Android.App;
using Android.Runtime;
using Recto.Platforms.AndroidImpl;

namespace Recto;

[Application]
public class MainApplication : MauiApplication
{
    public MainApplication(IntPtr handle, JniHandleOwnership ownership)
        : base(handle, ownership)
    {
    }

    protected override MauiApp CreateMauiApp() => MauiProgram.CreateMauiApp();

    /// <summary>
    /// The process started (for the activity, or for a push with the app
    /// closed): the channel a push wake's notification is shown on exists
    /// before the first one arrives.
    /// </summary>
    public override void OnCreate()
    {
        base.OnCreate();
        AndroidPushWakeNotice.EnsureChannel(this);
    }
}
