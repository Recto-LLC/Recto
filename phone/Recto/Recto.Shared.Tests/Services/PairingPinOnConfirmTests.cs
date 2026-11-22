using Recto.Shared.Services;
using Recto.Shared.Tests.Capability;
using Xunit;

namespace Recto.Shared.Tests.Services;

/// <summary>
/// A bootloader's certificate becomes this phone's anchor only when the
/// pairing is confirmed: registered, the poll key echoed, the identity
/// checked and the state saved. A pairing refused at any of those leaves no
/// anchor for its host. Before, the anchor was set as soon as the register
/// call answered, so a pairing refused a line later still left a self-signed
/// host accepted for the life of the process.
/// </summary>
public class PairingPinOnConfirmTests
{
    private const string Host = "bootloader.example";
    private const string Pin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    // --- the pairing flow, pinned from the page's text ---

    [Fact]
    public void ThePairFlow_ReadsTheObservedPin_AndSetsTheAnchorOnlyAfterTheSave()
    {
        var pair = ProfileSigningInputTests.MethodBody(ProfileSigningInputTests.HomePage(), "HandlePairClick");

        // The flow itself never sets a pin; it reads what the connection showed.
        Assert.DoesNotContain("Pinning.SetPin(", pair);
        var read = pair.IndexOf("observedPin = ObservedBootloaderPin(_bootloaderUrl);", StringComparison.Ordinal);
        Assert.True(read > 0);

        // The anchor is set once, from the saved state, after every check that can still refuse the pairing.
        var anchor = pair.IndexOf("RestorePin(pairedState);", StringComparison.Ordinal);
        Assert.True(anchor > read);
        Assert.Equal(anchor, pair.LastIndexOf("RestorePin(", StringComparison.Ordinal));
        foreach (var check in new[]
        {
            "if (!registerResult.Value.Registered)",
            "if (registration.PollPublicKeyB64u != pollPubB64u)",
            "if (identityCheck.Status == BootloaderIdentityStatus.Refused)",
            "BootloaderSpkiPin: observedPin,",
            "await Pairing.SaveAsync(pairedState, CancellationToken.None);",
            "if (saveResult.IsFailure)",
        })
        {
            var at = pair.IndexOf(check, StringComparison.Ordinal);
            Assert.True(at > 0, $"the pair flow no longer has: {check}");
            Assert.True(at < anchor, $"the anchor is set before: {check}");
        }

        // No way out between the save's own refusal and the anchor.
        var saved = pair.IndexOf("if (saveResult.IsFailure)", StringComparison.Ordinal);
        Assert.Equal(1, Count(pair.Substring(saved, anchor - saved), "return;"));
        // The window still closes on every way out.
        Assert.Contains("finally\n        {\n            Pinning.EndPairing();", pair.Replace("\r\n", "\n"));
    }

    [Fact]
    public void TheObservedPinReader_SetsNothing()
    {
        var page = ProfileSigningInputTests.HomePage();
        var reader = ProfileSigningInputTests.MethodBody(page, "ObservedBootloaderPin");

        Assert.Contains("Pinning.GetObservedPin(", reader);
        Assert.DoesNotContain("SetPin", reader);
        Assert.DoesNotContain("TryCaptureBootloaderPin", page);
    }

    [Fact]
    public void ThePage_SetsAPinInOnePlace_FromASavedState()
    {
        var page = ProfileSigningInputTests.HomePage();

        Assert.Equal(1, Count(page, "Pinning.SetPin("));
        Assert.Contains(
            "Pinning.SetPin(host, state.BootloaderSpkiPin);",
            ProfileSigningInputTests.MethodBody(page, "RestorePin"));
    }

    // --- what a refused pairing leaves behind ---

    [Fact]
    public void APairingThatEndsUnconfirmed_LeavesNoAnchor_AndItsHostIsRefusedAgain()
    {
        var pinning = new PinningService();

        // The pairing window: the self-signed certificate is accepted and observed.
        pinning.BeginPairing(Host);
        Assert.True(pinning.Validate(Host, Pin, systemTrustOk: false));
        Assert.Equal(Pin, pinning.GetObservedPin(Host));

        // The pairing is refused after the register call: the flow reads the observed pin and sets nothing.
        pinning.EndPairing();

        Assert.Null(pinning.GetPin(Host));
        Assert.False(pinning.Validate(Host, Pin, systemTrustOk: false));
    }

    [Fact]
    public void AConfirmedPairing_SetsTheAnchor_AndItsHostIsAcceptedAfterTheWindowCloses()
    {
        var pinning = new PinningService();
        pinning.BeginPairing(Host);
        Assert.True(pinning.Validate(Host, Pin, systemTrustOk: false));

        // Confirmed and saved: the anchor is set from the saved state, then the window closes.
        pinning.SetPin(Host, pinning.GetObservedPin(Host)!);
        pinning.EndPairing();

        Assert.True(pinning.Validate(Host, Pin, systemTrustOk: false));
        Assert.False(pinning.Validate(Host, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", systemTrustOk: false));
    }

    private static int Count(string text, string needle)
    {
        var n = 0;
        for (var at = text.IndexOf(needle, StringComparison.Ordinal); at >= 0;
             at = text.IndexOf(needle, at + needle.Length, StringComparison.Ordinal))
        {
            n++;
        }
        return n;
    }
}
