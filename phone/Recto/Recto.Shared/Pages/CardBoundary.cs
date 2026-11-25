using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Rendering;

namespace Recto.Shared.Pages;

/// <summary>
/// One card's drawing, kept to that card: what throws while it is drawn is
/// that card's refusal, and the cards beside it stand. Nothing of a card is
/// logged (hard rule 15.ab).
/// </summary>
public sealed class CardBoundary : ErrorBoundaryBase
{
    protected override Task OnErrorAsync(Exception exception) => Task.CompletedTask;

    protected override void BuildRenderTree(RenderTreeBuilder builder)
    {
        if (CurrentException is null) builder.AddContent(0, ChildContent);
        else if (ErrorContent is not null) builder.AddContent(1, ErrorContent(CurrentException));
    }
}
