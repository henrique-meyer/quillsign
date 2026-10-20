using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Razor.TagHelpers;
using Microsoft.Net.Http.Headers;

namespace QuillSign.Documents;

public sealed class PdfFilePresentationOptions
{
    public bool ViewInsteadOfDownload { get; set; }
}

// Presentation only: the page handler must still authorize and prepare the exact file.
public sealed class PdfFilePresentationFilter(PdfFilePresentationOptions options) : IResultFilter
{
    public void OnResultExecuting(ResultExecutingContext context)
    {
        if (!options.ViewInsteadOfDownload || context.Result is not FileResult file ||
            string.IsNullOrEmpty(file.FileDownloadName) ||
            !MediaTypeHeaderValue.TryParse(file.ContentType, out var type) ||
            !type.MediaType.Equals("application/pdf", StringComparison.OrdinalIgnoreCase)) return;

        var disposition = new ContentDispositionHeaderValue("inline");
        disposition.SetHttpFileName(file.FileDownloadName);
        context.HttpContext.Response.GetTypedHeaders().ContentDisposition = disposition;
        // The MVC executor writes attachment when this property is populated.
        file.FileDownloadName = string.Empty;
    }

    public void OnResultExecuted(ResultExecutedContext context) { }
}

[HtmlTargetElement("a", Attributes = "pdf-file-action")]
[HtmlTargetElement("form", Attributes = "pdf-file-action")]
[HtmlTargetElement("button", Attributes = "pdf-file-label")]
public sealed class PdfFileActionTagHelper(PdfFilePresentationOptions options) : TagHelper
{
    [HtmlAttributeName("pdf-file-label")]
    public string? Label { get; set; }

    public override void Process(TagHelperContext context, TagHelperOutput output)
    {
        output.Attributes.RemoveAll("pdf-file-action");
        output.Attributes.RemoveAll("pdf-file-label");
        if (!options.ViewInsteadOfDownload) return;
        if (output.TagName is "a" or "form")
        {
            output.Attributes.SetAttribute("target", "_blank");
            output.Attributes.SetAttribute("rel", "noopener noreferrer");
        }
        if (Label is not null)
        {
            output.Content.SetContent("View " + Label);
            output.Attributes.SetAttribute("aria-label", "View " + Label + " (opens in a new tab)");
        }
    }
}
