using System.Text.Json;
using QuillSign.Data;
using QuillSign.Documents;

namespace QuillSign.Completion;

// The legacy stage string/recipe remains byte-for-byte unchanged. A versioned
// wrapper binds upload policy without adding mutable publication metadata.
internal static class CompletionRetentionBinding
{
    private const string Version="completion-upload-retention-v1";
    private sealed record Policy(Guid EnvelopeId,string PolicyVersion,int Days,DateTimeOffset StartedAt,DateTimeOffset DeleteAfter,
        Guid OriginalObjectId,byte[] OriginalSha256,Guid PdfObjectId,byte[] PdfSha256);
    private sealed record Binding(string RetentionVersion,JsonElement Stages,Policy UploadRetention);
    internal static string Bind(string stages,DocumentRetentionSnapshot? row)
    {
        if(row is null)return stages;
        using var document=JsonDocument.Parse(stages);
        return JsonSerializer.Serialize(new Binding(Version,document.RootElement.Clone(),new(row.EnvelopeId,row.PolicyVersion,row.Days,row.StartedAt,row.DeleteAfter,
            row.OriginalObjectId,row.OriginalSha256,row.PdfObjectId,row.PdfSha256)));
    }
    internal static DateTimeOffset? FixedUntil(CompletionPublicationIntent intent)
    {
        try
        {
            using var document=JsonDocument.Parse(intent.StageBindingsJson,new JsonDocumentOptions {MaxDepth=12});var root=document.RootElement;
            var version=root.TryGetProperty(nameof(Binding.RetentionVersion),out var v);var policy=root.TryGetProperty(nameof(Binding.UploadRetention),out var p);
            if(!version && !policy)return null;
            if(!version || !policy || v.GetString()!=Version || !root.TryGetProperty(nameof(Binding.Stages),out var stages) || stages.ValueKind!=JsonValueKind.Object)throw Invalid();
            var row=p.Deserialize<Policy>() ?? throw Invalid();
            if(row.EnvelopeId!=intent.EnvelopeId || row.PolicyVersion!=UploadRetention.Version || row.Days is <1 or >36500 || row.Days!=intent.RetentionDays ||
                row.StartedAt.Offset!=TimeSpan.Zero || row.DeleteAfter.Offset!=TimeSpan.Zero || row.StartedAt.Ticks%TimeSpan.TicksPerSecond!=0 ||
                row.DeleteAfter!=row.StartedAt.AddDays(row.Days) || row.OriginalObjectId==Guid.Empty || row.PdfObjectId==Guid.Empty || row.OriginalObjectId==row.PdfObjectId ||
                row.OriginalSha256 is not {Length:32} || row.PdfSha256 is not {Length:32})throw Invalid();
            return row.DeleteAfter;
        }
        catch(Exception e) when(e is JsonException or InvalidOperationException or ArgumentException or OverflowException) {throw new InvalidDataException("The frozen final-retention binding could not be verified.",e);}
    }
    internal static DateTimeOffset? RequiredUntil(CompletionPublicationIntent intent,DateTimeOffset decision)
        =>FixedUntil(intent) ?? new FinalRetention(intent.RetentionDays,intent.DevelopmentWriteOnce).RequiredUntil(decision);
    internal static bool Matches(CompletionPublicationIntent intent,DocumentRetentionSnapshot? row)
    {
        var until=FixedUntil(intent);
        if(row is null)return until is null;
        if(until is null)return false;
        using var document=JsonDocument.Parse(intent.StageBindingsJson);
        return Bind(document.RootElement.GetProperty(nameof(Binding.Stages)).GetRawText(),row)==intent.StageBindingsJson;
    }
    internal static void CanPublish(CompletionPublicationIntent intent,DateTimeOffset now)
    {
        if(FixedUntil(intent) is DateTimeOffset until && now>=until)throw new CompletionPublicationUnavailableException("The document retention deadline has passed.");
    }
    private static InvalidDataException Invalid()=>new("The frozen final-retention binding could not be verified.");
}
