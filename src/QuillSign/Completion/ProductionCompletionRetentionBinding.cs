using System.Text.Json;
using QuillSign.Data;
using QuillSign.Lifecycle;

namespace QuillSign.Completion;

// Canonical metadata only. The publication boundary must compare this with the
// actual authenticated ledger under the parent lock before issuing authority.
internal static class ProductionCompletionRetentionBinding
{
    internal const string Version="completion-production-retention-v1";
    internal sealed record Policy(string Snapshot,string Sha256,DateTimeOffset OriginalCreatedAt,
        long EnrollmentAuditSequence,string EnrollmentAuditHash);
    internal sealed record Binding(string RetentionVersion,JsonElement Stages,Policy ProductionRetention);

    internal static string Bind(string stages,VerifiedProductionRetention enrollment)
    {
        var snapshot=ProductionRetentionPolicyContract.Serialize(enrollment.Snapshot);
        var policy=new Policy(snapshot,ProductionRetentionPolicyContract.Digest(enrollment.Snapshot),enrollment.OriginalCreatedAt,
            enrollment.AuditSequence,enrollment.AuditHash);
        ValidatePolicy(policy,enrollment.Snapshot.RecordId,enrollment.Snapshot.Policy.CompletedDays);
        using var document=JsonDocument.Parse(stages,new JsonDocumentOptions {MaxDepth=12});
        if(document.RootElement.ValueKind!=JsonValueKind.Object)throw Invalid();
        return JsonSerializer.Serialize(new Binding(Version,document.RootElement.Clone(),policy));
    }

    internal static Binding? Read(CompletionPublicationIntent intent)
    {
        try {
            using var document=JsonDocument.Parse(intent.StageBindingsJson,new JsonDocumentOptions {MaxDepth=16});
            var root=document.RootElement;
            var marked=root.TryGetProperty(nameof(Binding.ProductionRetention),out _);
            var version=root.TryGetProperty(nameof(Binding.RetentionVersion),out var value) && value.ValueKind==JsonValueKind.String ? value.GetString() : null;
            if(!marked && version!=Version)return null; // The existing parser owns old recipe versions.
            if(version!=Version || root.TryGetProperty("UploadRetention",out _) || intent.DevelopmentWriteOnce)throw Invalid();
            var binding=root.Deserialize<Binding>()??throw Invalid();
            if(binding.Stages.ValueKind!=JsonValueKind.Object || binding.ProductionRetention is null ||
                JsonSerializer.Serialize(binding)!=intent.StageBindingsJson)throw Invalid();
            ValidatePolicy(binding.ProductionRetention,intent.EnvelopeId,intent.RetentionDays);
            if(intent.PreparedAt.Offset!=TimeSpan.Zero || intent.PreparedAt<binding.ProductionRetention.OriginalCreatedAt)throw Invalid();
            return binding;
        }
        catch(Exception error) when(error is JsonException or ArgumentException or InvalidOperationException or NullReferenceException) {
            throw new InvalidDataException("The production completion retention binding is invalid.",error);
        }
    }

    internal static bool Matches(CompletionPublicationIntent intent,VerifiedProductionRetention? enrollment)
    {
        var binding=Read(intent);
        if(binding is null)return enrollment is null;
        return enrollment is not null && Bind(binding.Stages.GetRawText(),enrollment)==intent.StageBindingsJson;
    }

    private static void ValidatePolicy(Policy policy,Guid id,int days)
    {
        var snapshot=ProductionRetentionPolicyContract.Read(policy.Snapshot,policy.Sha256);
        if(snapshot.RecordId!=id || snapshot.Policy.CompletedDays!=days || policy.OriginalCreatedAt.Offset!=TimeSpan.Zero ||
            ProductionRetentionLedger.Seconds(policy.OriginalCreatedAt)!=snapshot.CreatedAt || policy.EnrollmentAuditSequence!=1 ||
            policy.EnrollmentAuditHash is not {Length:64} || policy.EnrollmentAuditHash.Any(c=>!char.IsAsciiHexDigitLower(c)))throw Invalid();
        _=ProductionRetentionPolicyContract.AddDays(policy.OriginalCreatedAt,days);
    }
    private static InvalidDataException Invalid()=>new("The production completion retention binding is invalid.");
}
