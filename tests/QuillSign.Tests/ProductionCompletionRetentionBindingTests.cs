using System.Text.Json;
using System.Text.Json.Nodes;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;

namespace QuillSign.Tests;

public sealed class ProductionCompletionRetentionBindingTests
{
    private static (CompletionPublicationIntent Intent,VerifiedProductionRetention Enrollment) Saved(int days=365)
    {
        var now=ProductionRetentionAdmissionContractTests.Now;var options=ProductionRetentionAdmissionContractTests.Settings();
        options.Production.CompletedDays=days;
        var snapshot=ProductionRetentionPolicyContract.Freeze(Guid.NewGuid(),ProductionRetentionLedger.Seconds(now),options.Production);
        var enrolled=new VerifiedProductionRetention(snapshot,now,now,1,new string('a',64));
        return (new() {EnvelopeId=snapshot.RecordId,RetentionDays=days,PreparedAt=now.AddDays(1),
            StageBindingsJson=ProductionCompletionRetentionBinding.Bind("{\"synthetic\":\"exact-stage\"}",enrolled)},enrolled);
    }

    [Theory]
    [InlineData(1)][InlineData(365)][InlineData(0)]
    public void Publication_binds_exact_saved_policy_and_uses_actual_completion_clock(int days)
    {
        var (intent,enrolled)=Saved(days);var completion=intent.PreparedAt.AddMinutes(5).AddTicks(4321);
        Assert.True(ProductionCompletionRetentionBinding.Matches(intent,enrolled));
        Assert.Null(CompletionRetentionBinding.FixedUntil(intent));
        Assert.Equal("{\"synthetic\":\"exact-stage\"}",CompletionRetentionBinding.StagesJson(intent));
        Assert.Equal(days==0 ? (DateTimeOffset?)null : completion.AddDays(days),CompletionRetentionBinding.RequiredUntil(intent,completion));
        Assert.True(CompletionRetentionBinding.Matches(intent,null));
        Assert.False(ProductionCompletionRetentionBinding.Matches(intent,null));
        var changed=enrolled with {Snapshot=enrolled.Snapshot with {Policy=enrolled.Snapshot.Policy with {CompletedDays=30}}};
        Assert.False(ProductionCompletionRetentionBinding.Matches(intent,changed));
        Assert.False(ProductionCompletionRetentionBinding.Matches(intent,enrolled with {AuditHash=new string('b',64)}));
    }

    [Theory]
    [InlineData("record")][InlineData("days")][InlineData("development")][InlineData("created")]
    [InlineData("hash")][InlineData("sequence")][InlineData("missing")][InlineData("unknown")]
    [InlineData("mixed")][InlineData("duplicate")][InlineData("unknown-field")][InlineData("whitespace")]
    public void Structural_tampering_never_becomes_a_legacy_recipe(string change)
    {
        var (intent,enrolled)=Saved();var originalBinding=ProductionCompletionRetentionBinding.Read(intent)!;
        var root=JsonNode.Parse(intent.StageBindingsJson)!.AsObject();
        switch(change) {
            case "record":intent.EnvelopeId=Guid.NewGuid();break;
            case "days":intent.RetentionDays=1;break;
            case "development":intent.DevelopmentWriteOnce=true;break;
            case "created":root["ProductionRetention"]!["OriginalCreatedAt"]=enrolled.OriginalCreatedAt.AddTicks(1).ToString("O");break;
            case "hash":root["ProductionRetention"]!["Sha256"]=new string('b',64);break;
            case "sequence":root["ProductionRetention"]!["EnrollmentAuditSequence"]=2;break;
            case "missing":root.Remove("ProductionRetention");break;
            case "unknown":root["RetentionVersion"]="unsupported";break;
            case "mixed":root["UploadRetention"]=new JsonObject();break;
            case "unknown-field":root["Unexpected"]=true;break;
        }
        if(change is not ("record" or "days" or "development"))intent.StageBindingsJson=root.ToJsonString(new(){WriteIndented=false});
        if(change=="whitespace")intent.StageBindingsJson+=" ";
        if(change=="duplicate")intent.StageBindingsJson=intent.StageBindingsJson.Replace("\"RetentionVersion\":", "\"RetentionVersion\":\"discarded\",\"RetentionVersion\":",StringComparison.Ordinal);
        // A structurally representable fractional clock still requires exact ledger
        // comparison; parsing metadata alone is deliberately not authentication.
        if(change=="created") {
            intent.StageBindingsJson=JsonSerializer.Serialize(originalBinding with {ProductionRetention=originalBinding.ProductionRetention with {
                OriginalCreatedAt=enrolled.OriginalCreatedAt.AddTicks(1)}});
            Assert.False(ProductionCompletionRetentionBinding.Matches(intent,enrolled));return;
        }
        Assert.Throws<InvalidDataException>(()=>CompletionRetentionBinding.RequiredUntil(intent,intent.PreparedAt));
    }

    [Fact]
    public void Legacy_and_demo_binding_bytes_and_fixed_deadline_keep_their_existing_interpretation()
    {
        var legacy=new CompletionPublicationIntent {EnvelopeId=Guid.NewGuid(),StageBindingsJson="{\"synthetic\":true}",RetentionDays=9};
        Assert.Null(ProductionCompletionRetentionBinding.Read(legacy));Assert.Equal(legacy.StageBindingsJson,CompletionRetentionBinding.StagesJson(legacy));
        Assert.Equal(ProductionRetentionAdmissionContractTests.Now.AddDays(9),CompletionRetentionBinding.RequiredUntil(legacy,ProductionRetentionAdmissionContractTests.Now));
        var at=ProductionRetentionLedger.Seconds(ProductionRetentionAdmissionContractTests.Now);
        var demo=new DocumentRetentionSnapshot {EnvelopeId=legacy.EnvelopeId,PolicyVersion=UploadRetention.Version,Days=7,
            StartedAt=at,DeleteAfter=at.AddDays(7),OriginalObjectId=Guid.NewGuid(),PdfObjectId=Guid.NewGuid(),OriginalSha256=new byte[32],PdfSha256=new byte[32]};
        var original=legacy.StageBindingsJson;legacy.RetentionDays=7;legacy.StageBindingsJson=CompletionRetentionBinding.Bind(original,demo);
        Assert.Null(ProductionCompletionRetentionBinding.Read(legacy));Assert.Equal(original,CompletionRetentionBinding.StagesJson(legacy));
        Assert.Equal(demo.DeleteAfter,CompletionRetentionBinding.RequiredUntil(legacy,at.AddDays(6)));
        Assert.True(CompletionRetentionBinding.Matches(legacy,demo));
        Assert.Throws<CompletionPublicationUnavailableException>(()=>CompletionRetentionBinding.CanPublish(legacy,demo.DeleteAfter));
    }
}
