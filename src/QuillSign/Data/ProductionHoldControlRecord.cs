using Microsoft.EntityFrameworkCore;

namespace QuillSign.Data;

// Private preservation progress, never participant evidence or runtime authority.
public sealed class ProductionHoldControlRecord
{
    public Guid EventId { get; set; }
    public Guid EnvelopeId { get; set; }
    public Guid HoldId { get; set; }
    public Guid PlanId { get; set; }
    public long Sequence { get; set; }
    public int Kind { get; set; }
    public DateTimeOffset At { get; set; }
    public string PolicySha256 { get; set; } = "";
    public string PlanSha256 { get; set; } = "";
    public string? ItemSha256 { get; set; }
    public string? PayloadSha256 { get; set; }
    public byte[]? PlanPayload { get; set; }
    public string ProtectedEvidence { get; set; } = "";
    public byte[]? PreviousHash { get; set; }
    public byte[] Hash { get; set; } = [];
}

internal static class ProductionHoldControlModel
{
    internal static void Configure(ModelBuilder model)
    {
        var e = model.Entity<ProductionHoldControlRecord>();
        e.HasKey(x => x.EventId);
        e.HasIndex(x => new { x.EnvelopeId, x.Sequence }).IsUnique();
        e.HasIndex(x => new { x.EnvelopeId, x.PlanId }).IsUnique().HasFilter("[Kind]=0");
        e.HasIndex(x => new { x.EnvelopeId, x.PlanId, x.ItemSha256 }).IsUnique().HasFilter("[Kind]=1");
        e.HasOne<ProductionRetentionPolicyRecord>().WithMany().HasForeignKey(x => x.EnvelopeId).OnDelete(DeleteBehavior.NoAction);
        e.Property(x => x.PolicySha256).HasMaxLength(64).IsUnicode(false);
        e.Property(x => x.PlanSha256).HasMaxLength(64).IsUnicode(false);
        e.Property(x => x.ItemSha256).HasMaxLength(64).IsUnicode(false);
        e.Property(x => x.PayloadSha256).HasMaxLength(64).IsUnicode(false);
        e.Property(x => x.PlanPayload).HasColumnType("varbinary(max)").HasMaxLength(41 * 1024 * 1024);
        e.Property(x => x.ProtectedEvidence).HasColumnType("nvarchar(max)").HasMaxLength(65536);
        e.Property(x => x.Hash).HasMaxLength(32); e.Property(x => x.PreviousHash).HasMaxLength(32);
        e.ToTable(t => {
            t.HasCheckConstraint("CK_ProductionHoldControl_Bounds", "[Sequence] BETWEEN 1 AND 16384 AND [Kind] IN (0,1) AND DATEPART(TZOFFSET,[At])=0 AND DATALENGTH([PolicySha256])=64 AND DATALENGTH([PlanSha256])=64 AND DATALENGTH([ProtectedEvidence]) BETWEEN 64 AND 131072");
            t.HasCheckConstraint("CK_ProductionHoldControl_Payload", "([Kind]=0 AND [EventId]=[PlanId] AND [ItemSha256] IS NULL AND [PayloadSha256] IS NOT NULL AND DATALENGTH([PayloadSha256])=64 AND [PlanPayload] IS NOT NULL AND DATALENGTH([PlanPayload]) BETWEEN 1 AND 42991616) OR ([Kind]=1 AND [ItemSha256] IS NOT NULL AND DATALENGTH([ItemSha256])=64 AND [PayloadSha256] IS NULL AND [PlanPayload] IS NULL)");
            t.HasCheckConstraint("CK_ProductionHoldControl_Hash", "DATALENGTH([Hash])=32 AND (([Sequence]=1 AND [PreviousHash] IS NULL) OR ([Sequence]>1 AND DATALENGTH([PreviousHash])=32))");
            t.HasCheckConstraint("CK_ProductionHoldControl_Ids", "[EventId]<>'00000000-0000-0000-0000-000000000000' AND [HoldId]<>'00000000-0000-0000-0000-000000000000' AND [PlanId]<>'00000000-0000-0000-0000-000000000000'");
        });
    }
}
