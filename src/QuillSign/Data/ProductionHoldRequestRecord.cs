using Microsoft.EntityFrameworkCore;

namespace QuillSign.Data;

// Private operator journal; deliberately absent from runtime/worker table grants.
public sealed class ProductionHoldRequestRecord
{
    public Guid CommandId { get; set; }
    public Guid EnvelopeId { get; set; }
    public Guid HoldId { get; set; }
    public long Revision { get; set; }
    public int Operation { get; set; }
    public DateTimeOffset At { get; set; }
    public string PolicySha256 { get; set; } = "";
    public string CommandSha256 { get; set; } = "";
    public string ProtectedEvidence { get; set; } = "";
    public byte[]? PreviousHash { get; set; }
    public byte[] Hash { get; set; } = [];
}

internal static class ProductionHoldRequestModel
{
    internal static void Configure(ModelBuilder model)
    {
        var entity = model.Entity<ProductionHoldRequestRecord>();
        entity.HasKey(x => x.CommandId);
        entity.HasIndex(x => new { x.EnvelopeId, x.Revision }).IsUnique();
        entity.HasIndex(x => new { x.EnvelopeId, x.HoldId, x.Operation }).IsUnique();
        entity.HasOne<ProductionRetentionPolicyRecord>().WithMany().HasForeignKey(x => x.EnvelopeId).OnDelete(DeleteBehavior.NoAction);
        entity.Property(x => x.PolicySha256).HasMaxLength(64).IsUnicode(false);
        entity.Property(x => x.CommandSha256).HasMaxLength(64).IsUnicode(false);
        entity.Property(x => x.ProtectedEvidence).HasColumnType("nvarchar(max)").HasMaxLength(32768);
        entity.Property(x => x.Hash).HasMaxLength(32);
        entity.Property(x => x.PreviousHash).HasMaxLength(32);
        entity.ToTable(t =>
        {
            t.HasCheckConstraint("CK_ProductionHoldRequest_Bounds", "[Revision] BETWEEN 1 AND 512 AND [Operation] IN (0,1) AND DATEPART(TZOFFSET,[At])=0 AND DATALENGTH([PolicySha256])=64 AND DATALENGTH([CommandSha256])=64 AND DATALENGTH([ProtectedEvidence]) BETWEEN 64 AND 65536");
            t.HasCheckConstraint("CK_ProductionHoldRequest_Hash", "DATALENGTH([Hash])=32 AND (([Revision]=1 AND [PreviousHash] IS NULL) OR ([Revision]>1 AND DATALENGTH([PreviousHash])=32))");
            t.HasCheckConstraint("CK_ProductionHoldRequest_Ids", "[CommandId]<>'00000000-0000-0000-0000-000000000000' AND [HoldId]<>'00000000-0000-0000-0000-000000000000'");
        });
    }
}
