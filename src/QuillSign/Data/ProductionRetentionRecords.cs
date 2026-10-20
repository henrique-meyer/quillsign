using Microsoft.EntityFrameworkCore;

namespace QuillSign.Data;

// Technical policy evidence only. Participant identities remain in the parent/audit.
public sealed class ProductionRetentionPolicyRecord
{
    public Guid EnvelopeId { get; set; }
    public DateTimeOffset OriginalCreatedAt { get; set; }
    public DateTimeOffset EnrolledAt { get; set; }
    public string PolicyJson { get; set; } = "";
    public string PolicySha256 { get; set; } = "";
    public byte[] OriginSha256 { get; set; } = [];
    public long AuditSequence { get; set; }
    public byte[] AuditHash { get; set; } = [];
}

public sealed class ProductionRetentionTerminalRecord
{
    public Guid EnvelopeId { get; set; }
    public EnvelopeStatus Status { get; set; }
    public string PolicySha256 { get; set; } = "";
    public DateTimeOffset OriginalAt { get; set; }
    public DateTimeOffset ClockAt { get; set; }
    public DateTimeOffset RecordedAt { get; set; }
    public long SourceAuditSequence { get; set; }
    public byte[] SourceAuditHash { get; set; } = [];
    public long AuditSequence { get; set; }
    public byte[] AuditHash { get; set; } = [];
}

internal static class ProductionRetentionModel
{
    internal static void Configure(ModelBuilder model)
    {
        model.Entity<ProductionRetentionPolicyRecord>().HasKey(x => x.EnvelopeId);
        model.Entity<ProductionRetentionPolicyRecord>().Property(x => x.PolicySha256).HasMaxLength(64).IsUnicode(false);
        model.Entity<ProductionRetentionPolicyRecord>().ToTable(t =>
        {
            t.HasCheckConstraint("CK_ProductionRetentionPolicy_Bounds", "DATALENGTH([PolicyJson]) BETWEEN 2 AND 16384 AND DATALENGTH([PolicySha256])=64 AND [AuditSequence] BETWEEN 1 AND 512");
            t.HasCheckConstraint("CK_ProductionRetentionPolicy_Clock", "DATEPART(TZOFFSET,[OriginalCreatedAt])=0 AND DATEPART(TZOFFSET,[EnrolledAt])=0 AND [EnrolledAt]>=[OriginalCreatedAt]");
        });
        model.Entity<ProductionRetentionTerminalRecord>().HasKey(x => x.EnvelopeId);
        model.Entity<ProductionRetentionTerminalRecord>().HasOne<ProductionRetentionPolicyRecord>().WithMany()
            .HasForeignKey(x => x.EnvelopeId).OnDelete(DeleteBehavior.NoAction);
        model.Entity<ProductionRetentionTerminalRecord>().Property(x => x.PolicySha256).HasMaxLength(64).IsUnicode(false);
        model.Entity<ProductionRetentionTerminalRecord>().ToTable(t =>
        {
            t.HasCheckConstraint("CK_ProductionRetentionTerminal_Bounds", "[Status] IN ('Completed','Expired','Declined','Voided') AND DATALENGTH([PolicySha256])=64 AND [SourceAuditSequence] BETWEEN 1 AND 511 AND [AuditSequence] BETWEEN 2 AND 512 AND [AuditSequence]>[SourceAuditSequence]");
            t.HasCheckConstraint("CK_ProductionRetentionTerminal_Clock", "DATEPART(TZOFFSET,[OriginalAt])=0 AND DATEPART(TZOFFSET,[ClockAt])=0 AND DATEPART(TZOFFSET,[RecordedAt])=0 AND [RecordedAt]>=[OriginalAt] AND [ClockAt]<=[OriginalAt] AND DATEDIFF_BIG(nanosecond,[ClockAt],[OriginalAt]) BETWEEN 0 AND 999999999 AND DATEPART(nanosecond,[ClockAt])=0");
        });
    }
}
