using Microsoft.EntityFrameworkCore;

namespace QuillSign.Data;

internal static class EmailPilotCloseoutModel
{
    internal static void Configure(ModelBuilder model)
    {
        model.Entity<EmailPilotCloseoutHeaderRecord>().ToTable("EmailPilotCloseouts",t=> {
            t.HasCheckConstraint("CK_PilotCloseout_Header","[Id]<>'00000000-0000-0000-0000-000000000000' AND DATEPART(TZOFFSET,[CreatedAt])=0 AND DATEPART(TZOFFSET,[Until])=0 AND DATEPART(TZOFFSET,[DeleteAfter])=0 AND [Until]>[CreatedAt] AND [Until]<=DATEADD(minute,30,[CreatedAt]) AND [DeleteAfter]>[Until] AND DATALENGTH([CapabilitySha256])=32 AND DATALENGTH([ManifestSha256])=32");
            t.HasCheckConstraint("CK_PilotCloseout_Secret","[ProtectedManifest] IS NULL OR DATALENGTH([ProtectedManifest]) BETWEEN 2 AND 131072"); });
        model.Entity<EmailPilotCloseoutHeaderRecord>().HasKey(x=>x.Id);
        model.Entity<EmailPilotCloseoutHeaderRecord>().Property(x=>x.ProtectedManifest).HasMaxLength(65536);
        model.Entity<EmailPilotCloseoutOperationRecord>().ToTable("EmailPilotCloseoutOperations",t=> {
            t.HasCheckConstraint("CK_PilotCloseout_Operation","[Id]<>'00000000-0000-0000-0000-000000000000' AND [WorkId]<>'00000000-0000-0000-0000-000000000000' AND [SubjectEnvelopeId]<>'00000000-0000-0000-0000-000000000000' AND DATEPART(TZOFFSET,[At])=0 AND [Step] BETWEEN 0 AND 9 AND DATALENGTH([RequestSha256])=32 AND DATALENGTH([ProtectedReceipt]) BETWEEN 2 AND 16384");
            t.HasCheckConstraint("CK_PilotCloseout_Accounting","([Kind]=0 AND [Step] BETWEEN 6 AND 9 AND [EncodedBytes]=0) OR ([Kind]=1 AND [EncodedBytes] BETWEEN 1 AND 1048576)"); });
        model.Entity<EmailPilotCloseoutOperationRecord>().HasKey(x=>x.Id);
        model.Entity<EmailPilotCloseoutOperationRecord>().HasIndex(x=>new{x.CloseoutId,x.Kind,x.Step}).IsUnique();
        model.Entity<EmailPilotCloseoutOperationRecord>().HasOne<EmailPilotCloseoutHeaderRecord>().WithMany().HasForeignKey(x=>x.CloseoutId).OnDelete(DeleteBehavior.NoAction);
        model.Entity<EmailPilotCloseoutOperationRecord>().Property(x=>x.ProtectedReceipt).HasMaxLength(8192);
    }
}
