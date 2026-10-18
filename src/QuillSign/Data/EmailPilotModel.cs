using Microsoft.EntityFrameworkCore;

namespace QuillSign.Data;

internal static class EmailPilotModel
{
    internal static void Configure(ModelBuilder model)
    {
        model.Entity<EmailPilotRunRecord>().HasKey(x => x.Id);
        model.Entity<EmailPilotRunRecord>().ToTable(t => t.HasCheckConstraint("CK_EmailPilotRun_Interval",
            "[Id]<>'00000000-0000-0000-0000-000000000000' AND DATEPART(TZOFFSET,[CreatedAt])=0 AND DATEPART(TZOFFSET,[ExpiresAt])=0 AND [ExpiresAt]=DATEADD(minute,60,[CreatedAt])"));
        model.Entity<EmailPilotSecretRecord>().HasKey(x => x.RunId);
        model.Entity<EmailPilotSecretRecord>().HasOne<EmailPilotRunRecord>().WithMany().HasForeignKey(x => x.RunId).OnDelete(DeleteBehavior.NoAction);
        model.Entity<EmailPilotSecretRecord>().Property(x => x.ProtectedManifest).HasMaxLength(16384);
        model.Entity<EmailPilotSecretRecord>().ToTable(t => t.HasCheckConstraint("CK_EmailPilotSecret_Deadline", "DATEPART(TZOFFSET,[DeleteAfter])=0 AND DATALENGTH([ProtectedManifest]) BETWEEN 2 AND 32768"));
        model.Entity<EmailPilotEnrollmentRecord>().HasKey(x => x.SubjectEnvelopeId);
        model.Entity<EmailPilotEnrollmentRecord>().HasAlternateKey(x => new { x.RunId, x.SubjectEnvelopeId });
        model.Entity<EmailPilotEnrollmentRecord>().HasIndex(x => new { x.RunId, x.Scenario }).IsUnique();
        model.Entity<EmailPilotEnrollmentRecord>().HasOne<EmailPilotRunRecord>().WithMany().HasForeignKey(x => x.RunId).OnDelete(DeleteBehavior.NoAction);
        model.Entity<EmailPilotEnrollmentRecord>().Property(x => x.ProtectedBinding).HasMaxLength(2048);
        model.Entity<EmailPilotEnrollmentRecord>().ToTable(t => t.HasCheckConstraint("CK_EmailPilotEnrollment_Scope",
            "[SubjectEnvelopeId]<>'00000000-0000-0000-0000-000000000000' AND DATEPART(TZOFFSET,[EnrolledAt])=0"));
        model.Entity<EmailPilotReservationRecord>().HasKey(x => x.Id);
        model.Entity<EmailPilotReservationRecord>().HasIndex(x => new { x.RunId, x.ReservedAt });
        model.Entity<EmailPilotReservationRecord>().HasIndex(x => new { x.RunId, x.Kind, x.OperationId, x.Role }).IsUnique();
        model.Entity<EmailPilotReservationRecord>().HasOne<EmailPilotRunRecord>().WithMany().HasForeignKey(x => x.RunId).OnDelete(DeleteBehavior.NoAction);
        model.Entity<EmailPilotReservationRecord>().HasOne<EmailPilotEnrollmentRecord>().WithMany()
            .HasForeignKey(x => new { x.RunId, x.SubjectEnvelopeId }).HasPrincipalKey(x => new { x.RunId, x.SubjectEnvelopeId }).OnDelete(DeleteBehavior.NoAction);
        model.Entity<EmailPilotReservationRecord>().Property(x => x.ProtectedReceipt).HasMaxLength(4096);
        model.Entity<EmailPilotReservationRecord>().ToTable(t =>
        {
            t.HasCheckConstraint("CK_EmailPilotReservation_Scope", "[Id]<>'00000000-0000-0000-0000-000000000000' AND [OperationId]<>'00000000-0000-0000-0000-000000000000' AND DATEPART(TZOFFSET,[ReservedAt])=0");
            t.HasCheckConstraint("CK_EmailPilotReservation_Receipt", "DATALENGTH([ProtectedReceipt]) BETWEEN 2 AND 8192");
            t.HasCheckConstraint("CK_EmailPilotReservation_Bytes", "([Kind]='Timestamp' AND [EncodedBytes]=0 AND [Role]='None' AND [SubjectEnvelopeId] IS NOT NULL) OR ([Kind]='Application' AND [EncodedBytes] BETWEEN 1 AND 1048576 AND [Role] IN ('Sender','FirstSigner','SecondSigner','Recipient') AND [SubjectEnvelopeId] IS NOT NULL) OR ([Kind]='Simulator' AND [EncodedBytes] BETWEEN 1 AND 1048576 AND [Role]='Simulator' AND [SubjectEnvelopeId] IS NULL)");
        });
    }
}
