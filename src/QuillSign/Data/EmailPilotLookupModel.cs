using Microsoft.EntityFrameworkCore;

namespace QuillSign.Data;

internal static class EmailPilotLookupModel
{
    internal static void Configure(ModelBuilder model)
    {
        model.Entity<EmailPilotLookupRequestRecord>().HasKey(x => x.RunId);
        model.Entity<EmailPilotLookupRequestRecord>().HasAlternateKey(x => x.RequestId);
        model.Entity<EmailPilotLookupRequestRecord>().HasOne<EmailPilotRunRecord>().WithMany().HasForeignKey(x => x.RunId).OnDelete(DeleteBehavior.NoAction);
        model.Entity<EmailPilotLookupRequestRecord>().Property(x => x.ProtectedBinding).HasMaxLength(4096);
        model.Entity<EmailPilotLookupRequestRecord>().ToTable(t => {
            t.HasCheckConstraint("CK_PilotLookupRequest_Ids", "[RunId]<>'00000000-0000-0000-0000-000000000000' AND [RequestId]<>'00000000-0000-0000-0000-000000000000' AND [SubjectEnvelopeId]<>'00000000-0000-0000-0000-000000000000' AND [PublicationId]<>'00000000-0000-0000-0000-000000000000'");
            t.HasCheckConstraint("CK_PilotLookupRequest_Interval", "DATEPART(TZOFFSET,[RequestedAt])=0 AND DATEPART(TZOFFSET,[ExpiresAt])=0 AND [ExpiresAt]>[RequestedAt] AND [ExpiresAt]<=DATEADD(minute,60,[RequestedAt])");
            t.HasCheckConstraint("CK_PilotLookupRequest_Binding", "DATALENGTH([ProtectedBinding]) BETWEEN 2 AND 8192");
        });
        model.Entity<EmailPilotLookupTokenRecord>().HasKey(x => x.Id);
        model.Entity<EmailPilotLookupTokenRecord>().HasIndex(x => new { x.RequestId, x.Attempt }).IsUnique();
        model.Entity<EmailPilotLookupTokenRecord>().HasOne<EmailPilotRunRecord>().WithMany().HasForeignKey(x => x.RunId).OnDelete(DeleteBehavior.NoAction);
        model.Entity<EmailPilotLookupTokenRecord>().HasOne<EmailPilotLookupRequestRecord>().WithMany().HasForeignKey(x => x.RequestId)
            .HasPrincipalKey(x => x.RequestId).OnDelete(DeleteBehavior.NoAction);
        model.Entity<EmailPilotLookupTokenRecord>().Property(x => x.ProtectedBinding).HasMaxLength(4096);
        model.Entity<EmailPilotLookupTokenRecord>().Property(x => x.IssuedRevision).HasMaxLength(12);
        model.Entity<EmailPilotLookupTokenRecord>().ToTable(t => {
            t.HasCheckConstraint("CK_PilotLookupToken_Ids", "[Id]<>'00000000-0000-0000-0000-000000000000' AND [RunId]<>'00000000-0000-0000-0000-000000000000' AND [RequestId]<>'00000000-0000-0000-0000-000000000000' AND [Attempt] BETWEEN 1 AND 10");
            t.HasCheckConstraint("CK_PilotLookupToken_Interval", "DATEPART(TZOFFSET,[IssuedAt])=0 AND DATEPART(TZOFFSET,[ExpiresAt])=0 AND [ExpiresAt]>[IssuedAt] AND [ExpiresAt]<=DATEADD(minute,60,[IssuedAt])");
            t.HasCheckConstraint("CK_PilotLookupToken_Binding", "DATALENGTH([ProtectedBinding]) BETWEEN 2 AND 8192 AND LEN([IssuedRevision])=12");
        });
        // This is a lookup-purpose marker, never envelope or party authority.
        model.Entity<AuthToken>().ToTable(t => t.HasCheckConstraint("CK_AuthToken_PilotLookup", "[EmailPilotLookupRequestId] IS NULL OR ([EmailPilotLookupRequestId]<>'00000000-0000-0000-0000-000000000000' AND [Purpose]='Lookup' AND [EnvelopeId] IS NULL AND [PartyType]='System' AND [PartyId] IS NULL AND [Email]='' AND [Ip] IS NULL AND [DocumentId] IS NULL AND [DocumentSha256] IS NULL AND [DisclosureSha256] IS NULL AND [CompletionPublicationId] IS NULL AND [CompletionRecipeSha256] IS NULL AND [CompletionPartySha256] IS NULL AND [SignerContactRevisionId] IS NULL)"));
    }
}
