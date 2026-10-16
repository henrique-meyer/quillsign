using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

namespace QuillSign.Data;

public sealed class QuillSignDbContext(DbContextOptions<QuillSignDbContext> options) : DbContext(options)
{
    public DbSet<Envelope> Envelopes => Set<Envelope>();
    public DbSet<Signer> Signers => Set<Signer>();
    public DbSet<SignaturePreview> SignaturePreviews => Set<SignaturePreview>();
    public DbSet<SignerReviewCandidate> SignerReviewCandidates => Set<SignerReviewCandidate>();
    public DbSet<SignerFinishAcceptance> SignerFinishAcceptances => Set<SignerFinishAcceptance>();
    public DbSet<CompletionCandidate> CompletionCandidates => Set<CompletionCandidate>();
    public DbSet<CompletionSealOutput> CompletionSealOutputs => Set<CompletionSealOutput>();
    public DbSet<Recipient> Recipients => Set<Recipient>();
    public DbSet<DocumentField> Fields => Set<DocumentField>();
    public DbSet<AuthToken> AuthTokens => Set<AuthToken>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();
    public DbSet<EmailOutbox> EmailOutbox => Set<EmailOutbox>();
    public DbSet<WorkItem> WorkItems => Set<WorkItem>();
    public DbSet<Suppression> Suppressions => Set<Suppression>();

    protected override void OnModelCreating(ModelBuilder model)
    {
        model.UseCollation("Latin1_General_100_CI_AS_SC");
        model.Entity<Suppression>().HasKey(x => x.Email);
        model.Entity<Envelope>().HasIndex(x => x.PublicId).IsUnique();
        model.Entity<Envelope>().HasIndex(x => x.PurgeAfter);
        model.Entity<Envelope>().ToTable(t => t.HasCheckConstraint("CK_Envelope_PageCount", "[PageCount] IS NULL OR [PageCount] > 0"));
        model.Entity<Envelope>().ToTable(t => t.HasCheckConstraint("CK_Envelope_ErsdText", "[ErsdText] IS NULL OR DATALENGTH([ErsdText]) <= 65536"));
        model.Entity<Envelope>().HasOne<SignerFinishAcceptance>().WithMany().HasForeignKey(x=>new { x.Id,x.CurrentFinishId })
            .HasPrincipalKey(x=>new { x.EnvelopeId,x.Id }).OnDelete(DeleteBehavior.NoAction);
        model.Entity<Envelope>().ToTable(t=>t.HasCheckConstraint("CK_Envelope_CurrentCopy","([CurrentFinishId] IS NULL AND [CurrentCopyVersion] = 0) OR ([CurrentFinishId] IS NOT NULL AND [CurrentCopyVersion] BETWEEN 1 AND 100)"));

        model.Entity<Signer>().HasIndex(x => new { x.EnvelopeId, x.Email }).IsUnique();
        model.Entity<Signer>().HasIndex(x => new { x.EnvelopeId, x.Order }).IsUnique();
        model.Entity<Signer>().HasAlternateKey(x => new { x.EnvelopeId, x.Id });
        model.Entity<Signer>().ToTable(t => t.HasCheckConstraint("CK_Signer_Order", "[Order] > 0"));
        model.Entity<SignaturePreview>().HasOne<Signer>().WithMany()
            .HasForeignKey(x => new { x.EnvelopeId,x.SignerId }).HasPrincipalKey(x => new { x.EnvelopeId,x.Id }).OnDelete(DeleteBehavior.NoAction);
        model.Entity<SignaturePreview>().HasIndex(x => new { x.EnvelopeId,x.SignerId,x.ExpiresAt });
        model.Entity<SignaturePreview>().HasAlternateKey(x => new { x.EnvelopeId,x.SignerId,x.Id });
        model.Entity<SignaturePreview>().ToTable(t =>
        {
            t.HasCheckConstraint("CK_SignaturePreview_Expiry", "[ExpiresAt] > [CreatedAt] AND ([UsedAt] IS NULL OR [UsedAt] >= [CreatedAt])");
            t.HasCheckConstraint("CK_SignaturePreview_Dimensions", "[SignatureWidth] BETWEEN 1 AND 2048 AND [InitialsWidth] BETWEEN 1 AND 2048 AND [SignatureHeight] BETWEEN 1 AND 1024 AND [InitialsHeight] BETWEEN 1 AND 1024");
        });
        model.Entity<Recipient>().HasIndex(x => new { x.EnvelopeId, x.Email }).IsUnique();
        model.Entity<SignerReviewCandidate>().HasOne<Signer>().WithMany()
            .HasForeignKey(x => new { x.EnvelopeId,x.SignerId }).HasPrincipalKey(x => new { x.EnvelopeId,x.Id }).OnDelete(DeleteBehavior.NoAction);
        model.Entity<SignerReviewCandidate>().HasOne<SignaturePreview>().WithMany()
            .HasForeignKey(x => new { x.EnvelopeId,x.SignerId,x.AdoptionId }).HasPrincipalKey(x => new { x.EnvelopeId,x.SignerId,x.Id }).OnDelete(DeleteBehavior.NoAction);
        model.Entity<SignerReviewCandidate>().HasIndex(x => new { x.EnvelopeId,x.SignerId,x.ExpiresAt });
        model.Entity<SignerReviewCandidate>().HasIndex(x => new { x.EnvelopeId,x.PdfObjectId }).IsUnique();
        model.Entity<SignerReviewCandidate>().HasAlternateKey(x => new { x.EnvelopeId,x.SignerId,x.Id });
        model.Entity<SignerReviewCandidate>().ToTable(t =>
        {
            t.HasCheckConstraint("CK_SignerReviewCandidate_Expiry", "[ExpiresAt] > [PreparedAt] AND [ExpiresAt] <= DATEADD(minute,10,[PreparedAt]) AND [ProspectiveDate] = CONVERT(date,SWITCHOFFSET([PreparedAt],'+00:00')) AND [ExpiresAt] <= DATEADD(day,1,CONVERT(datetimeoffset,[ProspectiveDate]))");
            t.HasCheckConstraint("CK_SignerReviewCandidate_State", "([UsedAt] IS NULL OR [UsedAt] >= [PreparedAt]) AND ([SupersededAt] IS NULL OR [SupersededAt] >= [PreparedAt]) AND ([UsedAt] IS NULL OR [SupersededAt] IS NULL)");
            t.HasCheckConstraint("CK_SignerReviewCandidate_Pdf", "[PdfLength] BETWEEN 16 AND 67108864 AND [SourceObjectId] <> [PdfObjectId]");
        });

        model.Entity<SignerFinishAcceptance>().HasOne<Signer>().WithMany()
            .HasForeignKey(x=>new { x.EnvelopeId,x.SignerId }).HasPrincipalKey(x=>new { x.EnvelopeId,x.Id }).OnDelete(DeleteBehavior.NoAction);
        model.Entity<SignerFinishAcceptance>().HasOne<SignerReviewCandidate>().WithMany()
            .HasForeignKey(x=>new { x.EnvelopeId,x.SignerId,x.ReviewCandidateId }).HasPrincipalKey(x=>new { x.EnvelopeId,x.SignerId,x.Id }).OnDelete(DeleteBehavior.NoAction);
        model.Entity<SignerFinishAcceptance>().HasIndex(x=>new { x.EnvelopeId,x.SignerId }).IsUnique();
        model.Entity<SignerFinishAcceptance>().HasIndex(x=>x.ReviewCandidateId).IsUnique();
        model.Entity<SignerFinishAcceptance>().HasAlternateKey(x=>new { x.EnvelopeId,x.Id });
        model.Entity<SignerFinishAcceptance>().HasIndex(x=>x.NextInvitationId).IsUnique();
        model.Entity<SignerFinishAcceptance>().HasIndex(x=>new { x.ProcessedAt,x.FinishedAt });
        model.Entity<SignerFinishAcceptance>().ToTable(t=>
        {
            t.HasCheckConstraint("CK_SignerFinishAcceptance_Time","[FinishedAt] >= [ReviewPreparedAt] AND [FinishedAt] < [ReviewExpiresAt] AND [ReviewExpiresAt] <= DATEADD(minute,10,[ReviewPreparedAt]) AND [ProspectiveDate] = CONVERT(date,SWITCHOFFSET([FinishedAt],'+00:00')) AND [ProspectiveDate] = CONVERT(date,SWITCHOFFSET([ReviewPreparedAt],'+00:00')) AND ([ProcessedAt] IS NULL OR [ProcessedAt] >= [FinishedAt])");
            t.HasCheckConstraint("CK_SignerFinishAcceptance_Pdf","[PdfLength] BETWEEN 16 AND 67108864 AND [SourceObjectId] <> [PdfObjectId]");
            t.HasCheckConstraint("CK_SignerFinishAcceptance_Fields","ISJSON([FieldsJson]) = 1 AND DATALENGTH([FieldsJson]) BETWEEN 2 AND 16777216");
            t.HasCheckConstraint("CK_SignerFinishAcceptance_Invitation","[NextInvitationId] IS NULL OR [ProcessedAt] IS NOT NULL");
        });

        model.Entity<CompletionCandidate>().HasIndex(x=>x.EnvelopeId).IsUnique();
        model.Entity<CompletionCandidate>().HasAlternateKey(x=>new {x.EnvelopeId,x.Id});
        model.Entity<CompletionCandidate>().HasIndex(x=>new {x.EnvelopeId,x.PdfObjectId}).IsUnique();
        model.Entity<CompletionCandidate>().HasOne<SignerFinishAcceptance>().WithMany().HasForeignKey(x=>new {x.EnvelopeId,x.FinishId})
            .HasPrincipalKey(x=>new {x.EnvelopeId,x.Id}).OnDelete(DeleteBehavior.NoAction);
        model.Entity<CompletionCandidate>().ToTable(t=>
        {
            t.HasCheckConstraint("CK_CompletionCandidate_Pdf","[PdfLength] BETWEEN 16 AND 67108864 AND [PdfObjectId] <> [SourceObjectId] AND [DocumentPages] >= 1 AND [CertificatePages] BETWEEN 1 AND 64 AND [DocumentPages] + [CertificatePages] <= 200");
            t.HasCheckConstraint("CK_CompletionCandidate_Snapshot","[CopyVersion] BETWEEN 1 AND 20 AND [AuditSequence] BETWEEN 1 AND 512 AND DATALENGTH([GeometryJson]) BETWEEN 2 AND 131072 AND DATALENGTH([EvidenceJson]) BETWEEN 2 AND 67108864");
        });

        model.Entity<CompletionSealOutput>().HasOne<CompletionCandidate>().WithMany().HasForeignKey(x=>new {x.EnvelopeId,x.CandidateId})
            .HasPrincipalKey(x=>new {x.EnvelopeId,x.Id}).OnDelete(DeleteBehavior.NoAction);
        model.Entity<CompletionSealOutput>().HasIndex(x=>new {x.EnvelopeId,x.CandidateId,x.Kind}).IsUnique();
        model.Entity<CompletionSealOutput>().HasIndex(x=>new {x.EnvelopeId,x.PdfObjectId}).IsUnique();
        model.Entity<CompletionSealOutput>().ToTable(t=> {
            t.HasCheckConstraint("CK_CompletionSealOutput_Pdf","[SourceLength] BETWEEN 16 AND 67108864 AND [PdfLength] BETWEEN 16 AND 67108864 AND [SourceObjectId] <> [PdfObjectId] AND [PageCount] BETWEEN 1 AND 200");
            t.HasCheckConstraint("CK_CompletionSealOutput_Metadata","DATALENGTH([MetadataJson]) BETWEEN 2 AND 262144 AND (([Kind]='Executed' AND [ExecutedSha256] IS NULL) OR ([Kind]='Certificate' AND [ExecutedSha256] IS NOT NULL))");
        });

        model.Entity<DocumentField>().HasOne<Signer>().WithMany()
            .HasForeignKey(x => new { x.EnvelopeId, x.SignerId })
            .HasPrincipalKey(x => new { x.EnvelopeId, x.Id }).OnDelete(DeleteBehavior.NoAction);
        model.Entity<DocumentField>().HasOne<SignaturePreview>().WithMany()
            .HasForeignKey(x => new { x.EnvelopeId,x.SignerId,x.SignatureAdoptionId })
            .HasPrincipalKey(x => new { x.EnvelopeId,x.SignerId,x.Id }).OnDelete(DeleteBehavior.NoAction);
        model.Entity<DocumentField>().ToTable(t =>
        {
            t.HasCheckConstraint("CK_Field_Bounds", "[Page] >= 1 AND [X] >= 0 AND [Y] >= 0 AND [Width] > 0 AND [Height] > 0 AND [X] + [Width] <= 1 AND [Y] + [Height] <= 1");
            t.HasCheckConstraint("CK_Field_Assignment", "[SignerId] IS NOT NULL OR [Type] IN ('Text','Checkbox','Date')");
            t.HasCheckConstraint("CK_Field_Confidence", "[AiConfidence] IS NULL OR ([AiConfidence] >= 0 AND [AiConfidence] <= 1)");
            t.HasCheckConstraint("CK_Field_MarkBinding", "([SignatureAdoptionId] IS NULL AND [ImageSha256] IS NULL) OR ([SignatureAdoptionId] IS NOT NULL AND [ImageSha256] IS NOT NULL AND [Type] IN ('Signature','Initials') AND [SignerId] IS NOT NULL AND [FilledAt] IS NOT NULL AND [FilledBy] IS NOT NULL AND [FilledBy] = 'Signer' AND [Value] IS NOT NULL)");
        });
        model.Entity<AuthToken>().HasIndex(x => x.TokenSha256).IsUnique();
        model.Entity<AuthToken>().HasIndex(x => x.ExpiresAt);
        model.Entity<AuthToken>().ToTable(t => t.HasCheckConstraint("CK_Token_Scope", "[Purpose] = 'Lookup' OR [EnvelopeId] IS NOT NULL"));
        model.Entity<AuthToken>().ToTable(t=>t.HasCheckConstraint("CK_Token_DocumentBinding","([DocumentId] IS NULL AND [DocumentSha256] IS NULL AND [DisclosureSha256] IS NULL) OR ([DocumentId] IS NOT NULL AND [DocumentSha256] IS NOT NULL AND [DisclosureSha256] IS NOT NULL)"));
        model.Entity<AuditEvent>().HasIndex(x => new { x.EnvelopeId, x.Sequence }).IsUnique();
        model.Entity<AuditEvent>().ToTable(t => t.HasCheckConstraint("CK_Audit_Chain", "([Sequence] = 1 AND [PrevHash] IS NULL) OR ([Sequence] > 1 AND [PrevHash] IS NOT NULL)"));

        model.Entity<EmailOutbox>().HasIndex(x => new { x.Status, x.AvailableAt });
        model.Entity<WorkItem>().HasIndex(x => new { x.Status, x.AvailableAt });
        model.Entity<EmailOutbox>().ToTable(t => t.HasCheckConstraint("CK_Email_Lease", "[Attempts] >= 0 AND (([LeaseOwner] IS NULL AND [LeaseExpiresAt] IS NULL) OR ([LeaseOwner] IS NOT NULL AND [LeaseExpiresAt] IS NOT NULL))"));
        model.Entity<WorkItem>().ToTable(t => t.HasCheckConstraint("CK_Work_Lease", "[Attempts] >= 0 AND (([LeaseOwner] IS NULL AND [LeaseExpiresAt] IS NULL) OR ([LeaseOwner] IS NOT NULL AND [LeaseExpiresAt] IS NOT NULL))"));

        // All records belong to an envelope except address suppression and pre-envelope work.
        // Explicit deletes make retention ordering visible and avoid SQL multiple-cascade paths.
        foreach (var type in model.Model.GetEntityTypes().ToArray())
        {
            var entity = model.Entity(type.ClrType);
            if (type.ClrType != typeof(Envelope) && type.FindProperty("EnvelopeId") is not null)
                entity.HasOne(typeof(Envelope)).WithMany().HasForeignKey("EnvelopeId").OnDelete(DeleteBehavior.NoAction);
            if (typeof(IVersionedRecord).IsAssignableFrom(type.ClrType))
                entity.Property("RowVersion").IsRowVersion();

            foreach (var property in type.GetProperties().ToArray())
            {
                var name = property.Name;
                var builder = entity.Property(name);
                if (property.ClrType == typeof(string))
                {
                    if (name.EndsWith("Json", StringComparison.Ordinal))
                    {
                        builder.HasColumnType("nvarchar(max)");
                        entity.ToTable(t => t.HasCheckConstraint($"CK_{type.ClrType.Name}_{name}", $"[{name}] IS NULL OR ISJSON([{name}]) = 1"));
                    }
                    else if (name == "ErsdText") builder.HasColumnType("nvarchar(max)").HasMaxLength(32768);
                    else builder.HasMaxLength(name == "PublicId" ? 64 : name.Contains("Email") || name == "To" ? 320 : name is "Value" or "Message" or "LastError" ? 4000 : name.Contains("Ua") || name == "UserAgent" ? 2048 : name.EndsWith("Ip") || name == "Ip" ? 45 : 512);
                }
                var enumType = Nullable.GetUnderlyingType(property.ClrType) ?? property.ClrType;
                if (enumType.IsEnum)
                {
                    builder.HasConversion<string>().HasMaxLength(32);
                    var names = string.Join(",", Enum.GetNames(enumType).Select(x => $"'{x}'"));
                    entity.ToTable(t => t.HasCheckConstraint($"CK_{type.ClrType.Name}_{name}", $"[{name}] IS NULL OR [{name}] IN ({names})"));
                }
                if (property.ClrType == typeof(decimal) || property.ClrType == typeof(decimal?))
                    builder.HasPrecision(10, 8);
                if (property.ClrType == typeof(byte[]) && name != "RowVersion")
                {
                    var length = name == "BaselineSignerVersion" ? 8 : 32;
                    builder.HasMaxLength(length);
                    entity.ToTable(t => t.HasCheckConstraint($"CK_{type.ClrType.Name}_{name}", $"[{name}] IS NULL OR DATALENGTH([{name}]) = {length}"));
                }
            }
        }
    }

    private void GuardAuditMutations()
    {
        ChangeTracker.DetectChanges();
        if(ChangeTracker.Entries<CompletionCandidate>().Any(x=>x.State is EntityState.Modified or EntityState.Deleted))
            throw new InvalidOperationException("Saved completion candidates are immutable. Retention requires a separate privileged path.");
        if(ChangeTracker.Entries<CompletionSealOutput>().Any(x=>x.State is EntityState.Modified or EntityState.Deleted))
            throw new InvalidOperationException("Saved completion seals are immutable. Retention requires a separate privileged path.");
        if (ChangeTracker.Entries<SignaturePreview>().Any(x => x.State == EntityState.Modified &&
            x.Properties.Any(p => p.IsModified && p.Metadata.Name != nameof(SignaturePreview.UsedAt))))
            throw new InvalidOperationException("Saved signature previews are immutable.");
        if (ChangeTracker.Entries<AuditEvent>().Any(x => x.State is EntityState.Modified or EntityState.Deleted))
            throw new InvalidOperationException("Audit events are append-only. Retention requires a separate privileged path.");
        if (ChangeTracker.Entries<SignerReviewCandidate>().Any(x => x.State == EntityState.Modified &&
            x.Properties.Any(p => p.IsModified && p.Metadata.Name is not (nameof(SignerReviewCandidate.UsedAt) or nameof(SignerReviewCandidate.SupersededAt)))))
            throw new InvalidOperationException("Saved signer review candidates are immutable.");
        if (ChangeTracker.Entries<SignerFinishAcceptance>().Any(x=>x.State==EntityState.Modified &&
            x.Properties.Any(p=>p.IsModified && p.Metadata.Name is not (nameof(SignerFinishAcceptance.ProcessedAt) or nameof(SignerFinishAcceptance.NextInvitationId)))))
            throw new InvalidOperationException("Saved signer Finish acceptances are immutable.");
        foreach (var entry in ChangeTracker.Entries<AuditEvent>().Where(x => x.State == EntityState.Added))
            if (!CryptographicOperations.FixedTimeEquals(entry.Entity.Hash, AuditHash.Compute(entry.Entity)))
                throw new InvalidOperationException("Audit hash does not match the canonical event.");
    }

    public override int SaveChanges(bool acceptAllChangesOnSuccess)
    {
        GuardAuditMutations();
        return base.SaveChanges(acceptAllChangesOnSuccess);
    }

    public override Task<int> SaveChangesAsync(bool acceptAllChangesOnSuccess, CancellationToken cancellationToken = default)
    {
        GuardAuditMutations();
        return base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);
    }
}
