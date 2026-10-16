using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

namespace QuillSign.Data;

public sealed class QuillSignDbContext(DbContextOptions<QuillSignDbContext> options) : DbContext(options)
{
    public DbSet<Envelope> Envelopes => Set<Envelope>();
    public DbSet<Signer> Signers => Set<Signer>();
    public DbSet<SignaturePreview> SignaturePreviews => Set<SignaturePreview>();
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
        if (ChangeTracker.Entries<SignaturePreview>().Any(x => x.State == EntityState.Modified &&
            x.Properties.Any(p => p.IsModified && p.Metadata.Name != nameof(SignaturePreview.UsedAt))))
            throw new InvalidOperationException("Saved signature previews are immutable.");
        if (ChangeTracker.Entries<AuditEvent>().Any(x => x.State is EntityState.Modified or EntityState.Deleted))
            throw new InvalidOperationException("Audit events are append-only. Retention requires a separate privileged path.");
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
