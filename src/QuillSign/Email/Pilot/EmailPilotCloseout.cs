using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

internal sealed record EmailPilotCloseoutParent(Guid Id, string Sha256);
internal sealed record EmailPilotCloseoutQueue(EmailPilotCloseoutStep Step, Guid RecordId, Guid WorkId, string MailJson, string WorkJson, Guid OriginalId = default, string? OriginalMailJson = null, string? OriginalWorkJson = null);
internal sealed record EmailPilotCloseoutManifest(string Version, Guid AuthorizationId, DateTimeOffset CreatedAt, DateTimeOffset Until,
    DateTimeOffset DeleteAfter, string ConfigurationSha256, EmailPilotCloseoutParent[] Parents, EmailPilotCloseoutQueue[] Queue, string PublicationSha256);
internal sealed record EmailPilotCloseoutReceipt(string Version, Guid AuthorizationId, int Kind, EmailPilotCloseoutStep Step,
    Guid SubjectEnvelopeId, Guid WorkId, DateTimeOffset At, int EncodedBytes, string RequestSha256,
    [property: JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)] EmailPilotCloseoutLookupBinding? LookupBinding=null,
    [property: JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)] EmailPilotCloseoutQueue? Queued=null);

internal sealed class EmailPilotCloseoutSnapshot
{
    internal EmailPilotCloseoutSnapshot(EmailPilotCloseoutConfiguration configuration, EmailPilotCloseoutManifest manifest,
        IReadOnlyDictionary<Guid, EmailPilotHistoricalState> parents)
    { Configuration = configuration; Manifest = manifest; Parents = parents; }
    internal EmailPilotCloseoutConfiguration Configuration { get; }
    internal EmailPilotCloseoutManifest Manifest { get; }
    private IReadOnlyDictionary<Guid, EmailPilotHistoricalState> Parents { get; }
    internal Guid AuthorizationId => Configuration.AuthorizationId;
    internal DateTimeOffset Until => Manifest.Until;
    internal Guid CompletionRecord => Configuration.CompletionRecord;
    internal Guid VoidRecord => Configuration.VoidRecord;
    internal Guid DeclineRecord => Configuration.DeclineRecord;
    internal ImmutableArray<Guid> CompletionWork => Manifest.Queue.Where(x=>x.Step<=EmailPilotCloseoutStep.CompletionRecipient).Select(x=>x.WorkId).ToImmutableArray();
    internal ImmutableArray<Guid> VoidWork => Manifest.Queue.Where(x=>x.Step is EmailPilotCloseoutStep.VoidSender or EmailPilotCloseoutStep.VoidSigner).Select(x=>x.WorkId).ToImmutableArray();
    internal EmailPilotMailboxes Mailboxes => Parents[Configuration.CompletionParent].Manifest.Mailboxes;
    internal EmailPilotManifest Parent(Guid record) => Parents[record == VoidRecord ? Configuration.VoidParent :
        record == CompletionRecord || record == DeclineRecord ? Configuration.CompletionParent : throw EmailPilotProtection.Invalid()].Manifest;
    internal EmailPilotEnrollment Enrollment(Guid record) => Parents[Parent(record).RunId].Enrollments.Single(x => x.SubjectEnvelopeId == record);
    internal IEnumerable<EmailPilotHistoricalState> ReceiptParents => Parents.Values;
}

// Purpose-specific bounded finishing authority. Original manifests and every
// old accounting/enrollment row remain unchanged and expired.
public sealed partial class EmailPilotCloseout(EmailPilotCloseoutOptions options, EmailOptions email, WorkOptions work,
    Func<QuillSignDbContext> database, Func<EmailPilotLedger> legacy, Func<EmailPilotProtection> protection, TimeProvider time)
{
    internal Func<EmailPilotCloseoutLookup>? Lookup { get; init; }
    internal Func<EmailPayloadProtection>? Payloads { get; init; }
    internal EmailPilotOptions? ReceiptPilotOptions { get; init; }
    private static readonly JsonSerializerOptions Json = new() { Converters = { new JsonStringEnumConverter() } };
    private const string Purpose = "bounded-failed-notice-closeout-manifest-v1", ReceiptPurpose = "bounded-failed-notice-closeout-operation-v1";
    internal bool Available => options.Enabled && options.Host(email,work) && time.GetUtcNow().Offset == TimeSpan.Zero &&
        options.StartsAt <= time.GetUtcNow() && options.Until > time.GetUtcNow();
    internal EmailPilotCloseoutOptions HostOptions=>options;
    internal bool PassHost=>options.HostRole==EmailPilotCloseoutHostRole.Pass && Available;
    internal bool CanAdmit=>Available && options.HostRole is EmailPilotCloseoutHostRole.Legacy or EmailPilotCloseoutHostRole.Web && SendCutoff>Now;
    internal bool CanSend=>Available && options.HostRole is EmailPilotCloseoutHostRole.Legacy or EmailPilotCloseoutHostRole.Pass && SendCutoff>Now;
    internal DateTimeOffset SendCutoff=>options.HostRole==EmailPilotCloseoutHostRole.Legacy?options.Until:new[]{options.StartsAt.AddMinutes(25),options.Until}.Min();
    internal string TransportConfigurationSet=>options.HostRole==EmailPilotCloseoutHostRole.Legacy?email.Ses.ConfigurationSet:options.PrivateConfigurationSet;
    internal DateTimeOffset Now => time.GetUtcNow();
    private static string Hash<T>(T value) => Convert.ToHexStringLower(EmailPilotCanonical.Hash(value));
    private static string Raw<T>(T value) => JsonSerializer.Serialize(value, Json);
    private static InvalidDataException Invalid() => EmailPilotProtection.Invalid();
    internal bool MatchesCapability(string? raw)
    {
        if (!Available || raw is null) return false;
        try { return CryptographicOperations.FixedTimeEquals(EmailPilotCanonical.Capability(raw), Convert.FromHexString(options.Capture().CapabilitySha256)); }
        catch (ArgumentException) { return false; }
    }

    internal async Task<EmailPilotCloseoutSnapshot> CreateAsync(string capability,CancellationToken ct=default)
    {
        var db=database();Clean(db);
        try{return await CreateCoreAsync(capability,ct);}
        catch {db.ChangeTracker.Clear();throw;}
    }

    private async Task<EmailPilotCloseoutSnapshot> CreateCoreAsync(string capability, CancellationToken ct)
    {
        if (!CanAdmit || !MatchesCapability(capability)) throw Invalid();
        var cfg = options.Capture(); var db = database(); Clean(db);
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct), ct);
        await using var tx = await db.Database.BeginTransactionAsync(ct); await Lock(db, Guid.Empty, ct); await Lock(db, cfg.AuthorizationId, ct);
        if (await db.EmailPilotCloseouts.AnyAsync(x => x.Id == cfg.AuthorizationId, ct))
        { var existing = await ReadLockedAsync(db, ct) ?? throw Invalid(); await tx.RollbackAsync(ct); return existing; }
        if (await db.EmailPilotCloseouts.AnyAsync(ct)) throw Invalid(); // This selected package has one authority, never a replacement allowance.
        var parents = await Parents(db, cfg, ct);
        var known = await db.EmailPilotRuns.AsNoTracking().Select(x => x.Id).Take(9).ToArrayAsync(ct);
        if (!known.ToHashSet().SetEquals(cfg.AccountingParents)) throw Invalid();
        var usage = parents.Values.SelectMany(x => x.Reservations).ToArray();
        if (usage.Count(x => x.Kind == EmailPilotAttemptKind.Application) != EmailPilotCloseoutLimits.PriorApplicationAttempts ||
            usage.Count(x => x.Kind == EmailPilotAttemptKind.Simulator) != EmailPilotCloseoutLimits.PriorSimulatorAttempts ||
            usage.Count(x => x.Kind == EmailPilotAttemptKind.Timestamp) != EmailPilotCloseoutLimits.PriorTimestampAttempts ||
            usage.Sum(x => (long)x.EncodedBytes) != EmailPilotCloseoutLimits.PriorEncodedBytes) throw Invalid();
        var facts = new EmailPilotCloseoutSnapshot(cfg, null!, parents);
        foreach (var record in new[] { cfg.CompletionRecord, cfg.VoidRecord, cfg.DeclineRecord })
        {
            var parent = facts.Parent(record); var enrollment = facts.Enrollment(record);
            await EmailPilotAdmission.ReadSourceAsync(db,parent,enrollment,Payloads??throw Invalid(),ct);
            if (enrollment.Verification is null || enrollment.Scenario != (record == cfg.CompletionRecord ? EmailPilotScenario.Completion : record == cfg.VoidRecord ? EmailPilotScenario.Void : EmailPilotScenario.Decline)) throw Invalid();
            var e = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == record, ct);
            if (!e.IsDemo || e.SenderEmail != parent.Mailboxes.Sender || e.Status != (record == cfg.CompletionRecord ? EnvelopeStatus.Completed : record == cfg.VoidRecord ? EnvelopeStatus.Voided : EnvelopeStatus.Draft)) throw Invalid();
            var until = await DocumentRetentionAccess.ReadAsync(db, e, ct); DocumentRetentionAccess.Check(until, time);
            if (until is { } end && end < cfg.Until || record == cfg.DeclineRecord && (e.SenderVerifiedAt is not null || e.SentAt is not null || e.PdfBlob is not null || e.OriginalBlob is not null)) throw Invalid();
            if (await db.Suppressions.AnyAsync(x => x.Email == e.SenderEmail, ct)) throw Invalid();
        }
        var publication = await CompletionDownloadState.ReadAsync(db, cfg.CompletionRecord, time, ct) ?? throw Invalid();
        if (publication.PurgeAfter is null || publication.PurgeAfter < cfg.Until) throw Invalid();
        var pairs = new List<EmailPilotCloseoutQueue>();
        var createdAt=Now;
        foreach (var pair in cfg.CompletionWork.Select(x => (Id:x, Record:cfg.CompletionRecord, Template:CompletionNotificationJobs.Template))
            .Concat(cfg.VoidWork.Select(x => (Id:x, Record:cfg.VoidRecord, Template:VoidNotificationJobs.Template))))
        {
            var mail = await db.EmailOutbox.AsNoTracking().SingleAsync(x => x.Id == pair.Id, ct);
            var item = await db.WorkItems.AsNoTracking().SingleAsync(x => x.Id == pair.Id, ct);
            FailedBeforeProvider(mail, item, pair.Record, pair.Template);
            if(mail.AvailableAt>createdAt||item.AvailableAt>createdAt)throw Invalid();
            var role = Role(facts.Mailboxes, mail.To); var step = pair.Record == cfg.CompletionRecord ? role switch {
                EmailPilotRole.Sender => EmailPilotCloseoutStep.CompletionSender, EmailPilotRole.FirstSigner => EmailPilotCloseoutStep.CompletionFirstSigner,
                EmailPilotRole.SecondSigner => EmailPilotCloseoutStep.CompletionSecondSigner, EmailPilotRole.Recipient => EmailPilotCloseoutStep.CompletionRecipient, _ => throw Invalid() } : role switch {
                EmailPilotRole.Sender => EmailPilotCloseoutStep.VoidSender, EmailPilotRole.FirstSigner => EmailPilotCloseoutStep.VoidSigner, _ => throw Invalid() };
            if (await db.Suppressions.AnyAsync(x => x.Email == mail.To, ct)) throw Invalid();
            pairs.Add(await InsertAliasPairLockedAsync(db,cfg.AuthorizationId,step,mail,item,createdAt,ct));
        }
        if (pairs.Select(x => x.Step).Distinct().Count() != 6) throw Invalid();
        var value = new EmailPilotCloseoutManifest(EmailPilotCloseoutLimits.Version, cfg.AuthorizationId, createdAt, cfg.Until,
            parents.Values.Min(x => x.DeleteAfter), Hash(cfg), parents.Select(x => new EmailPilotCloseoutParent(x.Key, x.Value.Sha256)).OrderBy(x => x.Id).ToArray(), pairs.OrderBy(x => x.Step).ToArray(), Hash(publication));
        if (value.DeleteAfter <= cfg.Until || Encoding.UTF8.GetByteCount(Raw(value)) > 49152) throw Invalid();
        var cipher = protection().Protect(cfg.AuthorizationId, Purpose, value); if (cipher.Length > 65536) throw Invalid();
        db.EmailPilotCloseouts.Add(new() { Id=cfg.AuthorizationId,CreatedAt=value.CreatedAt,Until=value.Until,DeleteAfter=value.DeleteAfter,
            CapabilitySha256=Convert.FromHexString(cfg.CapabilitySha256),ManifestSha256=EmailPilotCanonical.Hash(value),ProtectedManifest=cipher });
        await db.SaveChangesAsync(ct);
        foreach(var pair in value.Queue) {
            var originalMail=JsonSerializer.Deserialize<EmailOutbox>(pair.OriginalMailJson!,Json)??throw Invalid();
            var originalWork=JsonSerializer.Deserialize<WorkItem>(pair.OriginalWorkJson!,Json)??throw Invalid();
            await DemandCanonicalOriginalLockedAsync(db,originalMail,originalWork,ct);
        }
        if (!CanAdmit) throw Invalid(); await tx.CommitAsync(ct); await tx.DisposeAsync();
        return await ReadAsync(ct) ?? throw Invalid();
    }

    internal async Task<EmailPilotCloseoutSnapshot?> ReadAsync(CancellationToken ct = default)
    {
        if (!Available) return null; var db=database(); Clean(db);
        await using var tx=await db.Database.BeginTransactionAsync(ct); var value=await ReadLockedAsync(db,ct); await tx.RollbackAsync(ct); return value;
    }
    internal async Task<EmailPilotCloseoutSnapshot?> ReadLockedAsync(QuillSignDbContext db,CancellationToken ct=default)
    {
        if(!Available)return null;
        var result=await ReadSnapshotLockedAsync(db,options.Capture(),ct);
        if(!Available)throw Invalid();return result;
    }

    private async Task<EmailPilotCloseoutSnapshot?> ReadSnapshotLockedAsync(QuillSignDbContext db,EmailPilotCloseoutConfiguration cfg,CancellationToken ct)
    {
        if(!ReferenceEquals(db,database())||db.Database.CurrentTransaction is null||db.ChangeTracker.HasChanges())throw Invalid();
        var row=await db.EmailPilotCloseouts.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==cfg.AuthorizationId,ct);if(row is null)return null;
        var value=protection().Read<EmailPilotCloseoutManifest>(row.Id,Purpose,row.ProtectedManifest??throw Invalid(),65536);
        if(value.Version!=EmailPilotCloseoutLimits.Version||value.AuthorizationId!=row.Id||value.CreatedAt!=row.CreatedAt||value.Until!=row.Until||value.DeleteAfter!=row.DeleteAfter||
            value.ConfigurationSha256!=Hash(cfg)||value.CreatedAt<cfg.StartsAt||value.CreatedAt>Now||value.Until!=cfg.Until||value.DeleteAfter<=Now||
            !CryptographicOperations.FixedTimeEquals(EmailPilotCanonical.Hash(value),row.ManifestSha256)||!CryptographicOperations.FixedTimeEquals(Convert.FromHexString(cfg.CapabilitySha256),row.CapabilitySha256))throw Invalid();
        var parents=await Parents(db,cfg,ct);
        if(value.Parents.Length!=parents.Count||value.Parents.Any(x=>!parents.TryGetValue(x.Id,out var p)||p.Sha256!=x.Sha256))throw Invalid();
        if(value.Queue.Length!=6||value.Queue.Select(x=>x.Step).Distinct().Count()!=6||
            !value.Queue.Select(x=>x.OriginalId).ToHashSet().SetEquals(cfg.CompletionWork.Concat(cfg.VoidWork))||
            value.Queue.Any(x=>x.OriginalId==Guid.Empty||x.WorkId!=AliasId(cfg.AuthorizationId,x.OriginalId)||x.OriginalMailJson is null||x.OriginalWorkJson is null))throw Invalid();
        foreach(var pair in value.Queue)await DemandFailedOriginalLockedAsync(db,pair,ct);
        return new(cfg,value,parents);
    }

    private async Task<Dictionary<Guid,EmailPilotHistoricalState>> Parents(QuillSignDbContext db,EmailPilotCloseoutConfiguration cfg,CancellationToken ct)
    {
        var result=new Dictionary<Guid,EmailPilotHistoricalState>();
        foreach(var id in cfg.AccountingParents)result.Add(id,await legacy().ReadHistoricalLockedAsync(db,id,ct));
        if(result[cfg.CompletionParent].Manifest.Mailboxes!=result[cfg.VoidParent].Manifest.Mailboxes)throw Invalid();return result;
    }
    private static void Clean(QuillSignDbContext db){if(db.Database.CurrentTransaction is not null||db.ChangeTracker.HasChanges())throw Invalid();}
    private static Task Lock(QuillSignDbContext db,Guid id,CancellationToken ct)=>db.Database.ExecuteSqlInterpolatedAsync($"DECLARE @r int; EXEC @r=sys.sp_getapplock @Resource={"pilot-closeout:"+id.ToString("N")},@LockMode='Exclusive',@LockOwner='Transaction',@LockTimeout=5000; IF @r<0 THROW 50002,'Closeout accounting is busy.',1;",ct);
    private static void Queued(EmailOutbox mail,WorkItem item,Guid record,string template)
    {if(mail.Id!=item.Id||mail.EnvelopeId!=record||item.EnvelopeId!=record||mail.Template!=template||mail.Status!=EmailStatus.Queued||item.Kind!=WorkKind.Email||item.Status!=WorkStatus.Queued||
        mail.Attempts!=0||item.Attempts!=0||mail.SubmissionStartedAt is not null||mail.Provider is not null||mail.ProviderMessageId is not null||mail.LeaseOwner is not null||mail.LeaseExpiresAt is not null||item.LeaseOwner is not null||item.LeaseExpiresAt is not null||mail.LastError is not null||item.LastError is not null||mail.RowVersion.Length!=8||item.RowVersion.Length!=8)throw Invalid();}
    internal static EmailPilotRole Role(EmailPilotMailboxes boxes,string address)=>address==boxes.Sender?EmailPilotRole.Sender:address==boxes.FirstSigner?EmailPilotRole.FirstSigner:address==boxes.SecondSigner?EmailPilotRole.SecondSigner:address==boxes.Recipient?EmailPilotRole.Recipient:EmailPilotRole.None;
}
