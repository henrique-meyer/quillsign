using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

public sealed class PilotTimestampDeniedException() : Exception("The completion timestamp operation is not authorized.");

// Explicit restricted-runtime composition marker. It captures no scoped services
// and remains present after a run/configuration is disabled.
public sealed class PilotTimestampPolicy;

public sealed class CompletionTimestampWork
{
    internal CompletionTimestampWork(PilotTimestampBoundary owner, WorkLease lease, Guid envelopeId, string payloadHash,
        bool knownPilot, EmailPilotWorkScope? pilot, CompletionWorkPayload payload)
    { Owner=owner; Lease=lease; EnvelopeId=envelopeId; PayloadHash=payloadHash; KnownPilot=knownPilot; Pilot=pilot;
        FinishId=payload.FinishId;CopyVersion=payload.CopyVersion;CheckpointHash=payload.CheckpointSha256; }
    internal PilotTimestampBoundary Owner { get; }
    internal WorkLease Lease { get; }
    internal Guid EnvelopeId { get; }
    internal string PayloadHash { get; }
    internal bool KnownPilot { get; }
    internal EmailPilotWorkScope? Pilot { get; }
    internal Guid FinishId { get; }
    internal int CopyVersion { get; }
    internal string CheckpointHash { get; }
}

public sealed class CompletionTimestampArtifact
{
    internal CompletionTimestampArtifact(CompletionTimestampWork work, Guid candidateId, CompletionSealKind kind,
        byte[] sourceHash, byte[] recipe, byte[]? predecessor, byte[]? predecessorRecipe)
    { Work=work; CandidateId=candidateId; Kind=kind; SourceHash=sourceHash.ToArray(); Recipe=recipe.ToArray();
        Predecessor=predecessor?.ToArray(); PredecessorRecipe=predecessorRecipe?.ToArray(); }
    internal CompletionTimestampWork Work { get; }
    internal Guid CandidateId { get; }
    internal CompletionSealKind Kind { get; }
    internal byte[] SourceHash { get; }
    internal byte[] Recipe { get; }
    internal byte[]? Predecessor { get; }
    internal byte[]? PredecessorRecipe { get; }
    internal DateTimeOffset Until => Work.Pilot?.Until ?? Work.Lease.Until;
    internal TimeProvider Clock => Work.Owner.Clock;
    internal Task DemandAsync(byte[] actualSource, CancellationToken ct) => Work.Owner.DemandArtifactAsync(this,actualSource,ct);
    internal Task<TimestampAttemptPermit> ReserveAsync(byte[] request, CancellationToken ct) => Work.Owner.ReserveAsync(this,request,ct);
}

internal sealed class TimestampAttemptPermit(CompletionTimestampArtifact artifact, byte[] requestHash)
{
    private int consumed;
    internal async Task DemandSendAsync(byte[] request, CancellationToken ct)
    {
        if(Interlocked.Exchange(ref consumed,1)!=0 || !CryptographicOperations.FixedTimeEquals(requestHash,SHA256.HashData(request)))
            throw new PilotTimestampDeniedException();
        await artifact.DemandAsync(artifact.SourceHash,ct);
    }
}

// Scoped owner of per-call immutable contexts; singleton seal/TSA engines receive
// contexts as arguments and never retain this owner or its database in fields.
public sealed class PilotTimestampBoundary(Func<QuillSignDbContext> database, Func<EmailPilotWorkAuthority> authority,
    Func<EmailPilotLedger> ledger, TimeProvider time)
{
    internal TimeProvider Clock => time;
    public async Task<CompletionTimestampWork> ReadCompletionAsync(WorkLease lease, Guid envelopeId, string payload, CancellationToken ct=default)
    {
        if(!Shape(lease,envelopeId) || payload is not {Length:>0 and <=2048})throw new PilotTimestampDeniedException();
        var parsed=JsonSerializer.Deserialize<CompletionWorkPayload>(payload);
        if(parsed is null || parsed.Version!=CompletionJobs.Version || parsed.FinishId==Guid.Empty || parsed.CopyVersion is <1 or >100 ||
            !EmailPilotCanonical.Hash(parsed.CheckpointSha256) || !EmailPilotCanonical.Hash(parsed.DisclosureSha256))throw new PilotTimestampDeniedException();
        var known=await KnownAsync(envelopeId,ct);
        var pilot=known ? await authority().ReadAsync(lease,ct) : null;
        if(known && (pilot is null || !pilot.AllowsTimestamp || pilot.EnvelopeId!=envelopeId))throw new PilotTimestampDeniedException();
        var work=new CompletionTimestampWork(this,lease,envelopeId,Convert.ToHexStringLower(EmailPilotCanonical.Hash<string>(payload)),known,pilot,parsed);
        await DemandWorkAsync(work,ct);return work;
    }

    public async Task<CompletionTimestampArtifact> BindArtifactAsync(CompletionTimestampWork work, Guid candidateId, CompletionSealKind kind,
        byte[] sourceHash, byte[]? predecessor, byte[]? predecessorRecipe, CancellationToken ct=default)
    {
        if(candidateId==Guid.Empty || !Enum.IsDefined(kind) || sourceHash is not {Length:32})throw new PilotTimestampDeniedException();
        var ownedSource=sourceHash.ToArray();var ownedPredecessor=predecessor?.ToArray();var ownedRecipe=predecessorRecipe?.ToArray();
        await DemandWorkAsync(work,ct);
        var row=await database().CompletionCandidates.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==candidateId && x.EnvelopeId==work.EnvelopeId,ct);
        if(row?.RecipeSha256 is not {Length:32})throw new PilotTimestampDeniedException();
        var artifact=new CompletionTimestampArtifact(work,candidateId,kind,ownedSource,row.RecipeSha256,ownedPredecessor,ownedRecipe);
        await DemandArtifactAsync(artifact,ownedSource,ct);return artifact;
    }

    internal async Task DemandArtifactAsync(CompletionTimestampArtifact artifact, byte[] actualSource, CancellationToken ct)
    {
        if(artifact is null || actualSource is not {Length:32} || !Same(artifact.SourceHash,actualSource))throw new PilotTimestampDeniedException();
        await DemandWorkAsync(artifact.Work,ct);
        var db=database();
        var row=await db.CompletionCandidates.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==artifact.CandidateId && x.EnvelopeId==artifact.Work.EnvelopeId,ct);
        if(row is null || row.FinishId!=artifact.Work.FinishId || row.CopyVersion!=artifact.Work.CopyVersion ||
            Convert.ToHexStringLower(row.SourceSha256)!=artifact.Work.CheckpointHash || !Same(row.RecipeSha256,artifact.Recipe))throw new PilotTimestampDeniedException();
        if(artifact.Kind==CompletionSealKind.Executed)
        {
            if(artifact.Predecessor is not null || artifact.PredecessorRecipe is not null || !Same(row.PdfSha256,artifact.SourceHash))
                throw new PilotTimestampDeniedException();
        }
        else if(artifact.Kind!=CompletionSealKind.Certificate || artifact.Predecessor is not {Length:32} || artifact.PredecessorRecipe is not {Length:32} ||
            !await db.CompletionSealOutputs.AsNoTracking().AnyAsync(x=>x.EnvelopeId==artifact.Work.EnvelopeId && x.CandidateId==artifact.CandidateId &&
                x.Kind==CompletionSealKind.Executed && x.PdfSha256==artifact.Predecessor && x.RecipeSha256==artifact.PredecessorRecipe,ct))
            throw new PilotTimestampDeniedException();
    }

    internal async Task<TimestampAttemptPermit> ReserveAsync(CompletionTimestampArtifact artifact, byte[] request, CancellationToken ct)
    {
        if(request is not {Length:>0 and <=16384})throw new PilotTimestampDeniedException();
        await DemandArtifactAsync(artifact,artifact.SourceHash,ct);
        var hash=SHA256.HashData(request);
        if(artifact.Work.KnownPilot)
        {
            var work=artifact.Work;
            var operationHash=EmailPilotCanonical.Hash(new {Version="pilot-timestamp-v1",work.Pilot!.RunId,work.EnvelopeId,
                work.Lease.Id,work.Lease.Owner,work.Lease.Attempt,work.PayloadHash,artifact.CandidateId,artifact.Kind,
                Source=Convert.ToHexStringLower(artifact.SourceHash)});
            var operation=new Guid(operationHash.AsSpan(0,16));
            if(operation==Guid.Empty)throw new PilotTimestampDeniedException();
            EmailPilotReservationOutcome result;
            try { result=await ledger().ReserveAsync(new(operation,work.EnvelopeId,operation,EmailPilotAttemptKind.Timestamp,
                EmailPilotRole.None,0,Convert.ToHexStringLower(hash)),null,ct); }
            catch(Exception e)when(e is not OperationCanceledException and not OutOfMemoryException)
            { throw new PilotTimestampDeniedException(); }
            // A durable receipt is accounting, never a reusable HTTP permit.
            if(result!=EmailPilotReservationOutcome.Reserved)throw new PilotTimestampDeniedException();
        }
        return new(artifact,hash);
    }

    internal async Task DemandWorkAsync(CompletionTimestampWork work, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if(work is null || !ReferenceEquals(work.Owner,this) || !Shape(work.Lease,work.EnvelopeId))throw new PilotTimestampDeniedException();
        var db=database();
        var row=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==work.Lease.Id,ct);
        if(row is null || row.EnvelopeId!=work.EnvelopeId || row.Kind!=WorkKind.Sealing || row.Status!=WorkStatus.Leased ||
            row.LeaseOwner!=work.Lease.Owner || row.Attempts!=work.Lease.Attempt || row.LeaseExpiresAt!=work.Lease.Until ||
            row.LeaseExpiresAt<=Now || row.AvailableAt>Now || row.PayloadJson.Length>2048 ||
            Convert.ToHexStringLower(EmailPilotCanonical.Hash<string>(row.PayloadJson))!=work.PayloadHash || await KnownAsync(work.EnvelopeId,ct)!=work.KnownPilot)
            throw new PilotTimestampDeniedException();
        if(work.KnownPilot && (work.Pilot is null || !work.Pilot.AllowsTimestamp || !await authority().StillCurrentAsync(work.Pilot,ct)))
            throw new PilotTimestampDeniedException();
    }

    private Task<bool> KnownAsync(Guid envelopeId,CancellationToken ct) =>
        database().EmailPilotEnrollments.AsNoTracking().AnyAsync(x=>x.SubjectEnvelopeId==envelopeId,ct);
    private bool Shape(WorkLease lease,Guid envelopeId)=>lease is not null && envelopeId!=Guid.Empty && lease.Id==CompletionJobs.WorkId(envelopeId) &&
        lease.Owner!=Guid.Empty && lease.Kind==WorkKind.Sealing && lease.Attempt>=1 && lease.Until.Offset==TimeSpan.Zero && lease.Until>Now;
    private DateTimeOffset Now=>time.GetUtcNow().ToUniversalTime();
    private static bool Same(byte[]? a,byte[]? b)=>a is {Length:32} && b is {Length:32} && CryptographicOperations.FixedTimeEquals(a,b);
}
