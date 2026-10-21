using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Storage;

namespace QuillSign.Completion;

public sealed record CompletionMaterialization(Guid EnvelopeId,string PublicId,byte[] StateSha256,CompletionEvidence Evidence,
    byte[] Source,IReadOnlyList<PageGeometry> Pages,Guid SourceObjectId,Guid FinishId,int CopyVersion,byte[] FrozenStateSha256);

// Internal worker prerequisite. It has no public authorization surface or state mutation.
public sealed class CompletionEvidenceCollector(QuillSignDbContext db,SignerCheckpointState checkpoints,
    SignerCheckpointBlobs accepted,IBlobStore storage,TimeProvider time)
{
    internal bool UsesContext(QuillSignDbContext value)=>ReferenceEquals(db,value);
    private sealed record Frame(Envelope Envelope,Signer[] Signers,Recipient[] Recipients,DocumentField[] Fields,
        SignerFinishAcceptance[] Finishes,SignaturePreview[] Adoptions,AuditEvent[] Events,byte[] Binding,byte[] FrozenBinding,VerifiedSignerContacts? Contacts);
    public async Task<CompletionMaterialization?> CollectAsync(Guid envelopeId,CancellationToken ct=default)
        =>await CollectCore(envelopeId,null,ct);
    internal Task<CompletionMaterialization?> CollectPublishedAsync(Guid id,PublishedCompletionSource source,CancellationToken ct)=>CollectCore(id,source,ct);
    internal Task<CompletionMaterialization?> CollectLockedAsync(Guid id,CancellationToken ct,PublishedCompletionSource? source=null)
    {
        if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("A caller-owned completion transaction is required.");
        return CollectCore(id,source,ct,true);
    }
    private async Task<CompletionMaterialization?> CollectCore(Guid envelopeId,PublishedCompletionSource? published,CancellationToken ct,bool locked=false)
    {
        ct.ThrowIfCancellationRequested(); if(envelopeId==Guid.Empty)return null;
        try {
            var frame=locked ? await CaptureLocked(envelopeId,ct,published) : await Capture(envelopeId,ct,published); if(frame is null)return null;
            var e=frame.Envelope;
            await Verify(new(e.Id,DocumentBlobKind.Original,Id(e.OriginalBlob)),e.OriginalSha256!,ct);
            await Verify(new(e.Id,DocumentBlobKind.Normalized,Id(e.PdfBlob)),e.PdfSha256!,ct);
            await Verify(new(e.Id,DocumentBlobKind.Normalized,Id(e.SentPdfBlob)),e.SentPdfSha256!,ct);
            var marks=new Dictionary<Guid,SignerPdfMarks>(); byte[]? source=null;
            foreach(var signer in frame.Signers) {
                ct.ThrowIfCancellationRequested(); var finish=frame.Finishes.Single(x=>x.SignerId==signer.Id);
                var adoption=frame.Adoptions.Single(x=>x.Id==finish.AdoptionId);
                // Existing narrow accepted-work capabilities verify every predecessor and exact reviewed bytes.
                _=await accepted.PdfAsync(finish,true,ct); var bytes=await accepted.PdfAsync(finish,false,ct);
                marks.Add(signer.Id,await accepted.MarksAsync(finish,adoption,ct));
                if(signer.Order==frame.Signers.Length)source=bytes;
            }
            if(source is null)throw Invalid();
            PageGeometry[] pages;
            lock(SenderPdfRenderer.RenderGate) {
                ct.ThrowIfCancellationRequested(); using var discard=new MemoryStream();
                pages=new PdfValidation(new() {MaximumBytes=64*1024*1024,MaximumPages=200}).Rewrite(new MemoryStream(source),new BoundedDocumentStream(discard,64*1024*1024)).ToArray();
            }
            var expected=JsonSerializer.Deserialize<PageGeometry[]>(e.PageSizesJson!) ?? throw Invalid();
            if(pages.Length!=e.PageCount || !SenderPdfRenderer.GeometryMatches(pages,expected))throw Invalid();
            var current=locked ? await CaptureLocked(envelopeId,ct,published) : await Capture(envelopeId,ct,published);
            if(current is null || !Same(current.Binding,frame.Binding))throw new DocumentConflictException();
            var evidence=Project(current,marks,time.GetUtcNow());
            evidence=CompletionEvidenceValidation.Own(evidence,ct);
            var latest=frame.Finishes.Single(x=>x.Id==e.CurrentFinishId);
            return new(e.Id,e.PublicId,frame.Binding.ToArray(),evidence,source,pages,latest.PdfObjectId,latest.Id,e.CurrentCopyVersion,frame.FrozenBinding.ToArray());
        }
        catch(Azure.RequestFailedException) {throw new IOException("Completion source storage is unavailable.");}
        catch(Exception error) when(error is JsonException or FormatException or InvalidOperationException or ArgumentException or UnauthorizedAccessException or KeyNotFoundException)
        {throw Invalid();}
    }
    private async Task<Frame?> Capture(Guid id,CancellationToken ct,PublishedCompletionSource? published=null)
    {
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct); await using var transaction=await db.Database.BeginTransactionAsync(ct);
        var frame=await CaptureLocked(id,ct,published); await transaction.CommitAsync(ct); return frame;
    }
    // New preparation uses the complete optimistic binding. Saved candidates use the frozen-row
    // binding plus their verified historical anchor, allowing an append-only operational tail.
    internal async Task RecheckLockedAsync(Guid id,byte[] binding,CancellationToken ct,long? sequence=null,byte[]? anchor=null,PublishedCompletionSource? published=null)
    {
        if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("A transaction is required.");
        var frame=await CaptureLocked(id,ct,published);
        if(frame is null || !Same(binding,sequence is null ? frame.Binding : frame.FrozenBinding) ||
            sequence is long n && (n<1 || n>frame.Events.Length || !Same(frame.Events[n-1].Hash,anchor)))throw new DocumentConflictException();
    }
    private async Task<Frame?> CaptureLocked(Guid id,CancellationToken ct,PublishedCompletionSource? published=null)
    {
        var e=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if(e is not null && published is not null)e=published.Project(e);
        if(e is null || e.Status!=EnvelopeStatus.Sent || e.SenderVerifiedAt is null || e.SentAt is null || e.CurrentFinishId is null)return null;
        var maxSequence=published?.AuditSequence ?? long.MaxValue;
        var payloadBytes=await db.Database.SqlQuery<long>($"SELECT COALESCE((SELECT SUM(CONVERT(bigint,DATALENGTH([DataJson]))) FROM [AuditEvents] WHERE [EnvelopeId]={id} AND [Sequence]<={maxSequence}),0) + COALESCE((SELECT SUM(CONVERT(bigint,DATALENGTH([FieldsJson]))) FROM [SignerFinishAcceptances] WHERE [EnvelopeId]={id}),0) AS [Value]").SingleAsync(ct);
        if(payloadBytes>16*1024*1024)throw Invalid();
        var signers=await db.Signers.AsNoTracking().Where(x=>x.EnvelopeId==id).OrderBy(x=>x.Order).Take(101).ToArrayAsync(ct);
        if(signers.Length==0 || signers.Any(x=>x.Status!=SignerStatus.Signed))return null;
        if(signers.Length>100 || signers.Where((s,i)=>s.Order!=i+1).Any())throw Invalid();
        var source=await checkpoints.CurrentAsync(e,ct); if(source is null || source.Version!=signers.Length)throw Invalid();
        var finishes=await db.SignerFinishAcceptances.AsNoTracking().Where(x=>x.EnvelopeId==id).OrderBy(x=>x.SignerId).Take(101).ToArrayAsync(ct);
        if(finishes.Length!=signers.Length)throw Invalid();
        var adoptions=new List<SignaturePreview>();
        foreach(var signer in signers) {
            var finish=finishes.SingleOrDefault(x=>x.SignerId==signer.Id);
            if(finish is null || finish.ProcessedAt is null || finish.ProcessedAt<finish.FinishedAt || finish.FinishedAt<e.SentAt ||
                e.ExpiresAt is DateTimeOffset end && (finish.FinishedAt>=end || finish.ReviewExpiresAt>end))throw Invalid();
            adoptions.Add(await checkpoints.AcceptanceAsync(finish,signer,ct) ?? throw Invalid());
        }
        var recipients=await db.Recipients.AsNoTracking().Where(x=>x.EnvelopeId==id).OrderBy(x=>x.Id).Take(101).ToArrayAsync(ct);
        var fields=await db.Fields.AsNoTracking().Where(x=>x.EnvelopeId==id).OrderBy(x=>x.Id).Take(201).ToArrayAsync(ct);
        var events=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==id && x.Sequence<=maxSequence).OrderBy(x=>x.Sequence).Take(513).ToArrayAsync(ct);
        if(recipients.Length>100 || fields.Length is <1 or >200 || events.Length is <1 or >512)throw Invalid();
        byte[]? previous=null; long dataBytes=0;
        foreach(var entry in events) {
            ct.ThrowIfCancellationRequested();
            if(entry.Sequence<1 || entry.Sequence>events.Length || entry!=events[entry.Sequence-1] || !Enum.IsDefined(entry.ActorType) ||
                entry.DataJson.Length>1024*1024 || (dataBytes+=Encoding.UTF8.GetByteCount(entry.DataJson))>8*1024*1024 ||
                entry.At>time.GetUtcNow() || entry.Hash is not {Length:32} ||
                (previous is null ? entry.PrevHash is not null : !Same(previous,entry.PrevHash)) || !Same(entry.Hash,AuditHash.Compute(entry)))throw Invalid();
            previous=entry.Hash;
        }
        var sent=One(events,"sent",PartyType.Sender,null,e.SenderEmail);
        using(var document=JsonDocument.Parse(sent.DataJson)) {
            var r=document.RootElement; var version=r.GetProperty("reviewedVersion").GetString(); var reviewed=Convert.FromBase64String(version!);
            _=await SenderSentStatus.ReadSentAsync(db,e,reviewed,ct);
        }
        if(sent.At<e.SentAt || !string.IsNullOrEmpty(e.SenderName))throw Invalid();
        var verification=One(events,"sender_email_verified",PartyType.Sender,null,e.SenderEmail);
        if(verification.Sequence>=sent.Sequence || verification.At<e.SenderVerifiedAt)throw Invalid();
        VerifiedSignerContacts? contacts=null;
        if(events.Any(x=>x.Event==SignerContactHistory.Event))
        {
            // Published projections contain the pre-publication envelope/version;
            // contact verification locks the actual immutable current row instead.
            var contactEnvelope=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==id,ct);
            contacts=await new SignerContactState(db,time).ReadHistoryLockedAsync(contactEnvelope,ct);
        }
        Metadata(e,signers,recipients,fields,events,sent,contacts);
        // Valid metadata refs and disclosure are proven before any original/converted storage capability is minted.
        _=Id(e.OriginalBlob); _=Id(e.PdfBlob); _=Id(e.SentPdfBlob);
        if(e.OriginalSha256 is not {Length:32} || e.PdfSha256 is not {Length:32} || e.PageCount is not >0 || e.PageSizesJson is null)throw Invalid();
        var previews=adoptions.OrderBy(x=>x.Id).ToArray();
        var frozen=SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {e,signers,recipients,fields,finishes,previews}));
        var binding=SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {frozen,auditAnchor=previous}));
        var frame=new Frame(e,signers,recipients,fields,finishes,previews,events,binding,frozen,contacts);
        // Project validates semantic link/consent/publication evidence while the frozen frame is locked.
        ValidateSigningEvents(frame);
        return frame;
    }
    private static void Metadata(Envelope e,Signer[] signers,Recipient[] recipients,DocumentField[] fields,AuditEvent[] events,AuditEvent sent,VerifiedSignerContacts? contacts)
    {
        var signerEvents=events.Where(x=>x.Event is "signer_added" or "signer_updated" or "signer_removed" or "signers_reordered").ToArray();
        var recipientEvents=events.Where(x=>x.Event is "recipient_added" or "recipient_updated" or "recipient_removed").ToArray();
        var documents=events.Where(x=>x.Event is "document_uploaded" or "document_replaced").ToArray();
        if(signerEvents.Length==0 || documents.Length==0 || signerEvents.Concat(recipientEvents).Concat(documents).Any(x=>x.Sequence>=sent.Sequence || x.ActorType!=PartyType.Sender || x.ActorEmail!=e.SenderEmail))throw Invalid();
        using(var list=JsonDocument.Parse(signerEvents[^1].DataJson)) {
            var expected=contacts is null ? JsonSerializer.Serialize(signers.Select(x=>new {x.Id,x.Order,x.FullName,x.Email,x.Role})) :
                JsonSerializer.Serialize(signers.Select(x=>contacts.Resolve(x.Id,SignerContactEpoch.Legacy) ?? throw Invalid()).Select(x=>new {x.Id,x.Order,FullName=x.Name,x.Email,x.Role}));
            if(list.RootElement.GetProperty("signers").GetRawText()!=expected)throw Invalid();
        }
        if(recipientEvents.Length==0) {if(recipients.Length!=0)throw Invalid();}
        else {
            using var list=JsonDocument.Parse(recipientEvents[^1].DataJson); var rows=list.RootElement.GetProperty("recipients").EnumerateArray().ToArray();
            if(rows.Length!=recipients.Length || rows.Select(x=>x.GetProperty("Id").GetGuid()).Distinct().Count()!=rows.Length)throw Invalid();
            foreach(var row in rows)if(!recipients.Any(r=>r.Id==row.GetProperty("Id").GetGuid() && r.Name==row.GetProperty("Name").GetString() && r.Email==row.GetProperty("Email").GetString()))throw Invalid();
        }
        using(var upload=JsonDocument.Parse(documents[^1].DataJson)) {
            var r=upload.RootElement;
            if(r.GetProperty("originalSha256").GetString()!=Hex(e.OriginalSha256!) || r.GetProperty("pdfSha256").GetString()!=Hex(e.PdfSha256!) || r.GetProperty("pageCount").GetInt32()!=e.PageCount)throw Invalid();
        }
        var finalized=One(events,"fields_finalized",PartyType.Sender,null,e.SenderEmail);
        using(var proof=JsonDocument.Parse(finalized.DataJson)) {
            var snapshot=JsonSerializer.SerializeToUtf8Bytes(fields.Select(x=>new {x.Id,x.SignerId,x.Type,x.Page,x.X,x.Y,x.Width,x.Height,x.Required,x.Label,Value=x.SignerId is null ? x.Value : null}));
            var r=proof.RootElement;
            if(finalized.Sequence>=sent.Sequence || r.GetProperty("fieldCount").GetInt32()!=fields.Length || r.GetProperty("documentSha256").GetString()!=Hex(e.SentPdfSha256!) ||
                r.GetProperty("fieldSnapshotSha256").GetString()!=Hex(SHA256.HashData(snapshot)))throw Invalid();
        }
    }
    private static void ValidateSigningEvents(Frame frame)
    {
        foreach(var signer in frame.Signers) {
            var f=frame.Finishes.Single(x=>x.SignerId==signer.Id);
            var consent=One(CurrentEvents(frame,signer.Id),"consent_given",PartyType.Signer,signer.Id,signer.Email);
            var completed=One(frame.Events,"signer_completed",PartyType.Signer,signer.Id,signer.Email);
            if(consent.At<signer.ConsentAt || consent.At>f.FinishedAt || completed.At<f.ProcessedAt || completed.At<f.FinishedAt)throw Invalid();
            using(var proof=JsonDocument.Parse(consent.DataJson)) {
                var r=proof.RootElement;
                if(r.GetProperty("disclosureVersion").GetString()!=frame.Envelope.ErsdVersion || r.GetProperty("disclosureSha256").GetString()!=Hex(f.DisclosureSha256) ||
                    r.GetProperty("documentSha256").GetString()!=Hex(f.SourceSha256) || !r.GetProperty("agreement").GetBoolean() || !r.GetProperty("canRetain").GetBoolean() ||
                    r.GetProperty("accessMethod").GetString() is not ("preview" or "download") || r.GetProperty("serverEvidence").GetString()!="hash_verified_pdf_prepared" ||
                    r.GetProperty("clientEvidence").GetString()!="signer_reported_access_and_retention" || !r.GetProperty("accessReceiptId").TryGetGuid(out var receipt) || receipt==Guid.Empty)throw Invalid();
            }
            _=Link(frame,signer,f,consent);
        }
    }
    private static AuditEvent Link(Frame frame,Signer signer,SignerFinishAcceptance f,AuditEvent consent)
    {
        foreach(var entry in CurrentEvents(frame,signer.Id).Where(x=>x.Event=="link_opened" && x.ActorType==PartyType.Signer && x.ActorId==signer.Id && x.ActorEmail==signer.Email && x.Sequence<consent.Sequence && x.At<=signer.ConsentAt)) {
            using var proof=JsonDocument.Parse(entry.DataJson); var r=proof.RootElement;
            if(r.GetProperty("signerId").GetGuid()==signer.Id && r.GetProperty("documentId").GetGuid()==f.SourceObjectId &&
                r.GetProperty("documentSha256").GetString()==Hex(f.SourceSha256) && r.GetProperty("disclosureSha256").GetString()==Hex(f.DisclosureSha256) &&
                r.GetProperty("authentication").GetString()=="single_use_email_link" && r.GetProperty("tokenId").GetGuid()!=Guid.Empty)return entry;
        }
        throw Invalid();
    }
    private static CompletionEvidence Project(Frame frame,Dictionary<Guid,SignerPdfMarks> marks,DateTimeOffset prepared)
    {
        var e=frame.Envelope; var sender=One(frame.Events,"sender_email_verified",PartyType.Sender,null,e.SenderEmail);
        var signers=frame.Signers.Select(s=> {
            var f=frame.Finishes.Single(x=>x.SignerId==s.Id); var consent=One(CurrentEvents(frame,s.Id),"consent_given",PartyType.Signer,s.Id,s.Email);
            var linked=Link(frame,s,f,consent); var published=One(frame.Events,"signer_completed",PartyType.Signer,s.Id,s.Email); var image=marks[s.Id];
            var signature=frame.Fields.Any(x=>x.SignerId==s.Id && x.Type==FieldType.Signature && x.Value is not null);
            var initials=frame.Fields.Any(x=>x.SignerId==s.Id && x.Type==FieldType.Initials && x.Value is not null);
            return new CompletionSigner(s.Id,s.Order,s.FullName,s.Email,s.Role,linked.At,linked.At,consent.At,f.FinishedAt,published.At,e.ErsdVersion!,f.DisclosureSha256.ToArray(),
                f.PdfSha256.ToArray(),f.Ip,f.UserAgent,f.AdoptionId,signature ? new(image.Signature,image.SignatureSha256,image.NormalizationVersion) : null,
                initials ? new(image.Initials,image.InitialsSha256,image.NormalizationVersion) : null);
        }).ToArray();
        return new(Guid.ParseExact(e.PublicId,"N"),prepared,e.IsDemo,false,new(Id(e.PdfBlob),e.Title!,e.PageCount!.Value,e.OriginalSha256!.ToArray(),e.PdfSha256!.ToArray(),e.SentPdfSha256!.ToArray(),frame.Finishes.Single(x=>x.Id==e.CurrentFinishId).PdfSha256.ToArray()),
            new(null,e.SenderEmail,sender.At),e.ErsdVersion!,e.ErsdSha256!.ToArray(),signers,frame.Recipients.Select(r=>new CompletionRecipient(r.Name,r.Email)).ToArray(),
            frame.Events.Select(x=>new CompletionEvent(x.Sequence,x.At,x.Event,x.ActorType.ToString(),x.ActorEmail,x.Ip,x.UserAgent,x.PrevHash?.ToArray() ?? new byte[32],x.Hash.ToArray())
            {ContactCorrection=Correction(frame,x)}).ToArray(),frame.Events[^1].Hash.ToArray());
    }
    private static AuditEvent[] CurrentEvents(Frame frame,Guid signerId)
    {
        var current=frame.Contacts?.Current.Single(x=>x.Id==signerId);
        if(current is null || current.Epoch==SignerContactEpoch.Legacy)return frame.Events;
        var revision=frame.Contacts!.Revision(current.Epoch.RevisionId) ?? throw Invalid();
        var boundary=frame.Events.Single(x=>x.Event==SignerContactHistory.Event && x.DataJson==SignerContactHistory.Canonical(revision)).Sequence;
        return frame.Events.Where(x=>x.Sequence>boundary).ToArray();
    }
    private static CompletionContactCorrection? Correction(Frame frame,AuditEvent entry)
    {
        if(entry.Event!=SignerContactHistory.Event)return null;
        var revision=JsonSerializer.Deserialize<SignerContactRevision>(entry.DataJson,new JsonSerializerOptions{PropertyNamingPolicy=JsonNamingPolicy.CamelCase}) ?? throw Invalid();
        if(frame.Contacts?.Revision(revision.Id)!=revision)throw Invalid();
        var party=frame.Contacts.Resolve(revision.SignerId,new(revision.Id,revision.Number)) ?? throw Invalid();
        return new(revision.SignerId,party.Name,revision.OldEmail,revision.NewEmail,revision.Id,revision.Number,revision.RetirementSha256);
    }
    private async Task Verify(DocumentBlob blob,byte[] expected,CancellationToken ct)
    {
        if(expected is not {Length:32})throw Invalid(); using var output=new HashSink(64*1024*1024);
        var length=await storage.CopyToAsync(CompletionReadCapability.Create(blob,time),blob,output,ct);
        if(length!=output.Length || length<16 || !Same(expected,output.Digest()))throw Invalid();
    }
    private static AuditEvent One(AuditEvent[] events,string kind,PartyType actor,Guid? id,string email)
    {var matches=events.Where(x=>x.Event==kind && x.ActorType==actor && x.ActorId==id && x.ActorEmail==email).Take(2).ToArray(); return matches.Length==1 ? matches[0] : throw Invalid();}
    private static Guid Id(string? value)=>Guid.TryParseExact(value,"N",out var id) && id!=Guid.Empty ? id : throw Invalid();
    private static string Hex(byte[] value)=>Convert.ToHexStringLower(value);
    private static bool Same(byte[]? a,byte[]? b)=>SignerCheckpointState.Same(a,b);
    private static InvalidDataException Invalid()=>new("The complete frozen signing evidence could not be verified.");
    private sealed class HashSink(long maximum) : Stream
    {
        private readonly IncrementalHash hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256); private long count;
        public byte[] Digest()=>hash.GetHashAndReset(); public override long Length=>count;
        public override void Write(ReadOnlySpan<byte> buffer) {if(buffer.Length>maximum-count)throw Invalid(); hash.AppendData(buffer); count+=buffer.Length;}
        public override void Write(byte[] buffer,int offset,int length)=>Write(buffer.AsSpan(offset,length));
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer,CancellationToken ct=default) {ct.ThrowIfCancellationRequested(); Write(buffer.Span); return ValueTask.CompletedTask;}
        public override Task WriteAsync(byte[] buffer,int offset,int length,CancellationToken ct)=>WriteAsync(buffer.AsMemory(offset,length),ct).AsTask();
        public override bool CanRead=>false; public override bool CanSeek=>false; public override bool CanWrite=>true;
        public override long Position {get=>count;set=>throw new NotSupportedException();} public override void Flush() { }
        public override int Read(byte[] buffer,int offset,int length)=>throw new NotSupportedException(); public override long Seek(long offset,SeekOrigin origin)=>throw new NotSupportedException(); public override void SetLength(long length)=>throw new NotSupportedException();
        protected override void Dispose(bool disposing) {if(disposing)hash.Dispose(); base.Dispose(disposing);}
    }
}
