using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Storage;

namespace QuillSign.Signing;

public sealed record SignerReviewPrepared(Guid Id,string Receipt,string PdfSha256,string SnapshotSha256,
    DateOnly ProspectiveDate,DateTimeOffset PreparedAt,DateTimeOffset ExpiresAt);
public sealed record SignerReviewData(SignerReviewPrepared Candidate,byte[] Pdf);
public sealed record SignerReviewReceipt(Guid Id,VerifiedSigner Identity,string PdfSha256,string SnapshotSha256,
    string RecipeSha256,Guid AdoptionId,DateOnly ProspectiveDate,DateTimeOffset PreparedAt,DateTimeOffset ExpiresAt);

public sealed class SignerReviewProtection(IDataProtectionProvider provider,TimeProvider time)
{
    private readonly IDataProtector protector=provider.CreateProtector("QuillSign.SignerReview.v1");
    internal string Create(SignerReviewCandidate p,VerifiedSigner identity)=>protector.Protect(JsonSerializer.Serialize(new SignerReviewReceipt(
        p.Id,identity,Hex(p.PdfSha256),Hex(p.SnapshotSha256),Hex(p.RecipeSha256),p.AdoptionId,p.ProspectiveDate,p.PreparedAt,p.ExpiresAt)));
    public SignerReviewReceipt? Read(string? value,VerifiedSigner identity)
        =>ReadCore(value,identity,false);
    // Only a durable accepted-Finish replay may use an expired review proof.
    internal SignerReviewReceipt? ReadAccepted(string? value,VerifiedSigner identity)
        =>ReadCore(value,identity,true);
    private SignerReviewReceipt? ReadCore(string? value,VerifiedSigner identity,bool accepted)
    {
        if(value is null || value.Length>8192)return null;
        try
        {
            var p=JsonSerializer.Deserialize<SignerReviewReceipt>(protector.Unprotect(value)); var now=time.GetUtcNow();
            return p is not null && p.Id!=Guid.Empty && p.Identity==identity && p.AdoptionId!=Guid.Empty &&
                p.PreparedAt<=now && identity.SessionExpiresAt>now && p.ExpiresAt>p.PreparedAt && p.ExpiresAt<=identity.SessionExpiresAt && p.ExpiresAt<=p.PreparedAt.AddMinutes(10) &&
                (accepted || p.ExpiresAt>now && p.ProspectiveDate==DateOnly.FromDateTime(now.UtcDateTime)) && p.ProspectiveDate==DateOnly.FromDateTime(p.PreparedAt.UtcDateTime) ? p : null;
        }
        catch(Exception e) when(e is CryptographicException or JsonException or ArgumentException) { return null; }
    }
    private static string Hex(byte[] b)=>Convert.ToHexStringLower(b);
}

// Explicit preparation only. No field/signing state is frozen or completed here.
public sealed class SignerReviewCandidates(QuillSignDbContext db,SignerAccess access,SignatureAdoption adoption,SignerPdfAccess pdf,
    SignerPdfRenderer renderer,IBlobStore blobs,SignerReviewProtection protection,AuditWriter audit,TimeProvider time)
{
    public const string SnapshotVersion="signer-review-v1";
    public const int MaximumCandidatesPerSigner=20,MaximumActiveCandidates=2;
    private const long MaximumPdfBytes=64*1024*1024;
    private sealed record State(SignerReadContext Context,Envelope Envelope,Signer Signer,DocumentField[] Fields,
        CurrentSignatureAssets Assets,byte[] SnapshotHash,PageGeometry[] Pages);

    public async Task<SignerReviewPrepared?> PrepareAsync(ClaimsPrincipal principal,string publicId,string? ip=null,string? ua=null,CancellationToken ct=default)
    {
        var committed=false; var commitStarted=false; DocumentBlob? attempted=null; VerifiedSigner? identity=null;
        try
        {
            await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
            await using var transaction=await db.Database.BeginTransactionAsync(ct);
            var state=await Current(principal,publicId,ct); if(state is null)return null; identity=state.Context.Identity;
            var source=await pdf.PrepareAsync(principal,state.Context,ct); var now=time.GetUtcNow();
            var existing=await db.SignerReviewCandidates.AsNoTracking().Where(x=>x.EnvelopeId==identity.EnvelopeId && x.SignerId==identity.SignerId &&
                x.UsedAt==null && x.SupersededAt==null && x.ExpiresAt>now && x.SessionSha256==SessionHash(identity) && x.SnapshotSha256==state.SnapshotHash)
                .OrderByDescending(x=>x.PreparedAt).FirstOrDefaultAsync(ct);
            if(existing is not null)
            {
                if(!Matches(existing,state) || !await Evidence(existing,identity,ct))return null;
                _=await ReadPdf(existing,identity,ct);
                if(!await Live(existing,principal,publicId,ct))return null;
                await transaction.CommitAsync(ct); committed=true; return Data(existing,identity);
            }
            if(await db.SignerReviewCandidates.CountAsync(x=>x.EnvelopeId==identity.EnvelopeId && x.SignerId==identity.SignerId,ct)>=MaximumCandidatesPerSigner)
                throw new InvalidOperationException("This request reached its signer review limit. Contact the sender.");
            await db.SignerReviewCandidates.Where(x=>x.EnvelopeId==identity.EnvelopeId && x.SignerId==identity.SignerId && x.UsedAt==null &&
                x.SupersededAt==null && x.ExpiresAt>now && x.SnapshotSha256!=state.SnapshotHash).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SupersededAt,now),ct);
            if(await db.SignerReviewCandidates.CountAsync(x=>x.EnvelopeId==identity.EnvelopeId && x.SignerId==identity.SignerId && x.UsedAt==null && x.SupersededAt==null && x.ExpiresAt>now,ct)>=MaximumActiveCandidates)
                throw new InvalidOperationException("Reuse a current review copy or wait for another review session to expire.");
            var midnight=new DateTimeOffset(now.UtcDateTime.Date.AddDays(1),TimeSpan.Zero);
            var expires=new[]{now.AddMinutes(10),identity.SessionExpiresAt,state.Envelope.ExpiresAt??DateTimeOffset.MaxValue,midnight}.Min();
            if(expires<=now)return null;
            var a=state.Assets; var marks=new SignerPdfMarks(a.Preview.Id,a.Preview.SignatureObjectId,a.Preview.InitialsObjectId,
                a.Signature,a.Initials,a.Preview.SignatureSha256,a.Preview.InitialsSha256,a.Preview.NormalizationVersion);
            var request=new SignerPdfRequest(identity.EnvelopeId,identity.SignerId,state.Signer.FullName,now,a.Preview.Id,
                state.Fields.Select(f=>new SignerPdfField(f.Id,f.EnvelopeId,f.SignerId,f.RowVersion,f.Type,f.Page,f.X,f.Y,f.Width,f.Height,
                    f.Required,f.Value,f.FilledAt,f.FilledBy,f.SignatureAdoptionId,f.ImageSha256)).ToArray(),marks);
            var rendered=renderer.Render(source,state.Context.DocumentSha256,state.Pages,request);
            var candidate=new SignerReviewCandidate { EnvelopeId=identity.EnvelopeId,SignerId=identity.SignerId,AdoptionId=a.Preview.Id,
                SourceObjectId=identity.DocumentId,PdfObjectId=Guid.NewGuid(),PdfLength=rendered.Bytes.LongLength,
                SourceSha256=rendered.SourceSha256,DisclosureSha256=Convert.FromHexString(identity.DisclosureHash),SessionSha256=SessionHash(identity),
                SnapshotSha256=state.SnapshotHash,PdfSha256=rendered.Sha256,RecipeSha256=rendered.BindingSha256,RendererVersion=rendered.RendererVersion,
                SnapshotVersion=SnapshotVersion,PreparedAt=now,ExpiresAt=expires,ProspectiveDate=DateOnly.FromDateTime(now.UtcDateTime) };
            attempted=Blob(candidate); using(var input=new MemoryStream(rendered.Bytes,false))
                await blobs.WriteAsync(Capability(identity,attempted.Value,AssetOperation.Write),attempted.Value,input,input.Length,ct);
            _=await ReadPdf(candidate,identity,ct);
            if(!await Live(candidate,principal,publicId,ct))return null;
            db.SignerReviewCandidates.Add(candidate); await db.SaveChangesAsync(ct);
            await audit.AppendAsync(identity.EnvelopeId,"signer_review_prepared",identity.Email,ip,ua,ct,JsonSerializer.Serialize(new {
                candidateId=candidate.Id,candidate.PdfObjectId,candidate.SourceObjectId,candidate.PdfLength,candidate.AdoptionId,
                sourceSha256=Hex(candidate.SourceSha256),disclosureSha256=Hex(candidate.DisclosureSha256),sessionSha256=Hex(candidate.SessionSha256),
                snapshotSha256=Hex(candidate.SnapshotSha256),pdfSha256=Hex(candidate.PdfSha256),recipeSha256=Hex(candidate.RecipeSha256),
                candidate.RendererVersion,candidate.SnapshotVersion,candidate.ProspectiveDate,candidate.PreparedAt,candidate.ExpiresAt,
                serverEvidence="exact_review_pdf_prepared_not_user_review_or_finish" }),PartyType.Signer,identity.SignerId);
            if(!await Live(candidate,principal,publicId,ct))return null;
            commitStarted=true; await transaction.CommitAsync(ct); committed=true; return Data(candidate,identity);
        }
        finally
        {
            if(!committed && !commitStarted && attempted is DocumentBlob blob && identity is not null)
                try { await blobs.DeleteAsync(Capability(identity,blob,AssetOperation.Delete),blob,CancellationToken.None); }
                catch(Exception e) when(e is not OutOfMemoryException) { /* Unreachable bytes remain for envelope purge. */ }
        }
    }

    public async Task<SignerReviewData?> ReadAsync(ClaimsPrincipal principal,string publicId,string? receipt,CancellationToken ct=default)
    {
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
        await using var transaction=await db.Database.BeginTransactionAsync(ct);
        var review=await ReadLockedAsync(principal,publicId,receipt,ct); if(review is null)return null;
        await transaction.CommitAsync(ct); return new(Data(review.Candidate,review.Identity),review.Pdf);
    }
    internal sealed record LockedReview(SignerReviewCandidate Candidate,VerifiedSigner Identity,byte[] Pdf);
    internal async Task<LockedReview?> ReadLockedAsync(ClaimsPrincipal principal,string publicId,string? receipt,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("A transaction is required.");
        var context=await access.GetLockedContextAsync(principal,publicId,ct); if(context?.ConsentAt is null)return null;
        var token=protection.Read(receipt,context.Identity); if(token is null)return null;
        var candidate=await db.SignerReviewCandidates.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==token.Id && x.EnvelopeId==context.Identity.EnvelopeId && x.SignerId==context.Identity.SignerId,ct);
        if(candidate is null || !TokenMatches(candidate,token))return null;
        var state=await Current(principal,publicId,ct); if(state is null || !Matches(candidate,state) || !await Evidence(candidate,context.Identity,ct))return null;
        var bytes=await ReadPdf(candidate,context.Identity,ct); if(!await Live(candidate,principal,publicId,ct))return null;
        return new(candidate,context.Identity,bytes);
    }
    internal static bool TokenMatches(SignerReviewCandidate candidate,SignerReviewReceipt token)=>candidate.Id==token.Id &&
        candidate.EnvelopeId==token.Identity.EnvelopeId && candidate.SignerId==token.Identity.SignerId && candidate.AdoptionId==token.AdoptionId &&
        candidate.PreparedAt==token.PreparedAt && candidate.ExpiresAt==token.ExpiresAt && candidate.ProspectiveDate==token.ProspectiveDate &&
        Hex(candidate.PdfSha256)==token.PdfSha256 && Hex(candidate.SnapshotSha256)==token.SnapshotSha256 && Hex(candidate.RecipeSha256)==token.RecipeSha256 &&
        Same(candidate.SessionSha256,SessionHash(token.Identity));
    internal async Task<bool> VerifySourceLockedAsync(ClaimsPrincipal principal,string publicId,CancellationToken ct)
    {
        var context=await access.GetLockedContextAsync(principal,publicId,ct); if(context?.ConsentAt is null)return false;
        _=await pdf.PrepareAsync(principal,context,ct); return true;
    }

    private async Task<State?> Current(ClaimsPrincipal principal,string publicId,CancellationToken ct)
    {
        var context=await access.GetLockedContextAsync(principal,publicId,ct); if(context?.ConsentAt is null)return null;
        var identity=context.Identity; var envelope=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==identity.EnvelopeId,ct);
        var signer=await db.Signers.AsNoTracking().SingleAsync(x=>x.Id==identity.SignerId && x.EnvelopeId==identity.EnvelopeId,ct);
        var fields=await db.Fields.AsNoTracking().Where(x=>x.EnvelopeId==identity.EnvelopeId && x.SignerId==identity.SignerId).OrderBy(x=>x.Id).Take(201).ToArrayAsync(ct);
        if(envelope.PageCount is not (>=1 and <=200) || fields.Length is <1 or >200 ||
            fields.Any(f=>f.RowVersion.Length!=8 || !Enum.IsDefined(f.Type) || f.Page<1 || f.Page>envelope.PageCount || !FieldGeometry.InBounds(f.X,f.Y,f.Width,f.Height)) ||
            fields.Any(f=>f.Required && f.Type!=FieldType.DateSigned && !SignerFields.Item(f,signer).Filled) ||
            !fields.Any(f=>f.Type==FieldType.Signature && SignerFields.Item(f,signer).Filled))return null;
        var assets=await adoption.GetCurrentLockedAsync(identity,ct); if(assets is null)return null;
        PageGeometry[]? pages;
        try { pages=JsonSerializer.Deserialize<PageGeometry[]>(envelope.PageSizesJson??"null"); } catch(JsonException) { return null; }
        if(pages?.Length!=envelope.PageCount)return null;
        var hash=SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { version=SnapshotVersion,identity.EnvelopeId,identity.SignerId,identity.DocumentId,
            identity.DocumentHash,identity.DisclosureHash,envelope.RowVersion,envelope.PageCount,envelope.PageSizesJson,
            signer.FullName,signer.ConsentAt,signerVersion=signer.RowVersion,adoptionId=assets.Preview.Id,
            assets.Preview.SignatureSha256,assets.Preview.InitialsSha256,assets.Preview.NormalizationVersion,fields }));
        return new(context,envelope,signer,fields,assets,hash,pages!);
    }
    private bool Matches(SignerReviewCandidate p,State s)=>p.UsedAt is null && p.SupersededAt is null && p.ExpiresAt>time.GetUtcNow() && p.PreparedAt<=time.GetUtcNow() &&
        p.ProspectiveDate==DateOnly.FromDateTime(time.GetUtcNow().UtcDateTime) && p.EnvelopeId==s.Context.Identity.EnvelopeId && p.SignerId==s.Context.Identity.SignerId &&
        p.SourceObjectId==s.Context.Identity.DocumentId && p.AdoptionId==s.Assets.Preview.Id && Same(p.SourceSha256,s.Context.DocumentSha256) &&
        Same(p.DisclosureSha256,Convert.FromHexString(s.Context.Identity.DisclosureHash)) && Same(p.SessionSha256,SessionHash(s.Context.Identity)) && Same(p.SnapshotSha256,s.SnapshotHash) &&
        p.RendererVersion==SignerPdfRenderer.Version && p.SnapshotVersion==SnapshotVersion && p.PdfObjectId!=p.SourceObjectId && p.PdfLength is >=16 and <=MaximumPdfBytes;
    private async Task<bool> Live(SignerReviewCandidate p,ClaimsPrincipal principal,string publicId,CancellationToken ct)
    {
        if(p.ExpiresAt<=time.GetUtcNow() || p.ProspectiveDate!=DateOnly.FromDateTime(time.GetUtcNow().UtcDateTime))return false;
        var context=await access.GetLockedContextAsync(principal,publicId,ct); return context?.ConsentAt is not null && context.SignatureAdoptionId==p.AdoptionId;
    }
    internal async Task<byte[]> ReadPdf(SignerReviewCandidate p,VerifiedSigner identity,CancellationToken ct)
    {
        if(p.PdfLength is <16 or >MaximumPdfBytes || p.PdfObjectId==p.SourceObjectId)throw new InvalidDataException("Invalid saved review PDF.");
        using var memory=new MemoryStream(); using var bounded=new BoundedDocumentStream(memory,MaximumPdfBytes); var blob=Blob(p);
        var length=await blobs.CopyToAsync(Capability(identity,blob,AssetOperation.Read),blob,bounded,ct);
        if(length!=p.PdfLength || length!=memory.Length || !Same(p.PdfSha256,SHA256.HashData(memory.GetBuffer().AsSpan(0,checked((int)memory.Length)))))
            throw new InvalidDataException("The saved review PDF could not be verified.");
        return memory.ToArray();
    }
    internal async Task<bool> Evidence(SignerReviewCandidate p,VerifiedSigner identity,CancellationToken ct)
    {
        var events=await db.AuditEvents.FromSqlInterpolated($"SELECT * FROM [AuditEvents] WHERE JSON_VALUE([DataJson], '$.candidateId') = {p.Id.ToString("D")}")
            .AsNoTracking().Where(e=>e.EnvelopeId==identity.EnvelopeId && e.Event=="signer_review_prepared" && e.ActorType==PartyType.Signer && e.ActorId==identity.SignerId && e.ActorEmail==identity.Email).ToArrayAsync(ct);
        if(events.Length!=1 || !Same(events[0].Hash,AuditHash.Compute(events[0])))return false;
        try
        {
            using var json=JsonDocument.Parse(events[0].DataJson); var r=json.RootElement;
            bool Text(string key,string value)=>r.TryGetProperty(key,out var x) && x.ValueKind==JsonValueKind.String && x.GetString()==value;
            bool Id(string key,Guid value)=>r.TryGetProperty(key,out var x) && x.TryGetGuid(out var id) && id==value;
            bool Instant(string key,DateTimeOffset value)=>r.TryGetProperty(key,out var x) && x.TryGetDateTimeOffset(out var instant) && instant==value;
            return Id("candidateId",p.Id) && Id("PdfObjectId",p.PdfObjectId) && Id("SourceObjectId",p.SourceObjectId) && Id("AdoptionId",p.AdoptionId) &&
                r.TryGetProperty("PdfLength",out var length) && length.TryGetInt64(out var n) && n==p.PdfLength &&
                Text("sourceSha256",Hex(p.SourceSha256)) && Text("disclosureSha256",Hex(p.DisclosureSha256)) && Text("sessionSha256",Hex(p.SessionSha256)) &&
                Text("snapshotSha256",Hex(p.SnapshotSha256)) && Text("pdfSha256",Hex(p.PdfSha256)) && Text("recipeSha256",Hex(p.RecipeSha256)) &&
                Text("RendererVersion",p.RendererVersion) && Text("SnapshotVersion",p.SnapshotVersion) && Text("ProspectiveDate",p.ProspectiveDate.ToString("yyyy-MM-dd",System.Globalization.CultureInfo.InvariantCulture)) &&
                Instant("PreparedAt",p.PreparedAt) && Instant("ExpiresAt",p.ExpiresAt) && Text("serverEvidence","exact_review_pdf_prepared_not_user_review_or_finish");
        }
        catch(Exception e) when(e is JsonException or InvalidOperationException or FormatException) { return false; }
    }
    private SignerReviewPrepared Data(SignerReviewCandidate p,VerifiedSigner identity)=>new(p.Id,protection.Create(p,identity),Hex(p.PdfSha256),Hex(p.SnapshotSha256),p.ProspectiveDate,p.PreparedAt,p.ExpiresAt);
    private ClaimsPrincipal Capability(VerifiedSigner identity,DocumentBlob blob,AssetOperation op)=>SignerReviewPdfCapability.Create(identity,blob,op,time);
    private static DocumentBlob Blob(SignerReviewCandidate p)=>new(p.EnvelopeId,DocumentBlobKind.Normalized,p.PdfObjectId);
    private static byte[] SessionHash(VerifiedSigner identity)=>SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(identity));
    private static bool Same(byte[]? a,byte[] b)=>a is { Length:32 } && CryptographicOperations.FixedTimeEquals(a,b);
    private static string Hex(byte[] b)=>Convert.ToHexStringLower(b);
}
