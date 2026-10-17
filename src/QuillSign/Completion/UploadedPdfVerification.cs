using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Sealing;
using QuillSign.Storage;

namespace QuillSign.Completion;

public sealed class UploadedPdfVerificationOptions
{
    public const int HardMaximumBytes=64*1024*1024;
    public int MaximumBytes {get;set;}=HardMaximumBytes;
    public int TimeoutSeconds {get;set;}=60;
    public void Validate() {
        if(MaximumBytes is <16 or >HardMaximumBytes || TimeoutSeconds is <1 or >120)
            throw new InvalidOperationException("Invalid uploaded PDF verification limits.");
    }
}
public enum UploadedPdfVerificationStatus { Verified,NotRecognized,RejectedInput,EvidenceMismatch,Unavailable }
public sealed record UploadedPdfVerificationResult(UploadedPdfVerificationStatus Status,string? Sha256=null,FinalDocumentKind? Kind=null)
{
    public bool SealIntegrity=>Status==UploadedPdfVerificationStatus.Verified;
    public bool TimestampIntegrity=>Status==UploadedPdfVerificationStatus.Verified;
}

// Hash first; unrecognized uploads are never fed to a PDF parser or retained.
// Only existing completed-publication verification can establish known integrity.
// This service grants no downloads, sessions, identity trust or legal-validity claim.
public sealed class UploadedPdfVerification(QuillSignDbContext db,CompletionAccessState state,
    UploadedPdfVerificationOptions options,TimeProvider time)
{
    private sealed record Match(Guid Id,bool Executed,bool Certificate);
    public async Task<UploadedPdfVerificationResult> VerifyAsync(Stream input,long? declaredLength=null,CancellationToken ct=default)
    {
        options.Validate();ct.ThrowIfCancellationRequested();
        if(db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges())throw new InvalidOperationException("Uploaded verification requires a clean standalone unit of work.");
        var maximum=options.MaximumBytes;var until=time.GetUtcNow().AddSeconds(options.TimeoutSeconds);
        if(!input.CanRead || declaredLength is <16 || declaredLength>maximum)return new(UploadedPdfVerificationStatus.RejectedInput);
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(options.TimeoutSeconds),time);
        using var linked=CancellationTokenSource.CreateLinkedTokenSource(ct,deadline.Token);var active=linked.Token;string? digest=null;
        try {
            using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer=new byte[32*1024];var header=new byte[5];long length=0;
            while(true) {
                Active();
                // Consume at most the configured maximum plus one detection byte.
                var allowed=(int)Math.Min(buffer.Length,maximum+1L-length);
                var read=await input.ReadAsync(buffer.AsMemory(0,allowed),active);
                if(read==0)break;
                if(read>allowed || read<0)throw new IOException("Invalid upload stream response.");
                if(length<header.Length)buffer.AsSpan(0,Math.Min(read,header.Length-(int)length)).CopyTo(header.AsSpan((int)length));
                length+=read;if(length>maximum)return new(UploadedPdfVerificationStatus.RejectedInput);
                hash.AppendData(buffer,0,read);
            }
            if(length<16 || declaredLength is { } expected && length!=expected || !header.AsSpan().SequenceEqual("%PDF-"u8))return new(UploadedPdfVerificationStatus.RejectedInput);
            var sha=hash.GetHashAndReset();digest=Convert.ToHexStringLower(sha);
            Active();
            await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(active),active);
            var match=Unique(await Find(sha,false,active));if(match is null)return new(UploadedPdfVerificationStatus.NotRecognized,digest);
            var prepared=await state.PrepareAsync(match.Id,active);if(prepared is null)return new(UploadedPdfVerificationStatus.NotRecognized,digest);
            Active();
            var stored=match.Executed ? prepared.Saved.Executed : prepared.Saved.Certificate;
            var bytes=match.Executed ? prepared.Verified.ExecutedBytes : prepared.Verified.CertificateBytes;
            if(stored.Length!=length || bytes.LongLength!=length || !Same(stored.Sha256,sha) || !Same(SHA256.HashData(bytes),sha))
                return new(UploadedPdfVerificationStatus.EvidenceMismatch,digest);
            await using(var tx=await db.Database.BeginTransactionAsync(active)) {
                await state.RecheckLockedAsync(prepared.Saved,active);
                if(prepared.Until<=time.GetUtcNow())return new(UploadedPdfVerificationStatus.Unavailable,digest);
                // Hold the matching index ranges through the final read so a concurrent
                // duplicate cannot turn an ambiguous lookup into a known-packet result.
                if(Unique(await Find(sha,true,active))!=match)return new(UploadedPdfVerificationStatus.NotRecognized,digest);
                Active();await tx.CommitAsync(active);
            }
            Active();
            if(prepared.Saved.PurgeAfter<=time.GetUtcNow())return new(UploadedPdfVerificationStatus.NotRecognized,digest);
            if(prepared.Until<=time.GetUtcNow())return new(UploadedPdfVerificationStatus.Unavailable,digest);
            return new(UploadedPdfVerificationStatus.Verified,digest,match.Executed ? FinalDocumentKind.Executed : FinalDocumentKind.Certificate);
        }
        catch(OperationCanceledException) when(!ct.IsCancellationRequested) {return new(UploadedPdfVerificationStatus.Unavailable,digest);}
        catch(Exception e) when(e is InvalidDataException or SealUnavailableException or DocumentConflictException or CryptographicException)
        {return new(UploadedPdfVerificationStatus.EvidenceMismatch,digest);}
        catch(Exception e) when(e is IOException or Azure.RequestFailedException or Microsoft.Data.SqlClient.SqlException or HttpRequestException)
        {ct.ThrowIfCancellationRequested();return new(UploadedPdfVerificationStatus.Unavailable,digest);}
        void Active() {active.ThrowIfCancellationRequested();if(until<=time.GetUtcNow())throw new OperationCanceledException(active);}
    }
    private Task<Match[]> Find(byte[] hash,bool locked,CancellationToken ct)
    {
        var now=time.GetUtcNow();
        var query=locked ? db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (HOLDLOCK) WHERE [Status]='Completed' AND ([PurgeAfter] IS NULL OR [PurgeAfter]>{now}) AND ([FinalSha256]={hash} OR [CertificateSha256]={hash})") :
            db.Envelopes.Where(x=>x.Status==EnvelopeStatus.Completed && (x.PurgeAfter==null || x.PurgeAfter>now) && (x.FinalSha256==hash || x.CertificateSha256==hash));
        return query.AsNoTracking().Select(x=>new Match(x.Id,x.FinalSha256==hash,x.CertificateSha256==hash)).Take(3).ToArrayAsync(ct);
    }
    private static Match? Unique(Match[] rows)=>rows.Length==1 && rows[0].Executed!=rows[0].Certificate ? rows[0] : null;
    private static bool Same(byte[] a,byte[] b)=>CryptographicOperations.FixedTimeEquals(a,b);
}

public static class UploadedPdfVerificationConfiguration
{
    public static IServiceCollection AddUploadedPdfVerification(this IServiceCollection services,IConfiguration config)
    {
        var options=config.GetSection("PdfVerification").Get<UploadedPdfVerificationOptions>()??new();options.Validate();services.TryAddSingleton(options);
        services.TryAddScoped<UploadedPdfVerification>(sp=>ActivatorUtilities.CreateInstance<UploadedPdfVerification>(sp));
        return services;
    }
}
