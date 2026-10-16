using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using QuillSign.Documents;
using QuillSign.Signing;

namespace QuillSign.Completion;

internal static class CompletionEvidenceValidation
{
    internal static DocumentRejectedException Rejected()=>new("The completion evidence, source or output could not be verified within its limits.");
    internal static bool Same(byte[]? a,byte[]? b)=>a is {Length:32} && b is {Length:32} && CryptographicOperations.FixedTimeEquals(a,b);
    internal static byte[] Digest(CompletionEvidence evidence)=>SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(evidence));
    internal static CompletionEvidence Own(CompletionEvidence input,CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if(input is null || input.EnvelopeId==Guid.Empty || input.PreparedAt==default || input.Document is null || input.Sender is null ||
            input.Signers is null || input.Signers.Count is <1 or >20 || input.Recipients is null || input.Recipients.Count>50 ||
            input.Events is null || input.Events.Count is <1 or >512)throw Rejected();
        var remaining=128*1024;
        string Text(string? text,int maximum,bool optional=false)
        {
            if(text is null) {if(optional)return ""; throw Rejected();}
            if(text.Length>maximum || !optional && string.IsNullOrWhiteSpace(text))throw Rejected();
            try {if((remaining-=new UTF8Encoding(false,true).GetByteCount(text))<0)throw Rejected(); return text.Replace("\r\n","\n").Replace('\r','\n').Normalize(NormalizationForm.FormC);}
            catch(ArgumentException) {throw Rejected();}
        }
        string Email(string value) {var email=Text(value,320); if(!MailAddress.TryCreate(email,out var parsed) || parsed.Address!=email)throw Rejected(); return email;}
        byte[] Hash(byte[]? hash,bool genesis=false) {if(hash is not {Length:32} || !genesis && hash.All(x=>x==0))throw Rejected(); return hash.ToArray();}
        DateTimeOffset At(DateTimeOffset at) {if(at==default || at>input.PreparedAt)throw Rejected(); return at.ToUniversalTime();}
        CompletionMark? Mark(CompletionMark? mark)
        {
            if(mark is null)return null; ct.ThrowIfCancellationRequested();
            if(mark.Png is null || mark.Png.Length>SignaturePng.MaximumBytes || mark.NormalizationVersion!=SignaturePng.Version)throw Rejected();
            var png=mark.Png.ToArray(); var hash=Hash(mark.Sha256);
            try {if(!Same(SHA256.HashData(png),hash) || !SignaturePng.Normalize(png).Bytes.AsSpan().SequenceEqual(png))throw Rejected();}
            catch(SignatureImageRejectedException) {throw Rejected();}
            return new(png,hash,SignaturePng.Version);
        }
        var doc=input.Document; if(doc.Id==Guid.Empty || doc.Pages is <1 or >200)throw Rejected();
        doc=doc with {Name=Text(doc.Name,512),OriginalSha256=Hash(doc.OriginalSha256),ConvertedSha256=Hash(doc.ConvertedSha256),SentSha256=Hash(doc.SentSha256),CurrentSha256=Hash(doc.CurrentSha256)};
        var sender=input.Sender with {Name=Text(input.Sender.Name,512,true),Email=Email(input.Sender.Email),VerifiedAt=At(input.Sender.VerifiedAt)};
        var disclosureVersion=Text(input.DisclosureVersion,100); var disclosureHash=Hash(input.DisclosureSha256);
        var signers=new List<CompletionSigner>(); var ids=new HashSet<Guid>(); var previous=sender.VerifiedAt;
        foreach(var signer in input.Signers)
        {
            ct.ThrowIfCancellationRequested();
            if(signer is null || signer.Id==Guid.Empty || !ids.Add(signer.Id) || signer.Order!=signers.Count+1 ||
                signer.EmailVerifiedAt<previous || signer.ViewedAt<signer.EmailVerifiedAt || signer.ConsentedAt<signer.ViewedAt ||
                signer.FinishedAt<signer.ConsentedAt || signer.CheckpointAt<signer.FinishedAt || signer.DisclosureVersion!=disclosureVersion ||
                !Same(signer.DisclosureSha256,disclosureHash) || signer.AdoptionId==Guid.Empty ||
                (signer.Signature is not null || signer.Initials is not null) && signer.AdoptionId is null)throw Rejected();
            signers.Add(signer with {Name=Text(signer.Name,512),Email=Email(signer.Email),Role=Text(signer.Role,512,true),
                EmailVerifiedAt=At(signer.EmailVerifiedAt),ViewedAt=At(signer.ViewedAt),ConsentedAt=At(signer.ConsentedAt),FinishedAt=At(signer.FinishedAt),CheckpointAt=At(signer.CheckpointAt),
                DisclosureVersion=disclosureVersion,DisclosureSha256=Hash(signer.DisclosureSha256),CheckpointSha256=Hash(signer.CheckpointSha256),
                Ip=Text(signer.Ip,64,true),UserAgent=Text(signer.UserAgent,2048,true),Signature=Mark(signer.Signature),Initials=Mark(signer.Initials)});
            previous=signer.CheckpointAt;
        }
        if(!Same(signers[^1].CheckpointSha256,doc.CurrentSha256))throw Rejected();
        var recipients=input.Recipients.Select(r=>r is not null ? r with {Name=Text(r.Name,512,true),Email=Email(r.Email)} : throw Rejected()).ToArray();
        var events=new List<CompletionEvent>(); var previousHash=new byte[32];
        foreach(var entry in input.Events)
        {
            ct.ThrowIfCancellationRequested();
            if(entry is null || entry.Sequence!=events.Count+1 || !Same(entry.PreviousHash,previousHash) ||
                entry.ActorType is not ("Sender" or "Signer" or "Recipient" or "System"))throw Rejected();
            var hash=Hash(entry.Hash); events.Add(entry with {At=At(entry.At),Event=Text(entry.Event,100),Actor=Text(entry.Actor,512,true),
                Ip=Text(entry.Ip,64,true),UserAgent=Text(entry.UserAgent,2048,true),PreviousHash=Hash(entry.PreviousHash,true),Hash=hash}); previousHash=hash;
        }
        var anchor=Hash(input.AuditAnchor); if(!Same(anchor,previousHash))throw Rejected();
        return input with {PreparedAt=input.PreparedAt.ToUniversalTime(),Document=doc,Sender=sender,DisclosureVersion=disclosureVersion,DisclosureSha256=disclosureHash,
            Signers=signers.ToArray(),Recipients=recipients,Events=events.ToArray(),AuditAnchor=anchor};
    }
}
