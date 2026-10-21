using System.Text.Json;
using System.Text.Json.Serialization;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Storage;

namespace QuillSign.Lifecycle;

// Recorded token and audit facts only. Browser cookie material was never recorded
// and is neither reconstructed nor made a new preservation requirement.
internal static class ProductionHoldCompletionAccessReferences
{
    private static readonly JsonSerializerOptions Rows=new(){UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow,Converters={new JsonStringEnumConverter()}};
    internal sealed record History(IReadOnlySet<Guid> Tokens,IReadOnlySet<long> Audits);
    internal static History ReadVerified(JsonElement sql,HoldWitnessState state)
    {
        try{return Read(sql,state);}
        catch(Exception e)when(e is JsonException or KeyNotFoundException or InvalidOperationException or ArgumentException or FormatException or NullReferenceException or OverflowException){throw new InvalidDataException("Completed access history could not be verified.",e);}
    }
    private static History Read(JsonElement sql,HoldWitnessState state)
    {
        var tables=sql.GetProperty("Tables").EnumerateArray().ToDictionary(x=>x.GetProperty("Table").GetString()!,x=>x.GetProperty("Rows"));
        T[] Table<T>(string name)=>tables[name].Deserialize<T[]>(Rows)??throw Invalid();
        var envelope=Table<Envelope>("Envelopes").Single();var result=Table<CompletionPublicationResult>("CompletionPublicationResults").Single();
        var signers=Table<Signer>("Signers");var recipients=Table<Recipient>("Recipients");var audits=Table<AuditEvent>("AuditEvents");
        var tokens=Table<AuthToken>("AuthTokens").Where(x=>x.Purpose==TokenPurpose.CompletionAccess).ToArray();
        if(tokens.Length>4096||audits.Length>4096)throw Invalid();
        var captured=sql.GetProperty("CapturedAt").GetDateTimeOffset();var proof=new HashSet<long>();var ids=new HashSet<Guid>();
        foreach(var token in tokens)
        {
            if(!ids.Add(token.Id)||token.EnvelopeId!=envelope.Id||token.CompletionPublicationId!=result.Id||token.RowVersion is not{Length:8}||
                token.TokenSha256 is not{Length:32}||!Same(token.CompletionRecipeSha256,result.RecipeSha256)||token.ExpiresAt.Offset!=TimeSpan.Zero||
                token.DocumentId is not null||token.DocumentSha256 is not null||token.DisclosureSha256 is not null||token.SignerContactRevisionId is not null||token.EmailPilotLookupRequestId is not null||token.Ip is not null)throw Invalid();
            CompletionAccessParty member;
            if(token.PartyType==PartyType.Sender&&token.PartyId is null)member=CompletionAccessState.PartyProjection(envelope.Id,result.Id,result.RowVersion,PartyType.Sender,null,envelope.SenderEmail,envelope.SenderName,null);
            else if(token.PartyType==PartyType.Signer&&signers.SingleOrDefault(x=>x.Id==token.PartyId) is{} signer)member=CompletionAccessState.PartyProjection(envelope.Id,result.Id,result.RowVersion,PartyType.Signer,signer.Id,signer.Email,signer.FullName,signer.Order);
            else if(token.PartyType==PartyType.Recipient&&recipients.SingleOrDefault(x=>x.Id==token.PartyId) is{} recipient)member=CompletionAccessState.PartyProjection(envelope.Id,result.Id,result.RowVersion,PartyType.Recipient,recipient.Id,recipient.Email,recipient.Name,null);
            else throw Invalid();
            if(token.Email!=member.Email||!Same(token.CompletionPartySha256,member.Sha256))throw Invalid();
            var issued=audits.Single(x=>x.Event=="completion_access_issued"&&x.DataJson==CompletionAccess.Issued(token));
            Demand(issued,PartyType.System,null,null);
            if(issued.At<result.CompletedAt||issued.At>=token.ExpiresAt||token.ExpiresAt>issued.At.AddHours(168)||envelope.PurgeAfter is{} purge&&token.ExpiresAt>purge)throw Invalid();
            var mailOwned=audits.Any(x=>x.Event=="completion_notification_attempt"&&TokenId(x)==token.Id&&
                state.CompletionMailBaselines?.Values.Any(b=>{using var data=JsonDocument.Parse(x.DataJson);return b.WorkId==data.RootElement.GetProperty("notificationId").GetGuid()&&b.PublicationId==result.Id;})==true);
            // A standalone issuance must have its own exact settled operation.
            if(!HasOperation("completion/issue",token.Id)&&!HasOperation("completion/lookup-open",token.Id)&&!mailOwned)throw Invalid();
            if(token.UsedAt is{} used)
            {
                var consumed=audits.Single(x=>x.Event=="completion_access_redeemed"&&TokenId(x)==token.Id);
                var identity=ReadConsumption(consumed.DataJson,token,envelope.PublicId);
                Demand(consumed,token.PartyType,token.PartyId,token.Email);
                if(consumed.DataJson!=CompletionAccess.Consumed(identity)||identity.RedeemedAt!=used||used<issued.At||used>=token.ExpiresAt||
                    consumed.At<used||identity.ExpiresAt<=used||identity.ExpiresAt>used.AddHours(24)||envelope.PurgeAfter is{} end&&identity.ExpiresAt>end||
                    !HasOperation("completion/redeem",token.Id)&&!HasOperation("completion/lookup-open",token.Id))throw Invalid();
                var lookup=audits.Where(x=>x.Event=="completion_lookup_opened"&&ReaderToken(x)==token.Id).ToArray();
                if(HasOperation("completion/lookup-open",token.Id))
                {
                    if(lookup.Length!=1)throw Invalid();var opened=lookup[0];using var data=JsonDocument.Parse(opened.DataJson);
                    var d=data.RootElement;if(JsonSerializer.Serialize(d)!=opened.DataJson)throw Invalid();
                    Closed(d,["version","authentication","lookupTokenId","lookupTokenRevision","lookupSessionId","lookupExpiresAt","readerTokenId","readerSessionId","readerExpiresAt","publicationId","party","partyId","authority","observation"]);
                    if(d.GetProperty("version").GetString()!="lookup-packet-access-v1"||d.GetProperty("authentication").GetString()!="single_use_verified_mailbox_lookup"||
                        d.GetProperty("authority").GetString()!="readonly_published_final_pair"||d.GetProperty("observation").GetString()!="session_prepared_not_document_receipt"||
                        d.GetProperty("lookupTokenId").GetGuid()==Guid.Empty||Convert.FromBase64String(d.GetProperty("lookupTokenRevision").GetString()!).Length!=8||
                        d.GetProperty("lookupSessionId").GetGuid()==Guid.Empty||d.GetProperty("lookupExpiresAt").GetDateTimeOffset()<identity.ExpiresAt||
                        d.GetProperty("readerSessionId").GetGuid()!=identity.SessionId||d.GetProperty("readerExpiresAt").GetDateTimeOffset()!=identity.ExpiresAt||
                        d.GetProperty("publicationId").GetGuid()!=result.Id||d.GetProperty("party").GetString()!=token.PartyType.ToString()||
                        d.GetProperty("partyId").Deserialize<Guid?>()!=token.PartyId||opened.Sequence!=consumed.Sequence+1||opened.At<consumed.At)throw Invalid();
                    Demand(opened,token.PartyType,token.PartyId,token.Email);
                }
                else if(lookup.Length!=0)throw Invalid();
            }
            else if(audits.Any(x=>x.Event=="completion_access_redeemed"&&TokenId(x)==token.Id))throw Invalid();
        }
        foreach(var download in audits.Where(x=>x.Event=="final_download_prepared"))
        {
            using var data=JsonDocument.Parse(download.DataJson);var d=data.RootElement;if(JsonSerializer.Serialize(d)!=download.DataJson)throw Invalid();
            Closed(d,["version","publicationId","kind","fileSha256","nonce","referenceSha256","expiresAt","meaning"]);
            var nonce=d.GetProperty("nonce").GetGuid();var kind=d.GetProperty("kind").GetString();
            if(!HasOperation("completion/download",nonce)||d.GetProperty("version").GetString()!=CompletionDownloads.Version||d.GetProperty("publicationId").GetGuid()!=result.Id||
                kind is not("executed" or "certificate")||d.GetProperty("meaning").GetString()!="Verified download prepared; receipt or saving is not confirmed."||
                d.GetProperty("expiresAt").GetDateTimeOffset()<=download.At||d.GetProperty("expiresAt").GetDateTimeOffset()>download.At.AddMinutes(2))throw Invalid();
            using var documents=JsonDocument.Parse(result.FinalDocumentsJson);var file=documents.RootElement.GetProperty(kind=="executed"?"Executed":"Certificate").Deserialize<FinalStoredDocument>()??throw Invalid();
            if(d.GetProperty("fileSha256").GetString()!=Hex(file.Sha256)||d.GetProperty("referenceSha256").GetString()!=Hex(DownloadPublication.Reference(file)))throw Invalid();
            var valid=download.ActorType==PartyType.Sender&&download.ActorId is null&&download.ActorEmail==envelope.SenderEmail||download.ActorType==PartyType.Signer&&signers.Any(x=>x.Id==download.ActorId&&x.Email==download.ActorEmail)||download.ActorType==PartyType.Recipient&&recipients.Any(x=>x.Id==download.ActorId&&x.Email==download.ActorEmail);
            if(!valid)throw Invalid();Demand(download,download.ActorType,download.ActorId,download.ActorEmail);
        }
        if(!proof.SetEquals(audits.Where(x=>x.Event is "completion_access_issued" or "completion_access_redeemed" or "completion_lookup_opened" or "final_download_prepared").Select(x=>x.Sequence)))throw Invalid();
        return new(ids,proof);
        bool HasOperation(string kind,Guid reference)=>state.Operations?.Values.Any(x=>x.Kind==kind&&x.Reference==reference.ToString("N")&&state.Outcomes?.ContainsKey(x.OperationId)==true&&state.SettledOperations.GetValueOrDefault(x.OperationId)==ProductionCompletionReadAdmission.Receipt(envelope.Id,x.OperationId,x.Kind,x.Reference))==true;
        void Demand(AuditEvent a,PartyType party,Guid? partyId,string? email){if(a.EnvelopeId!=envelope.Id||a.ActorType!=party||a.ActorId!=partyId||a.ActorEmail!=email||a.Ip is not null||a.UserAgent is not null||a.At>captured||a.At.Offset!=TimeSpan.Zero||!Same(a.Hash,AuditHash.Compute(a))||!proof.Add(a.Sequence))throw Invalid();}
    }
    internal static CompletionReaderIdentity ReadConsumption(string json,AuthToken token,string publicId)
    {
        using var data=JsonDocument.Parse(json,new(){MaxDepth=8});var d=data.RootElement;
        Closed(d,["version","tokenId","EnvelopeId","publicationId","TokenRevision","party","PartyId","Email","RecipeSha256","PartySha256","SessionId","RedeemedAt","ExpiresAt","authentication","authority"]);
        if(d.GetProperty("version").GetString()!=CompletionAccessProtection.Version||d.GetProperty("tokenId").GetGuid()!=token.Id||d.GetProperty("EnvelopeId").GetGuid()!=token.EnvelopeId||
            d.GetProperty("publicationId").GetGuid()!=token.CompletionPublicationId||d.GetProperty("TokenRevision").GetString()!=Convert.ToBase64String(token.RowVersion)||
            d.GetProperty("party").GetString()!=token.PartyType.ToString()||d.GetProperty("PartyId").Deserialize<Guid?>()!=token.PartyId||d.GetProperty("Email").GetString()!=token.Email||
            d.GetProperty("RecipeSha256").GetString()!=Hex(token.CompletionRecipeSha256!)||d.GetProperty("PartySha256").GetString()!=Hex(token.CompletionPartySha256!)||
            d.GetProperty("SessionId").GetGuid()==Guid.Empty||d.GetProperty("authentication").GetString()!="single_use_party_scoped_link"||d.GetProperty("authority").GetString()!="readonly_published_final_pair")throw Invalid();
        if(token.UsedAt!=d.GetProperty("RedeemedAt").GetDateTimeOffset()||d.GetProperty("RedeemedAt").GetDateTimeOffset().Offset!=TimeSpan.Zero||d.GetProperty("ExpiresAt").GetDateTimeOffset().Offset!=TimeSpan.Zero)throw Invalid();
        return new(token.Id,Convert.ToBase64String(token.RowVersion),token.EnvelopeId!.Value,publicId,token.PartyType,token.PartyId,token.Email,token.CompletionPublicationId!.Value,
            Hex(token.CompletionRecipeSha256!),Hex(token.CompletionPartySha256!),d.GetProperty("SessionId").GetGuid(),d.GetProperty("RedeemedAt").GetDateTimeOffset(),d.GetProperty("ExpiresAt").GetDateTimeOffset());
    }
    private static void Closed(JsonElement value,string[] fields){if(!value.EnumerateObject().Select(x=>x.Name).SequenceEqual(fields))throw Invalid();}
    private static Guid TokenId(AuditEvent a){using var d=JsonDocument.Parse(a.DataJson);return d.RootElement.GetProperty("tokenId").GetGuid();}
    private static Guid ReaderToken(AuditEvent a){using var d=JsonDocument.Parse(a.DataJson);return d.RootElement.GetProperty("readerTokenId").GetGuid();}
    private static bool Same(byte[]? a,byte[]? b)=>a is not null&&b is not null&&a.AsSpan().SequenceEqual(b);
    private static string Hex(byte[] value)=>Convert.ToHexStringLower(value);
    private static InvalidDataException Invalid()=>new("Completed access history could not be verified.");
}
