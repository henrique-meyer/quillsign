using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Signing;
using QuillSign.Work;
using Shared = QuillSign.Tests.CompletionEvidenceCollectorTests.Run;

namespace QuillSign.Tests;

public sealed class SignerContactFlowTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Fresh_corrected_signer_completes_real_sequential_pipeline_without_inheriting_old_consent_or_authority(bool addressCycle)
    {
        VerifiedSigner? oldIdentity = null; string oldReview = ""; Guid oldAdoption = default;
        await using var run = await Shared.Create(fixture, signerOverride: async (r, order) =>
        {
            if (order != 1) return false;
            oldIdentity = await r.SignNext(false, false); oldReview = r.LastReviewReceipt;
            await using (var db = fixture.Open()) oldAdoption = (await db.Signers.SingleAsync(x => x.Id == oldIdentity.SignerId)).SignatureAdoptionId!.Value;
            var originalUnused = await Token(r, oldIdentity.SignerId, null);
            var first = await CorrectFixture(r, oldIdentity.SignerId, "corrected-" + oldIdentity.Email);
            var retiredPrincipal = SignerAccessConfiguration.Principal(oldIdentity);
            Assert.Null(await r.Use((SignerAccess s) => s.GetContextAsync(retiredPrincipal, r.Envelope.PublicId)));
            Assert.Null(await r.Use((SignerReviewCandidates s) => s.ReadAsync(retiredPrincipal, r.Envelope.PublicId, oldReview)));
            var final = addressCycle ? await CorrectFixture(r, oldIdentity.SignerId, oldIdentity.Email) : first;
            Assert.Null(await r.Use((SignerAccess s) => s.RedeemAsync(originalUnused, "127.0.0.1", "Synthetic delayed retired token")));
            Assert.Equal(SignerFinishOutcome.InvalidContext, (await r.Use((SignerFinish s) => s.AcceptAsync(retiredPrincipal,
                r.Envelope.PublicId, oldReview, true, SignerFinishStatement.Version, "127.0.0.1", "Synthetic retired Finish"))).Outcome);
            var fresh = await Token(r, oldIdentity.SignerId, final.Id);
            var identity = await r.SignNext(true, true, fresh);
            Assert.NotEqual(oldIdentity.SessionId, identity.SessionId);
            Assert.Equal(final.NewEmail, identity.Email);
            Assert.Null(await r.Use((SignerAccess s) => s.GetContextAsync(retiredPrincipal, r.Envelope.PublicId)));
            return true;
        });
        var material = await run.Collect(); Assert.NotNull(material);
        var evidence = material.Evidence; var corrections = evidence.Events.Where(x => x.ContactCorrection is not null).ToArray();
        Assert.Equal(addressCycle ? 2 : 1, corrections.Length);
        Assert.Equal(addressCycle ? oldIdentity!.Email : "corrected-" + oldIdentity!.Email, evidence.Signers[0].Email);
        Assert.All(corrections, x => Assert.Equal(SignerContactHistory.Event, x.Event));
        Assert.True(evidence.Signers[0].ConsentedAt >= corrections[^1].At);
        await using (var db = fixture.Open())
        {
            Assert.NotNull((await db.SignaturePreviews.SingleAsync(x => x.Id == oldAdoption)).UsedAt);
            Assert.Equal(addressCycle ? 2 : 1, await db.SignerContactRevisions.CountAsync(x => x.EnvelopeId == run.Envelope.Id));
            Assert.Equal(1, await db.SignerContactSessions.CountAsync(x => x.EnvelopeId == run.Envelope.Id));
            Assert.Equal(2, await db.SignerFinishAcceptances.CountAsync(x => x.EnvelopeId == run.Envelope.Id));
        }
        var packet = new CompletionCertificateRenderer().PreparePacket(material.Source, material.Pages, evidence);
        using var pdf = UglyToad.PdfPig.PdfDocument.Open(packet.AppendixBytes);
        var text = System.Text.RegularExpressions.Regex.Replace(string.Join(" ", pdf.GetPages().Select(x => x.Text)), @"\s+", "");
        Assert.Contains("Retiredaddress", text); Assert.Contains("Correctedaddress", text);
        Assert.Contains("notsignaturesbythecorrectedmailbox", text);
        Assert.Contains("finaleffectivesigner", text);
        if (addressCycle && Environment.GetEnvironmentVariable("QUILLSIGN_CONTACT_CERTIFICATE_QA") is { Length: > 0 } path)
            await File.WriteAllBytesAsync(path, packet.AppendixBytes);
    }

    [Fact]
    public void Legacy_completion_event_serialization_is_byte_compatible_when_no_correction_exists()
    {
        var item = new CompletionEvent(1, DateTimeOffset.UnixEpoch, "sent", "Sender", "Synthetic sender", null, null, new byte[32], RandomNumberGenerator.GetBytes(32));
        var legacy = JsonSerializer.SerializeToUtf8Bytes(new { item.Sequence, item.At, item.Event, item.ActorType, item.Actor, item.Ip, item.UserAgent, item.PreviousHash, item.Hash });
        Assert.Equal(legacy, JsonSerializer.SerializeToUtf8Bytes(item));
        Assert.Null(JsonSerializer.Deserialize<CompletionEvent>(legacy)!.ContactCorrection);
    }

    [Fact]
    public async Task Corrected_completed_copy_remains_verifiable_with_large_operational_tail_and_only_effective_mailbox_membership()
    {
        string original="",corrected=""; Guid signerId=default;
        await using var run=await CompletionSealOutputTests.Run.Create(fixture,signerOverride:async(r,order)=>
        {
            if(order!=1)return false;
            var old=await r.SignNext(false,false); original=old.Email; corrected="corrected-"+old.Email; signerId=old.SignerId;
            var revision=await CorrectFixture(r,signerId,corrected); await r.SignNext(true,true,await Token(r,signerId,revision.Id)); return true;
        });
        Assert.NotNull(await run.Prepare());
        await using var db=fixture.Open(); var clock=run.Signing.H.Clock; var collector=run.Collector(db);
        var final=new CompletionDownloadTests.FinalStore(clock); CompletionPublication? publication=null;
        var state=new CompletionAccessState(db,collector,()=>publication!,clock); var protection=new EphemeralDataProtectionProvider();
        var signals=new SignerReviewCandidateTests.CheckpointSignals();
        var notifications=new CompletionNotificationJobs(db,state,new(protection),()=>signals,new(){Enabled=true},new(db,clock),clock);
        publication=new(db,run.Candidates(db),run.Service(db),collector,final,new(db,clock),clock,
            new(){AllowDevelopmentWriteOnce=true,DemoPurgeAfterDays=7},run.Seal.App.Environment,notifications:()=>notifications);
        var saved=await publication.PublishAsync(run.Signing.Envelope.Id); Assert.NotNull(saved);
        var addresses=await db.EmailOutbox.Where(x=>x.EnvelopeId==saved.EnvelopeId && x.Template==CompletionNotificationJobs.Template).Select(x=>x.To).ToArrayAsync();
        Assert.Equal(4,addresses.Length); Assert.Contains(corrected,addresses); Assert.DoesNotContain(original,addresses);
        await using(var tx=await db.Database.BeginTransactionAsync())
        {
            var previous=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==saved.EnvelopeId).OrderByDescending(x=>x.Sequence).FirstAsync();
            for(var i=0;i<530;i++)
            {
                var entry=new AuditEvent{EnvelopeId=saved.EnvelopeId,Sequence=previous.Sequence+1,PrevHash=previous.Hash,At=clock.GetUtcNow(),ActorType=PartyType.System,Event="synthetic_operational_tail"};
                entry.Hash=AuditHash.Compute(entry);db.Add(entry);previous=entry;
            }
            await db.SaveChangesAsync();await tx.CommitAsync();
        }
        Assert.Equal(saved.ExecutedBytes,(await publication.ReadAsync(saved.EnvelopeId))!.ExecutedBytes);
        var access=new CompletionAccess(db,state,new(protection,clock),new(),new(db,clock),clock,()=>publication);
        var link=await access.IssueAsync(saved.EnvelopeId,PartyType.Signer,signerId); Assert.NotNull(link);
        Assert.Equal(corrected,(await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==link.TokenId)).Email);
        Assert.Equal(2,run.Seal.Requests); // Synthetic in-process TSA only.
    }

    private async Task<string> Token(Shared r, Guid signerId, Guid? revisionId)
    {
        await r.Refresh(); await using var db = fixture.Open(); var signer = await db.Signers.SingleAsync(x => x.Id == signerId);
        var invite = new SignerInvitationFactory(new(), r.H.Clock).Create(r.Envelope.Id, signer.Id, signer.Email, r.Envelope.ExpiresAt,
            Guid.ParseExact(r.Envelope.SentPdfBlob!, "N"), r.Envelope.SentPdfSha256!, r.Envelope.ErsdSha256!);
        invite.Record.SignerContactRevisionId = revisionId;
        db.AuthTokens.Add(invite.Record); await db.SaveChangesAsync(); return invite.RawToken;
    }

    // Explicit synthetic server fixture only, not a correction service or email delivery
    // claim. The later admission story owns sender review/caps/work transaction gates.
    private async Task<SignerContactRevision> CorrectFixture(Shared r, Guid signerId, string email)
    {
        r.H.Clock.Advance(TimeSpan.FromSeconds(1)); await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        var envelope = await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={r.Envelope.Id}").AsNoTracking().SingleAsync();
        var signer = await db.Signers.SingleAsync(x => x.Id == signerId); Assert.False(await db.SignerFinishAcceptances.AnyAsync(x => x.SignerId == signerId));
        var fields = await db.Fields.Where(x => x.EnvelopeId == envelope.Id && x.SignerId == signerId).ToArrayAsync();
        var retired = SignerContactState.RetirementJson(signer, fields);
        var prior = await db.SignerContactRevisions.Where(x => x.SignerId == signerId).OrderByDescending(x => x.Number).FirstOrDefaultAsync();
        var previous = prior is null ? null : JsonSerializer.Deserialize<SignerContactRevision>(prior.EvidenceJson, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        var revision = new SignerContactRevision(SignerContactHistory.Version, Guid.NewGuid(), envelope.Id, signerId, previous?.Id ?? Guid.Empty,
            (previous?.Number ?? 0) + 1, signer.Email, email, r.H.Clock.GetUtcNow(), r.H.Clock.GetUtcNow().AddMinutes(20),
            Convert.ToBase64String(envelope.RowVersion), Convert.ToBase64String(signer.RowVersion), Guid.ParseExact(envelope.SentPdfBlob!, "N"),
            Convert.ToHexStringLower(envelope.SentPdfSha256!), Convert.ToHexStringLower(envelope.ErsdSha256!), SignerContactState.RetirementDigest(retired),
            previous is null ? null : SignerContactHistory.Digest(previous), SignerContactHistory.StatementVersion, SignerContactHistory.StatementSha256);
        db.SignerContactRevisions.Add(new() { Id = revision.Id, EnvelopeId = envelope.Id, SignerId = signer.Id, Number = revision.Number,
            PreviousRevisionId = previous?.Id, ChangedAt = revision.ChangedAt, EvidenceJson = SignerContactHistory.Canonical(revision), RetirementJson = retired });
        signer.Email = email; signer.Status = SignerStatus.Pending; signer.ConsentAt = null; signer.ConsentIp = null; signer.ConsentUa = null;
        signer.SignatureImageBlob = null; signer.InitialsImageBlob = null; signer.SignatureMethod = null; signer.SignatureAdoptionId = null;
        signer.SignatureImageSha256 = null; signer.InitialsImageSha256 = null; signer.SignatureAdoptedAt = null; signer.SignatureTypedName = null;
        signer.SignatureTypedInitials = null; signer.SignatureNormalizationVersion = null; signer.SignatureAdoptionVersion = null;
        foreach (var field in fields) { field.Value = null; field.FilledAt = null; field.FilledBy = null; field.SignatureAdoptionId = null; field.ImageSha256 = null; }
        await db.SignerReviewCandidates.Where(x => x.EnvelopeId == envelope.Id && x.SignerId == signerId && x.UsedAt == null && x.SupersededAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.SupersededAt, revision.ChangedAt));
        await db.SaveChangesAsync(); await new AuditWriter(db, r.H.Clock).AppendAsync(envelope.Id, SignerContactHistory.Event,
            envelope.SenderEmail, "127.0.0.1", "Synthetic correction fixture", default, SignerContactHistory.Canonical(revision));
        await tx.CommitAsync(); return revision;
    }
}
