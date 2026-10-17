using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Storage;
using Shared=QuillSign.Tests.SendDraftWorkflowTests.Harness;

namespace QuillSign.Tests;

public sealed class CompletionEvidenceCollectorTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task On_time_Finish_survives_late_checkpoint_processing_without_inviting_after_the_deadline_then_expiry_preserves_it()
    {
        await using var run=await Run.Create(fixture,publishLast:false,firstOnly:true);run.H.Clock.Advance(TimeSpan.FromHours(2));
        Assert.Equal(SigningExpiryOutcome.AcceptedPending,(await run.Use((SigningExpiry s)=>s.ExpireAsync(run.Envelope.Id))).Outcome);
        await using var db=fixture.Open();var mails=await db.EmailOutbox.CountAsync(x=>x.EnvelopeId==run.Envelope.Id);Assert.True(await run.H.Once());
        var f=await db.SignerFinishAcceptances.AsNoTracking().SingleAsync(x=>x.EnvelopeId==run.Envelope.Id);await run.Refresh();
        Assert.True(f.ProcessedAt>run.Envelope.ExpiresAt);Assert.True(f.FinishedAt<run.Envelope.ExpiresAt);Assert.Null(f.NextInvitationId);Assert.Equal(1,run.Envelope.CurrentCopyVersion);
        Assert.Equal(mails,await db.EmailOutbox.CountAsync(x=>x.EnvelopeId==run.Envelope.Id));
        Assert.Equal(SigningExpiryOutcome.Expired,(await run.Use((SigningExpiry s)=>s.ExpireAsync(run.Envelope.Id))).Outcome);
        Assert.Equal(SigningExpiryOutcome.AlreadyExpired,(await run.Use((SigningExpiry s)=>s.ExpireAsync(run.Envelope.Id))).Outcome);
        Assert.Equal(f.PdfObjectId,(await db.SignerFinishAcceptances.AsNoTracking().SingleAsync(x=>x.Id==f.Id)).PdfObjectId);
    }
    [Fact]
    public async Task Final_on_time_acceptance_publishes_after_deadline_and_remains_collectable_for_completion_instead_of_expiry()
    {
        await using var run=await Run.Create(fixture,publishLast:false);run.H.Clock.Advance(TimeSpan.FromHours(2));
        Assert.Equal(SigningExpiryOutcome.AcceptedPending,(await run.Use((SigningExpiry s)=>s.ExpireAsync(run.Envelope.Id))).Outcome);
        Assert.True(await run.H.Once());Assert.Equal(SigningExpiryOutcome.AllSigned,(await run.Use((SigningExpiry s)=>s.ExpireAsync(run.Envelope.Id))).Outcome);
        var material=await run.Collect();Assert.NotNull(material);
        await using var db=fixture.Open();var finish=await db.SignerFinishAcceptances.AsNoTracking().Where(x=>x.EnvelopeId==run.Envelope.Id).OrderByDescending(x=>x.FinishedAt).FirstAsync();
        Assert.True(finish.ProcessedAt>run.Envelope.ExpiresAt);Assert.True(finish.FinishedAt<run.Envelope.ExpiresAt);Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==run.Envelope.Id && x.Event=="expired"));
    }
    [Fact]
    public async Task Genuine_verified_preparation_and_two_signer_chain_collect_exact_source_marks_parties_and_complete_audit_without_writes()
    {
        await using var run=await Run.Create(fixture); var before=await run.Counts();
        var snapshot=(await run.Collect())!; Assert.NotNull(snapshot); Assert.Equal(run.Envelope.Id,snapshot.EnvelopeId);
        Assert.Equal(run.Envelope.PublicId,snapshot.PublicId); Assert.Equal(2,snapshot.Evidence.Signers.Count); Assert.Single(snapshot.Evidence.Recipients);
        Assert.Equal(snapshot.Evidence.Document.CurrentSha256,SHA256.HashData(snapshot.Source));
        await using var db=fixture.Open(); var finishes=await db.SignerFinishAcceptances.Where(x=>x.EnvelopeId==run.Envelope.Id).ToArrayAsync();
        var events=await db.AuditEvents.Where(x=>x.EnvelopeId==run.Envelope.Id).OrderBy(x=>x.Sequence).ToArrayAsync();
        Assert.Equal(events.Select(x=>x.Event),snapshot.Evidence.Events.Select(x=>x.Event)); Assert.Equal(events[^1].Hash,snapshot.Evidence.AuditAnchor);
        Assert.Equal(new byte[32],snapshot.Evidence.Events[0].PreviousHash);
        foreach(var signer in snapshot.Evidence.Signers) {
            var finish=finishes.Single(x=>x.SignerId==signer.Id); Assert.Equal(finish.FinishedAt,signer.FinishedAt);
            Assert.True(signer.CheckpointAt>signer.FinishedAt); Assert.Equal(finish.Ip,signer.Ip); Assert.Equal(finish.UserAgent,signer.UserAgent);
            Assert.NotNull(signer.Signature); Assert.NotNull(signer.Initials); Assert.Equal(SHA256.HashData(signer.Signature.Png),signer.Signature.Sha256);
        }
        var packet=new CompletionCertificateRenderer().PreparePacket(snapshot.Source,snapshot.Pages,snapshot.Evidence with {Synthetic=true});
        Assert.Equal(snapshot.Evidence.Document.CurrentSha256,packet.SourceSha256); Assert.True(packet.CertificatePages>0);
        if(Environment.GetEnvironmentVariable("QUILLSIGN_COMPLETION_EVIDENCE_ARTIFACTS") is {Length:>0} path) {
            await using var seal=await SealFixtures.Create();
            if(seal.Time.GetUtcNow()<snapshot.Evidence.PreparedAt)seal.Time.Advance(snapshot.Evidence.PreparedAt-seal.Time.GetUtcNow()+TimeSpan.FromSeconds(1));
            var executed=await seal.Engine.SealAsync(packet.Bytes,packet.Sha256);
            var certificate=new CompletionCertificateRenderer().PrepareStandalone(snapshot.Evidence with {Synthetic=true},packet,executed);
            var sealedCertificate=await seal.Engine.SealAsync(certificate.Bytes,certificate.Sha256);
            Directory.CreateDirectory(path); await File.WriteAllBytesAsync(Path.Combine(path,"source.pdf"),snapshot.Source); await File.WriteAllBytesAsync(Path.Combine(path,"appendix.pdf"),packet.AppendixBytes);
            await File.WriteAllBytesAsync(Path.Combine(path,"executed.pdf"),executed.Bytes); await File.WriteAllBytesAsync(Path.Combine(path,"certificate.pdf"),sealedCertificate.Bytes);
        }
        Assert.Equal(before,await run.Counts()); Assert.All(run.Probe.Reads,x=>Assert.Equal(run.Envelope.Id,x.Blob.EnvelopeId));
        Assert.DoesNotContain(run.Probe.Reads,x=>x.Principal.Identities.Any(i=>i.AuthenticationType==EnvelopeStorageAuthorization.SenderScheme || i.AuthenticationType==SignerAccessConfiguration.Scheme));
        using var scope=run.H.App.Services.CreateScope(); Assert.NotNull(scope.ServiceProvider.GetRequiredService<CompletionEvidenceCollector>());
    }
    [Fact]
    public async Task Timely_published_signatures_remain_collectable_after_original_sessions_and_envelope_deadline_without_edit_authority()
    {
        await using var run=await Run.Create(fixture); run.H.Clock.Advance(TimeSpan.FromDays(31));
        var snapshot=(await run.Collect())!; Assert.Equal(2,snapshot.Evidence.Signers.Count);
        Assert.True(run.Envelope.ExpiresAt<snapshot.Evidence.PreparedAt);
        Assert.True(snapshot.Evidence.Signers.All(x=>x.FinishedAt<snapshot.Evidence.PreparedAt));
        using var scope=run.H.App.Services.CreateScope();
        Assert.Null(await scope.ServiceProvider.GetRequiredService<SignerFields>().GetAsync(run.LastSigner!,run.Envelope.PublicId));
        Assert.Equal(EnvelopeStatus.Sent,(await run.Refresh()).Status);
    }
    [Fact]
    public async Task Frozen_party_document_and_acceptance_mutations_are_rejected_instead_of_trusting_Signed_flags()
    {
        await using var run=await Run.Create(fixture); await using var db=fixture.Open();
        var e=await run.Refresh(); var s=await db.Signers.AsNoTracking().FirstAsync(x=>x.EnvelopeId==e.Id); var r=await db.Recipients.AsNoTracking().SingleAsync(x=>x.EnvelopeId==e.Id);
        var f=await db.SignerFinishAcceptances.AsNoTracking().SingleAsync(x=>x.SignerId==s.Id); var p=await db.SignaturePreviews.AsNoTracking().SingleAsync(x=>x.Id==f.AdoptionId);
        var previousFinish=await db.SignerFinishAcceptances.Where(x=>x.EnvelopeId==e.Id && x.Id!=e.CurrentFinishId).Select(x=>x.Id).SingleAsync();
        async Task Reject(Func<Task> change,Func<Task> restore) {
            await change(); await Assert.ThrowsAsync<InvalidDataException>(()=>run.Collect()); await restore(); Assert.NotNull(await run.Collect());
        }
        await Reject(()=>db.Signers.Where(x=>x.Id==s.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.Role,"changed")),()=>db.Signers.Where(x=>x.Id==s.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.Role,s.Role)));
        await Reject(()=>db.Signers.Where(x=>x.Id==s.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.FullName,"Changed signer")),()=>db.Signers.Where(x=>x.Id==s.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.FullName,s.FullName)));
        await Reject(()=>db.Signers.Where(x=>x.Id==s.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.Email,"changed@example.invalid")),()=>db.Signers.Where(x=>x.Id==s.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.Email,s.Email)));
        await Reject(()=>db.Signers.Where(x=>x.Id==s.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.Order,99)),()=>db.Signers.Where(x=>x.Id==s.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.Order,s.Order)));
        await Reject(()=>db.Recipients.Where(x=>x.Id==r.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.Name,"Changed recipient")),()=>db.Recipients.Where(x=>x.Id==r.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.Name,r.Name)));
        await Reject(()=>db.Recipients.Where(x=>x.Id==r.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.Email,"changed@example.invalid")),()=>db.Recipients.Where(x=>x.Id==r.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.Email,r.Email)));
        await Reject(()=>db.Envelopes.Where(x=>x.Id==e.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.SenderName,"Unbacked name")),()=>db.Envelopes.Where(x=>x.Id==e.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.SenderName,e.SenderName)));
        await Reject(()=>db.Envelopes.Where(x=>x.Id==e.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.OriginalSha256,new byte[32])),()=>db.Envelopes.Where(x=>x.Id==e.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.OriginalSha256,e.OriginalSha256)));
        await Reject(()=>db.Envelopes.Where(x=>x.Id==e.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.PdfSha256,new byte[32])),()=>db.Envelopes.Where(x=>x.Id==e.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.PdfSha256,e.PdfSha256)));
        await Reject(()=>db.Envelopes.Where(x=>x.Id==e.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.ErsdSha256,new byte[32])),()=>db.Envelopes.Where(x=>x.Id==e.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.ErsdSha256,e.ErsdSha256)));
        await Reject(()=>db.Envelopes.Where(x=>x.Id==e.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.PageCount,99)),()=>db.Envelopes.Where(x=>x.Id==e.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.PageCount,e.PageCount)));
        await Reject(()=>db.Envelopes.Where(x=>x.Id==e.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.PageSizesJson,"[]")),()=>db.Envelopes.Where(x=>x.Id==e.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.PageSizesJson,e.PageSizesJson)));
        await Reject(()=>db.Envelopes.Where(x=>x.Id==e.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.CurrentCopyVersion,1)),()=>db.Envelopes.Where(x=>x.Id==e.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.CurrentCopyVersion,e.CurrentCopyVersion)));
        await Reject(()=>db.Envelopes.Where(x=>x.Id==e.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.CurrentFinishId,previousFinish)),()=>db.Envelopes.Where(x=>x.Id==e.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.CurrentFinishId,e.CurrentFinishId)));
        await Reject(()=>db.Envelopes.Where(x=>x.Id==e.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.ExpiresAt,f.FinishedAt.AddSeconds(-1))),()=>db.Envelopes.Where(x=>x.Id==e.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.ExpiresAt,e.ExpiresAt)));
        await Reject(()=>db.SignerFinishAcceptances.Where(x=>x.Id==f.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.FieldsSha256,new byte[32])),()=>db.SignerFinishAcceptances.Where(x=>x.Id==f.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.FieldsSha256,f.FieldsSha256)));
        await Reject(()=>db.SignerFinishAcceptances.Where(x=>x.Id==f.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.SourceSha256,new byte[32])),()=>db.SignerFinishAcceptances.Where(x=>x.Id==f.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.SourceSha256,f.SourceSha256)));
        await Reject(()=>db.SignerFinishAcceptances.Where(x=>x.Id==f.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.RecipeSha256,new byte[32])),()=>db.SignerFinishAcceptances.Where(x=>x.Id==f.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.RecipeSha256,f.RecipeSha256)));
        await Reject(()=>db.SignaturePreviews.Where(x=>x.Id==p.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.SignatureSha256,new byte[32])),()=>db.SignaturePreviews.Where(x=>x.Id==p.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.SignatureSha256,p.SignatureSha256)));
        var forged=new Signer {EnvelopeId=e.Id,Order=3,Email="forged@example.invalid",FullName="Forged signed flag",Status=SignerStatus.Signed,SignedAt=run.H.Clock.GetUtcNow()}; db.Signers.Add(forged); await db.SaveChangesAsync();
        await Assert.ThrowsAsync<InvalidDataException>(()=>run.Collect());
    }
    [Fact]
    public async Task A_rehashed_but_false_consent_record_is_rejected_by_semantic_evidence_checks()
    {
        await using var run=await Run.Create(fixture); await using var db=fixture.Open();
        var events=await db.AuditEvents.Where(x=>x.EnvelopeId==run.Envelope.Id).OrderBy(x=>x.Sequence).AsNoTracking().ToArrayAsync();
        var consent=events.First(x=>x.Event=="consent_given"); consent.DataJson=consent.DataJson.Replace("\"agreement\":true","\"agreement\":false");
        byte[]? previous=null;
        foreach(var entry in events) {
            entry.PrevHash=previous; entry.Hash=AuditHash.Compute(entry); previous=entry.Hash;
            _=await db.AuditEvents.Where(x=>x.Id==entry.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.DataJson,entry.DataJson).SetProperty(x=>x.PrevHash,entry.PrevHash).SetProperty(x=>x.Hash,entry.Hash));
        }
        await Assert.ThrowsAsync<InvalidDataException>(()=>run.Collect()); Assert.Empty(run.Probe.Reads);
    }
    [Fact]
    public async Task Excessive_stored_canonical_payloads_are_rejected_before_materializing_or_reading_document_blobs()
    {
        await using var run=await Run.Create(fixture); await using var db=fixture.Open();
        var json=JsonSerializer.Serialize(new[]{new {padding=new string('x',5*1024*1024)}});
        await db.SignerFinishAcceptances.Where(x=>x.EnvelopeId==run.Envelope.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.FieldsJson,json));
        await Assert.ThrowsAsync<InvalidDataException>(()=>run.Collect()); Assert.Empty(run.Probe.Reads);
    }
    [Theory]
    [InlineData("consent")][InlineData("link")][InlineData("field")][InlineData("void")][InlineData("declined")][InlineData("pending")]
    public async Task Missing_recorded_actions_or_ineligible_states_never_return_completion_material(string kind)
    {
        await using var run=await Run.Create(fixture); await using var db=fixture.Open(); var id=run.Envelope.Id;
        if(kind is "consent" or "link")await db.AuditEvents.Where(x=>x.EnvelopeId==id && x.Event==(kind=="consent" ? "consent_given" : "link_opened")).ExecuteDeleteAsync();
        if(kind=="field")await db.Fields.Where(x=>x.EnvelopeId==id && x.Type==FieldType.DateSigned).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.Value,"2000-01-01"));
        if(kind=="void")await db.Envelopes.Where(x=>x.Id==id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.Status,EnvelopeStatus.Voided));
        if(kind=="declined")await db.Envelopes.Where(x=>x.Id==id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.Status,EnvelopeStatus.Declined));
        if(kind=="pending")await db.Signers.Where(x=>x.EnvelopeId==id && x.Order==2).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.Status,SignerStatus.Pending));
        if(kind is "void" or "declined" or "pending")Assert.Null(await run.Collect());
        else await Assert.ThrowsAsync<InvalidDataException>(()=>run.Collect());
        Assert.Empty(run.Probe.Reads);
    }
    [Theory]
    [InlineData("corrupt")][InlineData("missing")][InlineData("length")][InlineData("oversize")]
    [InlineData("corrupt-asset")][InlineData("corrupt-checkpoint")][InlineData("missing-previous")]
    public async Task Missing_corrupt_or_unbounded_storage_cannot_fall_back_to_an_older_copy(string kind)
    {
        await using var run=await Run.Create(fixture); var before=await run.Counts();
        await using var inspect=fixture.Open(); var firstId=await inspect.Signers.Where(x=>x.EnvelopeId==run.Envelope.Id && x.Order==1).Select(x=>x.Id).SingleAsync();
        var first=await inspect.SignerFinishAcceptances.AsNoTracking().SingleAsync(x=>x.SignerId==firstId);
        var lastId=await inspect.SignerFinishAcceptances.Where(x=>x.EnvelopeId==run.Envelope.Id && x.SignerId!=firstId).Select(x=>x.PdfObjectId).SingleAsync();
        run.Probe.Override=async (p,b,s,ct)=> {
            EnvelopeStorageAuthorization.DemandRead(p,b);
            if(kind=="corrupt-asset" && b.Kind!=DocumentBlobKind.Signature || (kind is "corrupt-checkpoint" or "missing-previous") && b.ObjectId!=first.PdfObjectId)
                return await run.H.Blobs.Inner.CopyToAsync(p,b,s,ct);
            if(kind is "missing" or "missing-previous")throw new Azure.RequestFailedException(404,"Synthetic missing object");
            if(kind=="oversize") {var block=new byte[1024*1024]; for(var i=0;i<65;i++)await s.WriteAsync(block,ct); return 65L*block.Length;}
            if(kind is "corrupt" or "corrupt-checkpoint" or "corrupt-asset") {var bytes=kind=="corrupt-asset" ? SignaturePng.Normalize(SignatureAdoptionTests.Mark(100)).Bytes : PdfFixtures.Create(text:"wrong source"); await s.WriteAsync(bytes,ct); return bytes.Length;}
            return (await run.H.Blobs.Inner.CopyToAsync(p,b,s,ct))-1;
        };
        if(kind is "missing" or "missing-previous")await Assert.ThrowsAsync<IOException>(()=>run.Collect()); else await Assert.ThrowsAsync<InvalidDataException>(()=>run.Collect());
        if(kind is "corrupt" or "missing" or "length" or "oversize")Assert.Single(run.Probe.Reads);
        else Assert.DoesNotContain(run.Probe.Reads,x=>x.Blob.ObjectId==lastId);
        Assert.Equal(before,await run.Counts());
    }
    [Fact]
    public async Task Completion_and_checkpoint_read_capabilities_reject_other_targets_mutation_and_changed_identity()
    {
        await using var run=await Run.Create(fixture); Assert.NotNull(await run.Collect());
        foreach(var call in run.Probe.Reads) {
            EnvelopeStorageAuthorization.DemandRead(call.Principal,call.Blob);
            Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.DemandRead(call.Principal,call.Blob with {EnvelopeId=Guid.NewGuid()}));
            Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.DemandRead(call.Principal,call.Blob with {ObjectId=Guid.NewGuid()}));
            Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.Demand(call.Principal,call.Blob));
            Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.DemandDelete(call.Principal,call.Blob));
            call.Principal.AddIdentity(new ClaimsIdentity([new Claim(EnvelopeStorageAuthorization.EnvelopeClaim,run.Envelope.Id.ToString())],EnvelopeStorageAuthorization.SenderScheme));
            Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.DemandRead(call.Principal,call.Blob));
            Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.Demand(call.Principal,call.Blob));
        }
    }
    [Fact]
    public async Task Concurrent_changes_during_blob_reads_are_rechecked_before_any_snapshot_is_returned()
    {
        await using var run=await Run.Create(fixture); var changed=false;
        run.Probe.After=async ()=> {if(changed)return; changed=true; await using var db=fixture.Open(); await db.Envelopes.Where(x=>x.Id==run.Envelope.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.Status,EnvelopeStatus.Voided));};
        await Assert.ThrowsAsync<DocumentConflictException>(()=>run.Collect()); Assert.True(changed);
    }
    [Fact]
    public async Task A_concurrent_valid_audit_tail_requires_a_fresh_complete_snapshot_and_recovers_on_retry()
    {
        await using var run=await Run.Create(fixture); var changed=false;
        run.Probe.After=async ()=> {
            if(changed)return; changed=true; await using var db=fixture.Open(); await using var transaction=await db.Database.BeginTransactionAsync();
            await new AuditWriter(db,run.H.Clock).AppendAsync(run.Envelope.Id,"synthetic_tail_event",null,null,null,default,"{}",PartyType.System); await transaction.CommitAsync();
        };
        await Assert.ThrowsAsync<DocumentConflictException>(()=>run.Collect());
        var recovered=(await run.Collect())!; Assert.Equal("synthetic_tail_event",recovered.Evidence.Events[^1].Event);
    }
    [Fact]
    public async Task Expired_internal_read_scope_and_caller_cancellation_return_no_material_or_writes()
    {
        await using var run=await Run.Create(fixture); var before=await run.Counts();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>run.Collect(new CancellationToken(true))); Assert.Empty(run.Probe.Reads);
        run.Probe.Before=()=> {run.H.Clock.Advance(TimeSpan.FromMinutes(3)); return Task.CompletedTask;};
        await Assert.ThrowsAsync<IOException>(()=>run.Collect()); Assert.Equal(before,await run.Counts());
    }

    internal sealed class Run : IAsyncDisposable
    {
        public Shared H=null!; public Envelope Envelope=null!; public ClaimsPrincipal Sender=null!,LastSigner=null!; public ReadProbe Probe=null!; public string LastReviewReceipt="";
        private SqlDatabaseFixture fixture=null!;
        public async Task<T> Use<S,T>(Func<S,Task<T>> action) where S:notnull {using var scope=H.App.Services.CreateScope(); return await action(scope.ServiceProvider.GetRequiredService<S>());}
        public async Task<Envelope> Refresh() {await using var db=fixture.Open(); return Envelope=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==Envelope.Id);}
        public static async Task<Run> Create(SqlDatabaseFixture fixture,bool demo=false,bool publishLast=true,bool senderAlsoSigns=false,bool finishLast=true,bool firstOnly=false,int? uploadRetentionDays=null,TimeSpan? afterUploadDelay=null,DateTimeOffset? initialTime=null)
        {
            var run=new Run {fixture=fixture,H=await Shared.Create(fixture,browser:true)}; var email="completion-"+Guid.NewGuid().ToString("N")+"@example.invalid";
            if(initialTime is { } start) {
                run.H.Clock.Advance(start-run.H.Clock.GetUtcNow());
                // The raw legacy signer reader uses wall-clock UTC. A historical
                // synthetic pipeline needs a clock-aware test transport, not changed
                // production authority or rewritten frozen enrollment evidence.
                run.H.Blobs.SyntheticSignerRead=async (principal,blob,destination,ct)=> {
                    var identity=SignerAccessConfiguration.ReadIdentity(principal,run.H.Clock.GetUtcNow());
                    if(identity is null || blob.Kind!=DocumentBlobKind.Normalized || blob.EnvelopeId!=identity.EnvelopeId || blob.ObjectId!=identity.DocumentId)
                        throw new UnauthorizedAccessException("A current synthetic signer read scope is required.");
                    var source=DemoPurgeStorageTests.Service().GetBlobContainerClient("normalized").GetBlobClient($"{blob.EnvelopeId:N}/{blob.ObjectId:N}");
                    var value=(await source.DownloadStreamingAsync(cancellationToken:ct)).Value;
                    await using var input=value.Content;await input.CopyToAsync(destination,ct);return value.Details.ContentLength;
                };
            }
            run.H.App.Services.GetRequiredService<DemoRetentionOptions>().PurgeAfterDays=uploadRetentionDays;
            _=await run.Use((SenderWorkflow s)=>s.RequestAsync(email,"127.0.0.1","Synthetic sender")); Assert.True(await run.H.Once());
            var sender=(await run.Use((SenderWorkflow s)=>s.VerifyAsync(Token(run.H),"127.0.0.1","Synthetic sender")))!; Assert.NotNull(sender);
            run.Sender=SenderConfiguration.Principal(sender); await using(var db=fixture.Open())run.Envelope=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==sender.EnvelopeId);
            await using(var db=fixture.Open())await db.Envelopes.Where(x=>x.Id==run.Envelope.Id).ExecuteUpdateAsync(v=>v.SetProperty(x=>x.ExpiresAt,run.H.Clock.GetUtcNow().AddHours(1)).SetProperty(x=>x.IsDemo,demo));
            await run.Refresh();
            var source=PdfFixtures.Create(text:"SYNTHETIC COMPLETION CHAIN - NO AGREEMENT");
            Assert.True(await run.Use((DocumentWorkflow s)=>s.UploadAsync(run.Sender,run.Envelope.PublicId,run.Envelope.RowVersion,"Synthetic completion NO AGREEMENT.pdf",new MemoryStream(source),source.Length,"127.0.0.1","Synthetic sender",default)));
            await run.Refresh(); Assert.True(await run.Use((DocumentWorkflow s)=>s.ConfirmAsync(run.Sender,run.Envelope.PublicId,run.Envelope.RowVersion,run.Envelope.PdfBlob!,true,"127.0.0.1","Synthetic sender",default)));
            if(afterUploadDelay is { } delay) {
                run.H.Clock.Advance(delay);
                await using var db=fixture.Open();await db.Envelopes.Where(x=>x.Id==run.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ExpiresAt,run.H.Clock.GetUtcNow().AddHours(1)));
            }
            for(var i=1;i<=2;i++) {
                await run.Refresh(); var result=await run.Use((SignerSetup s)=>s.ChangeAsync(run.Sender,run.Envelope.PublicId,new(SignerChangeKind.Save,Convert.ToBase64String(run.Envelope.RowVersion),null,"Synthetic signer "+i,senderAlsoSigns && i==1 ? email : "signer"+i+"-"+email,"Role "+i),"127.0.0.1","Synthetic sender",default));
                Assert.Equal(SignerSetupError.None,result.Error);
            }
            await run.Refresh(); var recipient=await run.Use((DraftDetails s)=>s.ChangeAsync(run.Sender,run.Envelope.PublicId,new(DetailsChangeKind.SaveRecipient,Convert.ToBase64String(run.Envelope.RowVersion),Name:"Synthetic recipient",Email:"recipient-"+email),"127.0.0.1","Synthetic sender",default)); Assert.Equal(DetailsError.None,recipient.Error);
            await using(var db=fixture.Open()) {
                var signers=await db.Signers.Where(x=>x.EnvelopeId==run.Envelope.Id).OrderBy(x=>x.Order).ToArrayAsync();
                foreach(var signer in signers)foreach(var type in new[]{FieldType.Signature,FieldType.Initials,FieldType.FullName,FieldType.DateSigned})
                    db.Fields.Add(new() {EnvelopeId=run.Envelope.Id,SignerId=signer.Id,Type=type,Page=signer.Order,X=type==FieldType.DateSigned ? .65m : .1m,Y=type switch {FieldType.Signature=>.4m,FieldType.Initials=>.55m,FieldType.FullName=>.7m,_=>.4m},Width=type==FieldType.DateSigned ? .25m : .5m,Height=.08m,Required=true});
                await db.SaveChangesAsync();
            }
            await run.Refresh();var sendReview=await run.Use((DraftReview r)=>r.GetAsync(run.Sender,run.Envelope.PublicId));
            Assert.NotNull(await run.Use((SendDraftWorkflow s)=>s.SendAsync(run.Sender,run.Envelope.PublicId,run.Envelope.RowVersion,true,true,SenderSendStatement.Version,"127.0.0.1","Synthetic sender",reviewedRetentionSha256:sendReview!.RetentionSha256)));
            var last=firstOnly ? 1 : 2;for(var i=1;i<=last;i++)await run.SignNext(i<last || publishLast,i<last || finishLast);
            await run.Refresh(); run.Probe=new(run.H.Blobs.Inner); return run;
        }
        private static string Token(Shared h) {var raw=Regex.Match(h.Sender.Last!.Text,"token=([A-Za-z0-9_-]{43})").Groups[1].Value; Assert.Equal(43,raw.Length); return raw;}
        private async Task SignNext(bool publish,bool finish)
        {
            Assert.True(await H.Once()); var identity=(await Use((SignerAccess s)=>s.RedeemAsync(Token(H),"127.0.0.1","Synthetic signer")))!; Assert.NotNull(identity);
            var principal=SignerAccessConfiguration.Principal(identity); LastSigner=principal;
            var context=(await Use((SignerAccess s)=>s.GetContextAsync(principal,Envelope.PublicId)))!;
            _=await Use((SignerPdfAccess s)=>s.PrepareAsync(principal,context));
            var receipt=await Use((SignerReceiptProtection s)=>Task.FromResult(s.Create(identity)));
            Assert.Equal(ConsentResult.Accepted,await Use((SignerConsent s)=>s.AcceptAsync(principal,Envelope.PublicId,receipt,true,true,"download","127.0.0.1","Synthetic signer")));
            var preview=(await Use((SignatureAdoption s)=>s.PrepareAsync(principal,Envelope.PublicId,new(SignatureAdoptionTests.Mark(),SignatureAdoptionTests.Mark(60),SignatureMethod.Drawn))))!;
            _=await Use((SignatureAdoption s)=>s.AdoptAsync(principal,Envelope.PublicId,preview.Receipt,true,SignatureAdoptionStatement.Version,"127.0.0.1","Synthetic signer"));
            var fields=(await Use((SignerFields s)=>s.GetAsync(principal,Envelope.PublicId)))!; Assert.NotNull(fields.AdoptionId);
            foreach(var field in fields.Fields.Where(x=>x.Type!=FieldType.DateSigned)) {
                var result=await Use((SignerFields s)=>s.ChangeAsync(principal,Envelope.PublicId,new(field.Id,field.Version,SignerFieldAction.Apply,AdoptionId:field.Type is FieldType.Signature or FieldType.Initials ? fields.AdoptionId : null),"127.0.0.1","Synthetic signer"));
                Assert.Equal(SignerFieldOutcome.Applied,result.Outcome);
            }
            var review=(await Use((SignerReviewCandidates s)=>s.PrepareAsync(principal,Envelope.PublicId,"127.0.0.1","Synthetic signer")))!;
            LastReviewReceipt=review.Receipt;
            Assert.NotNull(await Use((SignerReviewCandidates s)=>s.ReadAsync(principal,Envelope.PublicId,review.Receipt)));
            if(!finish)return;
            Assert.Equal(SignerFinishOutcome.Accepted,(await Use((SignerFinish s)=>s.AcceptAsync(principal,Envelope.PublicId,review.Receipt,true,SignerFinishStatement.Version,"127.0.0.1","Synthetic signer"))).Outcome);
            H.Clock.Advance(TimeSpan.FromSeconds(3)); if(publish)Assert.True(await H.Once());
        }
        public async Task<CompletionMaterialization?> Collect(CancellationToken ct=default)
        {await using var db=fixture.Open(); return await new CompletionEvidenceCollector(db,new(db,H.Clock),new(Probe,H.Clock),Probe,H.Clock).CollectAsync(Envelope.Id,ct);}
        public async Task<string> Counts()
        {await using var db=fixture.Open(); return string.Join(',',await db.AuditEvents.CountAsync(x=>x.EnvelopeId==Envelope.Id),await db.WorkItems.CountAsync(x=>x.EnvelopeId==Envelope.Id),await db.EmailOutbox.CountAsync(x=>x.EnvelopeId==Envelope.Id),H.Blobs.Created.Count,H.Blobs.Deleted.Count,H.Sender.Calls);}
        public async ValueTask DisposeAsync()
        {
            if(Envelope is not null) {foreach(var blob in H.Blobs.Created.Where(x=>x.EnvelopeId==Envelope.Id).Distinct())await H.Blobs.Inner.DeleteAsync(Sender,blob); H.Blobs.Created.RemoveAll(x=>x.EnvelopeId==Envelope.Id);}
            await H.DisposeAsync();
        }
    }
    internal sealed class ReadProbe(IBlobStore inner) : IBlobStore
    {
        public List<(ClaimsPrincipal Principal,DocumentBlob Blob)> Reads=[];
        public Func<Task>? Before,After; public Func<ClaimsPrincipal,DocumentBlob,Stream,CancellationToken,Task<long>>? Override;
        public Task WriteAsync(ClaimsPrincipal p,DocumentBlob b,Stream s,long n,CancellationToken ct)=>throw new Exception("Collector attempted a write.");
        public Task DeleteAsync(ClaimsPrincipal p,DocumentBlob b,CancellationToken ct)=>throw new Exception("Collector attempted a delete.");
        public async Task<long> CopyToAsync(ClaimsPrincipal p,DocumentBlob b,Stream s,CancellationToken ct) {Reads.Add((p,b)); if(Before is not null)await Before(); var length=Override is not null ? await Override(p,b,s,ct) : await inner.CopyToAsync(p,b,s,ct); if(After is not null)await After(); return length;}
    }
}
