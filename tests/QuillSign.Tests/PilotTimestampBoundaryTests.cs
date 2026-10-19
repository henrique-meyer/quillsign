using System.Data.Common;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Sealing;
using QuillSign.Sender;
using QuillSign.Work;
using SealRun=QuillSign.Tests.CompletionSealOutputTests.Run;

namespace QuillSign.Tests;

public sealed class PilotTimestampCompositionTests
{
    [Fact]
    public async Task Explicit_restricted_singletons_reject_unbound_calls_before_certificate_coordinator_SQL_or_HTTP()
    {
        await using var f=await SealFixtures.Create();var marker=new PilotTimestampPolicy();
        using var tsa=new TimestampAuthority(f.Options,f.App.Environment,f.Time,()=>throw new Exception("No coordinator"),marker);
        var engine=new PlatformPdfSeal(f.Options,f.Certificates,tsa,f.App.Environment,f.Time,marker);
        var source=PdfFixtures.Create();
        await Assert.ThrowsAsync<PilotTimestampDeniedException>(()=>engine.SealAsync(source,SHA256.HashData(source)));
        using var certificate=X509CertificateLoader.LoadPkcs12(f.Seal.Export(X509ContentType.Pkcs12),null);
        var cms=new SignedCms(new ContentInfo(new byte[]{1,2,3}));cms.ComputeSignature(new CmsSigner(certificate),true);
        await Assert.ThrowsAsync<PilotTimestampDeniedException>(()=>tsa.RequestAsync(cms.SignerInfos[0],f.Time.GetUtcNow(),default));
        Assert.Equal(0,f.Certificates.Calls);Assert.Equal(0,f.Requests);
        var services=new ServiceCollection();var config=new ConfigurationBuilder().Build();
        services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
        services.AddSingleton<Microsoft.Extensions.Hosting.IHostEnvironment>(f.App.Environment);
        services.AddPilotTimestampBoundaryFoundation(config);services.AddPlatformPdfSeals(config);
        using var provider=services.BuildServiceProvider(new ServiceProviderOptions{ValidateScopes=true,ValidateOnBuild=true});
        _=provider.GetRequiredService<PlatformPdfSeal>();_=provider.GetRequiredService<TimestampAuthority>();
        using var scope=provider.CreateScope();_=scope.ServiceProvider.GetRequiredService<PilotTimestampBoundary>();
    }
}

public sealed class PilotTimestampBoundaryTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    private const string Capability="1234567890123456789012345678901234567890123";

    [Fact]
    public async Task Admitted_verified_two_signer_chain_seals_exact_pair_and_reads_spend_nothing_then_replay_is_denied()
    {
        await using var h=await Harness.Create(fixture);var context=await h.Context();
        h.Run.Seal.RequestObserved=()=>Assert.True(h.Coordinator.Held);
        var pair=Assert.IsType<CompletionSealPair>(await h.Outputs.PrepareAsync(h.Id,timestampWork:context));
        Assert.Equal(2,h.Run.Seal.Requests);Assert.Equal(2,(await h.Ledger.ReadBudgetAsync())!.TimestampAttempts);
        Assert.NotNull(await h.Outputs.ReadAsync(h.Id));Assert.NotNull(await h.Outputs.PrepareAsync(h.Id,timestampWork:context));
        Assert.Equal(2,h.Run.Seal.Requests);Assert.Equal(2,(await h.Ledger.ReadBudgetAsync())!.TimestampAttempts);
        var source=h.Run.Candidate.Packet.Bytes;var hash=SHA256.HashData(source);
        var owned=await h.Boundary.BindArtifactAsync(context,h.Run.Candidate.Id,CompletionSealKind.Executed,hash,null,null);
        hash[0]^=1; // Source hashes passed by callers cannot alter the owned context.
        await Assert.ThrowsAsync<PilotTimestampDeniedException>(()=>h.Engine.SealAsync(source,SHA256.HashData(source),timestampContext:owned));
        Assert.Equal(2,h.Run.Seal.Requests);Assert.Equal(2,(await h.Ledger.ReadBudgetAsync())!.TimestampAttempts);
        var receipts=await h.Db.EmailPilotReservations.AsNoTracking().Where(x=>x.RunId==h.RunId).ToArrayAsync();
        Assert.All(receipts,x=>{Assert.Equal(EmailPilotAttemptKind.Timestamp,x.Kind);Assert.Equal(32,x.RequestSha256.Length);Assert.Equal(0,x.EncodedBytes);});
        Assert.Equal(2,h.Run.Seal.RequestBodies.Count);
        Assert.All(h.Run.Seal.RequestBodies,body=>Assert.Contains(receipts,r=>r.RequestSha256.SequenceEqual(SHA256.HashData(body))));
        Assert.Equal(pair.Executed.Pdf.SourceSha256,h.Run.Candidate.Packet.Sha256);
        Assert.True(h.Coordinator.Acquires>=2);Assert.False(h.Email.Enabled);
    }

    [Theory]
    [InlineData("disabled")][InlineData("public-email")][InlineData("run")][InlineData("secret")][InlineData("binding")][InlineData("lease-owner")][InlineData("candidate")][InlineData("source")]
    public async Task Known_or_changed_authority_never_falls_back_or_resolves_certificate(string change)
    {
        await using var h=await Harness.Create(fixture);var context=await h.Context();var source=h.Run.Candidate.Packet.Bytes;
        var artifact=await h.Boundary.BindArtifactAsync(context,h.Run.Candidate.Id,CompletionSealKind.Executed,SHA256.HashData(source),null,null);
        if(change=="disabled")h.Options.Enabled=false;
        if(change=="public-email")h.Email.Enabled=true;
        if(change=="run")h.Options.RunId=Guid.NewGuid().ToString("N");
        if(change=="secret")await h.Db.EmailPilotSecrets.Where(x=>x.RunId==h.RunId).ExecuteDeleteAsync();
        if(change=="binding")await h.Db.EmailPilotEnrollments.Where(x=>x.SubjectEnvelopeId==h.Id).ExecuteUpdateAsync(x=>x.SetProperty(v=>v.ProtectedBinding,"corrupt"));
        if(change=="lease-owner")await h.Db.WorkItems.Where(x=>x.Id==h.Lease.Id).ExecuteUpdateAsync(x=>x.SetProperty(v=>v.LeaseOwner,Guid.NewGuid()));
        if(change=="candidate")await h.Db.CompletionCandidates.Where(x=>x.Id==h.Run.Candidate.Id).ExecuteUpdateAsync(x=>x.SetProperty(v=>v.RecipeSha256,new byte[32]));
        if(change=="source")source=PdfFixtures.Create(text:"Changed NO AGREEMENT source");
        await Assert.ThrowsAsync<PilotTimestampDeniedException>(()=>h.Engine.SealAsync(source,SHA256.HashData(source),timestampContext:artifact));
        Assert.Equal(0,h.Run.Seal.Certificates.Calls);Assert.Equal(0,h.Run.Seal.Requests);
        if(change is not ("candidate" or "source"))await Assert.ThrowsAsync<PilotTimestampDeniedException>(()=>h.Context());
        if(change=="disabled"){
            var resolved=false;var clock=h.Run.Signing.H.Clock;
            var handler=new CompletionWorkHandler(h.AdmissionDb,new(h.AdmissionDb,clock),new(h.AdmissionDb,clock),()=>{resolved=true;throw new Exception("No pipeline");},clock);
            Assert.Equal(WorkOutcome.Failed,(await handler.ExecuteAsync(h.Lease,default)).Outcome);Assert.False(resolved);
        }
        await Assert.ThrowsAsync<PilotTimestampDeniedException>(()=>h.Outputs.PrepareAsync(h.Id));
        Assert.Equal(0,h.Run.Seal.Requests);
    }

    [Theory]
    [InlineData("coordinator")][InlineData("factory")][InlineData("preflight")][InlineData("HTTP")]
    public async Task Expiry_at_external_boundaries_never_returns_a_seal_and_never_refunds_committed_reservation(string at)
    {
        await using var h=await Harness.Create(fixture);var work=await h.Context();var source=h.Run.Candidate.Packet.Bytes;
        var artifact=await h.Boundary.BindArtifactAsync(work,h.Run.Candidate.Id,CompletionSealKind.Executed,SHA256.HashData(source),null,null);
        void Expire()=>h.Run.Signing.H.Clock.Advance(TimeSpan.FromHours(2));
        if(at=="coordinator")h.Coordinator.OnAcquire=Expire;
        if(at=="HTTP")h.Run.Seal.RequestObserved=Expire;
        if(at=="preflight")h.Coordinator.OnEnsure=n=>{if(n==2)Expire();};
        ISealCertificateProvider provider=at=="factory"?new HookProvider(h.Run.Seal.Certificates,Expire):h.Run.Seal.Certificates;
        var engine=new PlatformPdfSeal(h.Run.Seal.Options,provider,h.Tsa,h.Run.Seal.App.Environment,h.Run.Signing.H.Clock,new());
        if(at=="coordinator")await Assert.ThrowsAsync<SealUnavailableException>(()=>engine.SealAsync(source,SHA256.HashData(source),timestampContext:artifact));
        else await Assert.ThrowsAsync<PilotTimestampDeniedException>(()=>engine.SealAsync(source,SHA256.HashData(source),timestampContext:artifact));
        Assert.Equal(at=="HTTP"?1:0,h.Run.Seal.Requests);
        Assert.Equal(at is "preflight" or "HTTP"?1:0,await h.Db.EmailPilotReservations.CountAsync(x=>x.RunId==h.RunId));
    }

    [Fact]
    public async Task Lost_actual_reservation_commit_acknowledgement_is_nonrefunded_and_cannot_be_reused_for_HTTP()
    {
        await using var h=await Harness.Create(fixture);var work=await h.Context();var source=h.Run.Candidate.Packet.Bytes;
        var artifact=await h.Boundary.BindArtifactAsync(work,h.Run.Candidate.Id,CompletionSealKind.Executed,SHA256.HashData(source),null,null);
        await using var faultDb=new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(h.Db.Database.GetConnectionString()).AddInterceptors(new LostCommit()).Options);
        h.ReservationDatabase=faultDb;
        await Assert.ThrowsAsync<PilotTimestampDeniedException>(()=>h.Engine.SealAsync(source,SHA256.HashData(source),timestampContext:artifact));
        Assert.Equal(0,h.Run.Seal.Requests);Assert.Equal(1,(await h.Ledger.ReadBudgetAsync())!.TimestampAttempts);
        h.ReservationDatabase=null;
        await Assert.ThrowsAsync<PilotTimestampDeniedException>(()=>h.Engine.SealAsync(source,SHA256.HashData(source),timestampContext:artifact));
        Assert.Equal(0,h.Run.Seal.Requests);Assert.Equal(1,(await h.Ledger.ReadBudgetAsync())!.TimestampAttempts);
    }

    [Fact]
    public async Task Four_attempt_ceiling_is_enforced_after_coordinator_and_before_any_HTTP()
    {
        await using var h=await Harness.Create(fixture);var work=await h.Context();var source=h.Run.Candidate.Packet.Bytes;
        var artifact=await h.Boundary.BindArtifactAsync(work,h.Run.Candidate.Id,CompletionSealKind.Executed,SHA256.HashData(source),null,null);
        for(var i=0;i<4;i++){var id=Guid.NewGuid();Assert.Equal(EmailPilotReservationOutcome.Reserved,await h.Ledger.ReserveAsync(new(id,h.Id,id,EmailPilotAttemptKind.Timestamp,EmailPilotRole.None,0,new string('a',64)),null));}
        await Assert.ThrowsAsync<PilotTimestampDeniedException>(()=>h.Engine.SealAsync(source,SHA256.HashData(source),timestampContext:artifact));
        Assert.Equal(1,h.Coordinator.Acquires);Assert.Equal(0,h.Run.Seal.Requests);Assert.Equal(4,(await h.Ledger.ReadBudgetAsync())!.TimestampAttempts);
    }

    [Fact]
    public async Task Concurrent_same_artifact_calls_have_one_nonreusable_reservation_and_one_HTTP_request()
    {
        await using var h=await Harness.Create(fixture);var work=await h.Context();var source=h.Run.Candidate.Packet.Bytes;
        var artifact=await h.Boundary.BindArtifactAsync(work,h.Run.Candidate.Id,CompletionSealKind.Executed,SHA256.HashData(source),null,null);
        var results=await Task.WhenAll(Enumerable.Range(0,2).Select(_=>Record.ExceptionAsync(()=>h.Engine.SealAsync(source,SHA256.HashData(source),timestampContext:artifact))));
        Assert.Single(results,x=>x is null);Assert.Single(results,x=>x is PilotTimestampDeniedException);
        Assert.Equal(1,h.Run.Seal.Requests);Assert.Equal(1,(await h.Ledger.ReadBudgetAsync())!.TimestampAttempts);
    }

    [Fact]
    public async Task Exact_consumed_receipt_and_one_use_digest_permit_never_authorize_another_call()
    {
        await using var h=await Harness.Create(fixture);var work=await h.Context();var source=h.Run.Candidate.Packet.Bytes;
        var artifact=await h.Boundary.BindArtifactAsync(work,h.Run.Candidate.Id,CompletionSealKind.Executed,SHA256.HashData(source),null,null);
        var request=new byte[]{1,2,3};var permit=await artifact.ReserveAsync(request,default);
        await Assert.ThrowsAsync<PilotTimestampDeniedException>(()=>artifact.ReserveAsync(request,default));
        await Assert.ThrowsAsync<PilotTimestampDeniedException>(()=>permit.DemandSendAsync(new byte[]{1,2,4},default));
        await Assert.ThrowsAsync<PilotTimestampDeniedException>(()=>permit.DemandSendAsync(request,default));
        Assert.Equal(1,(await h.Ledger.ReadBudgetAsync())!.TimestampAttempts);Assert.Equal(0,h.Run.Seal.Requests);
    }

    private sealed class HookProvider(ISealCertificateProvider inner,Action hook):ISealCertificateProvider
    {public async Task<SealCertificateMaterial> AcquireAsync(CancellationToken ct){var value=await inner.AcquireAsync(ct);hook();return value;}}
    private sealed class LostCommit:DbTransactionInterceptor
    {public override Task TransactionCommittedAsync(DbTransaction tx,TransactionEndEventData e,CancellationToken ct=default)=>throw new IOException("Synthetic lost counter acknowledgement.");}
    internal sealed class Coordinator:ITimestampRequestCoordinator
    {
        internal int Acquires;internal bool Held;internal Action? OnAcquire;internal Action<int>? OnEnsure;
        public Task<ITimestampRequestLease> AcquireAsync(Uri uri,CancellationToken ct){Acquires++;Held=true;OnAcquire?.Invoke();return Task.FromResult<ITimestampRequestLease>(new Lease(this));}
        private sealed class Lease(Coordinator owner):ITimestampRequestLease
        {private int ensures;public CancellationToken Token=>CancellationToken.None;public Task EnsureOwnedAsync(CancellationToken ct){owner.OnEnsure?.Invoke(++ensures);ct.ThrowIfCancellationRequested();return Task.CompletedTask;}public ValueTask DisposeAsync(){owner.Held=false;return ValueTask.CompletedTask;}}
    }
    internal sealed class Harness:IAsyncDisposable
    {
        internal SealRun Run=null!;internal QuillSignDbContext Db=null!,AdmissionDb=null!;internal QuillSignDbContext? ReservationDatabase;
        internal EmailPilotOptions Options=new(){Enabled=true,RunId=Guid.NewGuid().ToString("N")};internal EmailOptions Email=null!;internal WorkOptions Work=null!;
        internal EmailPilotAdmissionOptions Admission=new(){CapabilitySha256=Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(Capability)))};
        internal IDataProtectionProvider Keys=null!;internal EmailPayloadProtection Payload=null!;internal WorkLease Lease=null!;
        internal Coordinator Coordinator=new();internal TimestampAuthority Tsa=null!;internal PlatformPdfSeal Engine=null!;internal PilotTimestampBoundary Boundary=null!;internal CompletionSealOutputs Outputs=null!;
        internal Guid Id=>Run.Signing.Envelope.Id;internal Guid RunId=>Guid.ParseExact(Options.RunId,"N");
        internal EmailPilotLedger Ledger=>LedgerFor(Db);
        internal EmailPilotLedger LedgerFor(QuillSignDbContext db)=>new(Options,Email,()=>db,()=>new(Keys),Run.Signing.H.Clock);
        internal EmailPilotWorkAuthority Authority()=>new(Options,Email,Work,Admission,()=>Ledger,()=>Db,()=>Payload,Run.Signing.H.Clock);
        internal Task<CompletionTimestampWork> Context()=>Boundary.ReadCompletionAsync(Lease,Id,Db.WorkItems.AsNoTracking().Single(x=>x.Id==Lease.Id).PayloadJson);
        internal static async Task<Harness> Create(SqlDatabaseFixture fixture)
        {
            var h=new Harness();var sender="pilot-tsa-"+h.Options.RunId+"@example.invalid";
            h.Options.Mailboxes=new(sender,"first@example.invalid","second@example.invalid","recipient@example.invalid");
            h.Run=await SealRun.Create(fixture,mailbox:sender,signerMailbox:i=>i==1?h.Options.Mailboxes.FirstSigner:h.Options.Mailboxes.SecondSigner,
                recipientMailbox:h.Options.Mailboxes.Recipient,requestSender:async(shared,_)=>{
                    h.Email=shared.App.Services.GetRequiredService<EmailOptions>();h.Email.Enabled=false;h.Work=shared.App.Services.GetRequiredService<WorkOptions>();
                    h.Keys=shared.App.Services.GetRequiredService<IDataProtectionProvider>();
                    using var scope=shared.App.Services.CreateScope();var sp=scope.ServiceProvider;var db=sp.GetRequiredService<QuillSignDbContext>();
                    h.Payload=sp.GetRequiredService<EmailPayloadProtection>();
                    var ledger=new EmailPilotLedger(h.Options,h.Email,()=>db,()=>new(h.Keys),shared.Clock);
                    var admission=new EmailPilotAdmission(h.Options,h.Admission,h.Email,h.Work,new(),()=>sp.GetRequiredService<SenderAvailability>(),()=>ledger,
                        ()=>sp.GetRequiredService<EmailOutboxWriter>(),()=>h.Payload,shared.Clock);
                    Assert.NotNull(await admission.RequestAsync(Capability,EmailPilotScenario.Completion));
                    // Existing synthetic-only normal dispatcher delivers to an in-memory fake.
                    // No pilot transport is composed and no external email is sent.
                    h.Email.Enabled=true;
                });
            h.Email.Enabled=false;h.Db=fixture.Open();h.AdmissionDb=fixture.Open();
            h.Lease=(await new WorkStore(h.Db,h.Work,h.Run.Signing.H.Clock).ClaimAsync(CompletionJobs.WorkId(h.Id),default)).Lease!;Assert.NotNull(h.Lease);
            h.Boundary=new(()=>h.Db,h.Authority,()=>h.LedgerFor(h.ReservationDatabase??h.Db),h.Run.Signing.H.Clock);
            h.Run.Seal.Options.TimestampCoordination.Enabled=true;
            h.Tsa=new(h.Run.Seal.Options,h.Run.Seal.App.Environment,h.Run.Signing.H.Clock,()=>h.Coordinator,new());
            h.Engine=new(h.Run.Seal.Options,h.Run.Seal.Certificates,h.Tsa,h.Run.Seal.App.Environment,h.Run.Signing.H.Clock,new());
            h.Outputs=new(h.AdmissionDb,h.Run.Candidates(h.AdmissionDb),h.Run.Collector(h.AdmissionDb),new(),h.Engine,new(h.Run.Seal.Options,h.Tsa),h.Run.Storage,
                new(h.AdmissionDb,h.Run.Signing.H.Clock),h.Run.Signing.H.Clock,null,h.Boundary);
            return h;
        }
        public async ValueTask DisposeAsync(){Tsa.Dispose();await AdmissionDb.DisposeAsync();await Db.DisposeAsync();await Run.DisposeAsync();}
    }
}
