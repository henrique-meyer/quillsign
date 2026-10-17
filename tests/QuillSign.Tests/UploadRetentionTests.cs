using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Documents;
using Shared=QuillSign.Tests.DocumentWorkflowTests.Harness;

namespace QuillSign.Tests;

public sealed class UploadRetentionTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData(null,true)][InlineData(1,true)][InlineData(7,true)][InlineData(36500,true)]
    [InlineData(0,false)][InlineData(-1,false)][InlineData(36501,false)]
    public void Configuration_is_explicit_bounded_and_does_not_resolve_storage(int? days,bool valid)
    {
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["Demo:PurgeAfterDays"]=days?.ToString() }).Build();
        var services=new ServiceCollection();
        if(valid) {services.AddQuillSignDocuments(config);using var provider=services.BuildServiceProvider();Assert.Equal(days,provider.GetRequiredService<DemoRetentionOptions>().PurgeAfterDays);}
        else Assert.Throws<InvalidOperationException>(()=>services.AddQuillSignDocuments(config));
    }

    [Fact]
    public async Task First_successful_upload_freezes_exact_UTC_interval_and_replacements_never_extend_it()
    {
        await using var h=await Shared.CreateAsync(fixture,demo:true);var clock=new Clock();h.Time=clock;h.Retention.PurgeAfterDays=7;
        Assert.True(await h.UploadAsync(PdfFixtures.Create(text:"SYNTHETIC RETENTION - NO AGREEMENT")));
        var original=await Read(h);Assert.Equal(clock.Now,original.StartedAt);Assert.Equal(clock.Now.AddDays(7),original.DeleteAfter);Assert.Equal(7,original.Days);
        var before=await h.StateAsync();Assert.Equal(Guid.ParseExact(before.OriginalBlob!,"N"),original.OriginalObjectId);Assert.Equal(before.PdfSha256,original.PdfSha256);
        Assert.Null(before.PurgeAfter); // Legacy completion metadata has not been silently reinterpreted.
        clock.Now=clock.Now.AddDays(2);h.Retention.PurgeAfterDays=30;Assert.True(await h.UploadAsync(PdfFixtures.Create(1,text:"SYNTHETIC REPLACEMENT")));
        var replacement=await h.StateAsync();Assert.NotEqual(before.PdfBlob,replacement.PdfBlob);Assert.Equal(UploadRetention.Digest(original),UploadRetention.Digest(await Read(h)));
        h.Retention.PurgeAfterDays=null;clock.Now=clock.Now.AddDays(1);Assert.True(await h.UploadAsync(PdfFixtures.Create(1,text:"SYNTHETIC SECOND REPLACEMENT")));
        Assert.Equal(UploadRetention.Digest(original),UploadRetention.Digest(await Read(h)));
        await using var db=fixture.Open();Assert.Equal(1,await db.DocumentRetentionSnapshots.CountAsync(x=>x.EnvelopeId==h.Id));
        var audits=await db.AuditEvents.Where(x=>x.EnvelopeId==h.Id && (x.Event=="document_uploaded" || x.Event=="document_replaced")).ToArrayAsync();Assert.Equal(3,audits.Length);
        foreach(var audit in audits) {using var json=JsonDocument.Parse(audit.DataJson);Assert.Equal(UploadRetention.Digest(original),json.RootElement.GetProperty("retentionSha256").GetString());}
    }

    [Theory]
    [InlineData("storage")][InlineData("audit")]
    public async Task Failed_first_upload_does_not_start_retention_and_retry_uses_its_own_success_time(string failure)
    {
        await using var h=await Shared.CreateAsync(fixture,demo:true);var clock=new Clock();h.Time=clock;h.Retention.PurgeAfterDays=7;
        if(failure=="storage")h.Store.FailWrite=2;else h.AuditFailure.Enabled=true;
        var error=await Record.ExceptionAsync(()=>h.UploadAsync(PdfFixtures.Create()));Assert.NotNull(error);
        Assert.True(error is IOException or DbUpdateException);await using(var db=fixture.Open())Assert.False(await db.DocumentRetentionSnapshots.AnyAsync(x=>x.EnvelopeId==h.Id));
        Assert.Null((await h.StateAsync()).PdfBlob);h.Store.FailWrite=0;h.AuditFailure.Enabled=false;clock.Now=clock.Now.AddDays(3);
        Assert.True(await h.UploadAsync(PdfFixtures.Create()));Assert.Equal(clock.Now,(await Read(h)).StartedAt);
    }

    [Fact]
    public async Task Lost_commit_acknowledgement_keeps_the_committed_snapshot_and_readable_bytes()
    {
        await using var h=await Shared.CreateAsync(fixture,demo:true);var clock=new Clock();h.Time=clock;h.Retention.PurgeAfterDays=7;h.CommitFailure.Enabled=true;
        await Assert.ThrowsAsync<IOException>(()=>h.UploadAsync(PdfFixtures.Create()));var saved=await Read(h);var state=await h.StateAsync();
        await using var file=await h.WithAsync(s=>s.ReadAsync(h.Sender,h.PublicId,state.PdfBlob!,default));Assert.NotNull(file);
        h.CommitFailure.Enabled=false;clock.Now=clock.Now.AddDays(1);Assert.True(await h.UploadAsync(PdfFixtures.Create(1)));
        Assert.Equal(UploadRetention.Digest(saved),UploadRetention.Digest(await Read(h)));
    }

    [Fact]
    public async Task Concurrent_first_uploads_freeze_only_the_winners_source_and_deadline()
    {
        await using var h=await Shared.CreateAsync(fixture,demo:true);h.Time=new Clock();h.Retention.PurgeAfterDays=7;var version=(await h.StateAsync()).RowVersion;
        async Task<bool> Upload(string text) {try {return await h.UploadAsync(PdfFixtures.Create(1,text:text),version);}catch(DocumentConflictException) {return false;}}
        var results=await Task.WhenAll(Upload("SYNTHETIC FIRST"),Upload("SYNTHETIC SECOND"));Assert.Single(results,x=>x);
        var state=await h.StateAsync();var row=await Read(h);Assert.Equal(state.PdfSha256,row.PdfSha256);Assert.Equal(Guid.ParseExact(state.PdfBlob!,"N"),row.PdfObjectId);
        await using var db=fixture.Open();Assert.Equal(1,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==h.Id && x.Event=="document_uploaded"));
    }

    [Theory]
    [InlineData(false,true)][InlineData(true,false)]
    public async Task Ordinary_or_unconfigured_demo_documents_are_not_enrolled(bool demo,bool configured)
    {
        await using var h=await Shared.CreateAsync(fixture,demo);h.Retention.PurgeAfterDays=configured ? 7 : null;Assert.True(await h.UploadAsync(PdfFixtures.Create()));
        await using var db=fixture.Open();Assert.Null(await new UploadRetention(db,h.Retention,h.Time).ReadAsync(await h.StateAsync()));
    }

    [Fact]
    public async Task Legacy_document_is_not_silently_backfilled_or_replaced_when_new_policy_is_configured()
    {
        await using var h=await Shared.CreateAsync(fixture,demo:true);Assert.True(await h.UploadAsync(PdfFixtures.Create()));var saved=await h.StateAsync();h.Retention.PurgeAfterDays=7;
        await Assert.ThrowsAsync<DocumentRejectedException>(()=>h.UploadAsync(PdfFixtures.Create(1)));Assert.Equal(saved.RowVersion,(await h.StateAsync()).RowVersion);
        await using var db=fixture.Open();Assert.False(await db.DocumentRetentionSnapshots.AnyAsync(x=>x.EnvelopeId==h.Id));
    }

    [Fact]
    public async Task Replacement_at_exact_deadline_is_rejected_without_extending_or_replacing_the_saved_document()
    {
        await using var h=await Shared.CreateAsync(fixture,demo:true);var clock=new Clock();h.Time=clock;h.Retention.PurgeAfterDays=7;Assert.True(await h.UploadAsync(PdfFixtures.Create()));
        var row=await Read(h);var before=await h.StateAsync();clock.Now=row.DeleteAfter;
        await Assert.ThrowsAsync<DocumentRejectedException>(()=>h.UploadAsync(PdfFixtures.Create(1)));Assert.Equal(before.RowVersion,(await h.StateAsync()).RowVersion);
        Assert.Equal(UploadRetention.Digest(row),UploadRetention.Digest(await Read(h)));
    }

    [Fact]
    public async Task Deadline_crossed_during_first_upload_audit_rolls_back_the_snapshot_and_document()
    {
        await using var h=await Shared.CreateAsync(fixture,demo:true);var clock=new Clock();h.Time=clock;h.Retention.PurgeAfterDays=7;
        h.AuditFailure.AfterInsert=()=>clock.Now=clock.Now.AddDays(8);
        await Assert.ThrowsAsync<DocumentRejectedException>(()=>h.UploadAsync(PdfFixtures.Create()));Assert.Null((await h.StateAsync()).PdfBlob);
        await using var db=fixture.Open();Assert.False(await db.DocumentRetentionSnapshots.AnyAsync(x=>x.EnvelopeId==h.Id));Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==h.Id));
    }

    [Theory]
    [InlineData("snapshot")][InlineData("audit")]
    public async Task Admin_tampering_with_snapshot_or_first_upload_evidence_fails_closed(string kind)
    {
        await using var h=await Shared.CreateAsync(fixture,demo:true);h.Time=new Clock();h.Retention.PurgeAfterDays=7;Assert.True(await h.UploadAsync(PdfFixtures.Create()));
        await using var db=fixture.Open();
        if(kind=="snapshot")await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==h.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Days,8).SetProperty(x=>x.DeleteAfter,((Clock)h.Time).Now.AddDays(8)));
        else {
            var audit=await db.AuditEvents.AsNoTracking().SingleAsync(x=>x.EnvelopeId==h.Id && x.Event=="document_uploaded");var data=JsonNode.Parse(audit.DataJson)!;
            data["retentionSha256"]=new string('0',64);audit.DataJson=data.ToJsonString();audit.Hash=AuditHash.Compute(audit);
            await db.AuditEvents.Where(x=>x.Id==audit.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.DataJson,audit.DataJson).SetProperty(x=>x.Hash,audit.Hash));
        }
        var envelope=await h.StateAsync();await Assert.ThrowsAsync<InvalidDataException>(()=>new UploadRetention(db,h.Retention,h.Time).ReadAsync(envelope));
    }

    [Fact]
    public async Task Runtime_can_capture_and_read_but_cannot_update_or_delete_the_snapshot()
    {
        await using var h=await Shared.CreateAsync(fixture,demo:true);h.Time=new Clock();h.Retention.PurgeAfterDays=7;
        await using var db=fixture.Open();await db.Database.OpenConnectionAsync();var connection=(SqlConnection)db.Database.GetDbConnection();
        await using var command=connection.CreateCommand();command.CommandText="IF DATABASE_PRINCIPAL_ID('app_runtime') IS NULL CREATE USER [app_runtime] WITHOUT LOGIN";await command.ExecuteNonQueryAsync();
        await DatabasePermissions.GrantRuntimeAsync(connection);command.CommandText="EXECUTE AS USER = 'app_runtime'";await command.ExecuteNonQueryAsync();
        try
        {
            var options=new DocumentOptions();var service=new DocumentWorkflow(db,h.Store,new(options),options,new(db,h.Time),h.Time,NullLogger<DocumentWorkflow>.Instance,h.Retention);
            var bytes=PdfFixtures.Create();using var source=new MemoryStream(bytes);var before=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Id);
            Assert.True(await service.UploadAsync(h.Sender,h.PublicId,before.RowVersion,"Synthetic.pdf",source,bytes.Length,null,null,default));
            Assert.NotNull(await new UploadRetention(db,h.Retention,h.Time).ReadAsync(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Id)));
            await Assert.ThrowsAsync<SqlException>(()=>db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==h.Id).ExecuteDeleteAsync());
            await Assert.ThrowsAsync<SqlException>(()=>db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==h.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PolicyVersion,"changed")));
        }
        finally {command.CommandText="REVERT";await command.ExecuteNonQueryAsync();}
        db.ChangeTracker.Clear();var row=await db.DocumentRetentionSnapshots.SingleAsync(x=>x.EnvelopeId==h.Id);row.Days=8;
        await Assert.ThrowsAsync<InvalidOperationException>(()=>db.SaveChangesAsync());db.ChangeTracker.Clear();
        db.Remove(await db.DocumentRetentionSnapshots.SingleAsync(x=>x.EnvelopeId==h.Id));await Assert.ThrowsAsync<InvalidOperationException>(()=>db.SaveChangesAsync());
    }

    [Fact]
    public async Task Enrolled_document_cannot_publish_using_the_old_completion_based_retention_interval()
    {
        await using var h=await Shared.CreateAsync(fixture,demo:true);h.Time=new Clock();h.Retention.PurgeAfterDays=7;Assert.True(await h.UploadAsync(PdfFixtures.Create()));
        await using var db=fixture.Open();var publication=new CompletionPublication(db,null!,null!,null!,null!,new(db,h.Time),h.Time,new(),null!);
        await Assert.ThrowsAsync<CompletionPublicationUnavailableException>(()=>publication.PublishAsync(h.Id));
    }

    private async Task<DocumentRetentionSnapshot> Read(Shared h)
    {
        await using var db=fixture.Open();return (await new UploadRetention(db,h.Retention,h.Time).ReadAsync(await h.StateAsync()))!;
    }
    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now=new(2028,2,28,23,59,59,TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow()=>Now;
    }
}
