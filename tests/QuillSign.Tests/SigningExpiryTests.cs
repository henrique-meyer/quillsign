using System.Text.Json;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using QuillSign.Data;
using QuillSign.Signing;
using Shared=QuillSign.Tests.SendDraftWorkflowTests.Harness;

namespace QuillSign.Tests;

public sealed class SigningExpiryTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Invalid_batch_bounds_cursors_and_pre_cancelled_calls_never_open_the_database()
    {
        await using var db=fixture.Open();var clock=TimeProvider.System;var service=new SigningExpiry(db,new(db,clock),new(db,clock),clock);
        foreach(var count in new[]{0,-1,65})await Assert.ThrowsAsync<ArgumentOutOfRangeException>(()=>service.RunBatchAsync(count));
        foreach(var cursor in new[]{"","invalid","0.00000000000000000000000000000000",new string('.',10000),"9223372036854775807.11111111111111111111111111111111"})
            await Assert.ThrowsAsync<ArgumentException>(()=>service.RunBatchAsync(cursor:cursor));
        using var cancelled=new CancellationTokenSource();cancelled.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>service.RunBatchAsync(ct:cancelled.Token));
        Assert.Equal(SigningExpiryOutcome.Missing,(await service.ExpireAsync(Guid.Empty)).Outcome);Assert.Equal(System.Data.ConnectionState.Closed,db.Database.GetDbConnection().State);
    }
    [Theory]
    [InlineData(-1)][InlineData(0)][InlineData(1)]
    public async Task UTC_deadline_is_exact_and_one_record_preserves_frozen_sources_and_party_evidence(int ticks)
    {
        await using var h=await Shared.Create(fixture);Assert.NotNull(await h.Send());var before=await Frozen(h.Envelope.Id);var writes=h.Blobs.Created.Count;
        h.Clock.Advance(h.Envelope.ExpiresAt!.Value-h.Clock.GetUtcNow()+TimeSpan.FromTicks(ticks));
        var result=await Expire(h);Assert.Equal(ticks<0 ? SigningExpiryOutcome.NotDue : SigningExpiryOutcome.Expired,result.Outcome);
        Assert.Equal(before,await Frozen(h.Envelope.Id));Assert.Equal(writes,h.Blobs.Created.Count);Assert.Empty(h.Blobs.Deleted);
        await using var db=fixture.Open();var rows=await db.AuditEvents.Where(x=>x.EnvelopeId==h.Envelope.Id && x.Event=="expired").ToArrayAsync();
        if(ticks<0)Assert.Empty(rows);else {
            var row=Assert.Single(rows);Assert.Equal(PartyType.System,row.ActorType);Assert.Null(row.ActorEmail);Assert.Equal(AuditHash.Compute(row),row.Hash);
            Assert.Equal(h.Clock.GetUtcNow(),result.ExpiredAt);var replay=await Expire(h);Assert.Equal(SigningExpiryOutcome.AlreadyExpired,replay.Outcome);Assert.Equal(result.ExpiredAt,replay.ExpiredAt);
            Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==h.Envelope.Id && x.Event=="expired").ToArrayAsync());
            Assert.True(await h.Once());Assert.Equal(0,h.Sender.Calls); // queued invitation cannot dispatch
        }
    }
    [Fact]
    public async Task Concurrent_maintenance_records_exactly_one_expiration_and_unused_invitation_authority_is_revoked()
    {
        await using var h=await Shared.Create(fixture);Assert.NotNull(await h.Send());Assert.True(await h.Once());
        await using(var db=fixture.Open())await db.AuthTokens.Where(x=>x.EnvelopeId==h.Envelope.Id && x.Purpose==TokenPurpose.SignerAccess)
            .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ExpiresAt,h.Envelope.ExpiresAt!.Value.AddDays(1)));
        h.Clock.Advance(TimeSpan.FromDays(31));var results=await Task.WhenAll(Expire(h),Expire(h));
        Assert.Single(results,x=>x.Outcome==SigningExpiryOutcome.Expired);Assert.Single(results,x=>x.Outcome==SigningExpiryOutcome.AlreadyExpired);
        await using var check=fixture.Open();Assert.All(await check.AuthTokens.Where(x=>x.EnvelopeId==h.Envelope.Id && x.Purpose==TokenPurpose.SignerAccess).ToArrayAsync(),x=>Assert.Equal(h.Clock.GetUtcNow(),x.ExpiresAt));
        Assert.Equal(results[0].ExpiredAt,results[1].ExpiredAt);
    }
    [Theory]
    [InlineData(EnvelopeStatus.Draft)][InlineData(EnvelopeStatus.Voided)][InlineData(EnvelopeStatus.Declined)][InlineData(EnvelopeStatus.Completed)]
    public async Task Another_terminal_state_or_a_draft_is_never_overwritten(EnvelopeStatus status)
    {
        await using var h=await Shared.Create(fixture);Assert.NotNull(await h.Send());
        await using(var db=fixture.Open())await db.Envelopes.Where(x=>x.Id==h.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,status));
        h.Clock.Advance(TimeSpan.FromDays(31));Assert.Equal(SigningExpiryOutcome.Closed,(await Expire(h)).Outcome);
        await using var check=fixture.Open();Assert.Equal(status,(await check.Envelopes.SingleAsync(x=>x.Id==h.Envelope.Id)).Status);Assert.False(await check.AuditEvents.AnyAsync(x=>x.EnvelopeId==h.Envelope.Id && x.Event=="expired"));
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Audit_failure_rolls_back_and_unknown_commit_resolves_only_from_saved_state(bool unknown)
    {
        await using var h=await Shared.Create(fixture);Assert.NotNull(await h.Send());h.Clock.Advance(TimeSpan.FromDays(31));
        await using var original=fixture.Open();var options=new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(original.Database.GetConnectionString()).AddInterceptors(new Faults(unknown));await using var db=new QuillSignDbContext(options.Options);
        var service=new SigningExpiry(db,new(db,h.Clock),new(db,h.Clock),h.Clock);
        if(unknown)await Assert.ThrowsAsync<IOException>(()=>service.ExpireAsync(h.Envelope.Id));else await Assert.ThrowsAsync<DbUpdateException>(()=>service.ExpireAsync(h.Envelope.Id));
        Assert.Empty(db.ChangeTracker.Entries());await db.SaveChangesAsync();
        var result=await Expire(h);Assert.Equal(unknown ? SigningExpiryOutcome.AlreadyExpired : SigningExpiryOutcome.Expired,result.Outcome);
        await using var check=fixture.Open();Assert.Single(await check.AuditEvents.Where(x=>x.EnvelopeId==h.Envelope.Id && x.Event=="expired").ToArrayAsync());
    }
    [Fact]
    public async Task Broken_source_or_replayed_expiry_evidence_cannot_manufacture_a_confirmed_expiration()
    {
        await using var h=await Shared.Create(fixture);Assert.NotNull(await h.Send());h.Clock.Advance(TimeSpan.FromDays(31));
        await using var db=fixture.Open();var original=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Envelope.Id);
        await db.Envelopes.Where(x=>x.Id==h.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SentPdfSha256,new byte[32]));await Assert.ThrowsAsync<InvalidDataException>(()=>Expire(h));
        await db.Envelopes.Where(x=>x.Id==h.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SentPdfSha256,original.SentPdfSha256));Assert.Equal(SigningExpiryOutcome.Expired,(await Expire(h)).Outcome);
        await db.AuditEvents.Where(x=>x.EnvelopeId==h.Envelope.Id && x.Event=="expired").ExecuteUpdateAsync(s=>s.SetProperty(x=>x.DataJson,"{}"));await Assert.ThrowsAsync<InvalidDataException>(()=>Expire(h));
    }
    [Fact]
    public async Task Bounded_batches_continue_past_a_bad_record_without_creating_jobs_or_starving_other_due_requests()
    {
        var isolated=new SqlDatabaseFixture();await isolated.InitializeAsync();
        try {
        await using var first=await Shared.Create(isolated);await using var second=await Shared.Create(isolated);await using var third=await Shared.Create(isolated);
        foreach(var h in new[]{first,second,third})Assert.NotNull(await h.Send());first.Clock.Advance(TimeSpan.FromDays(31));
        await using var db=isolated.Open();var broken=await db.Envelopes.AsNoTracking().Where(x=>x.Status==EnvelopeStatus.Sent).OrderBy(x=>x.ExpiresAt).ThenBy(x=>x.Id).FirstAsync();
        await db.Envelopes.Where(x=>x.Id==broken.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SentPdfSha256,new byte[32]));
        var work=await db.WorkItems.CountAsync();var mail=await db.EmailOutbox.CountAsync();var expiry=new SigningExpiry(db,new(db,first.Clock),new(db,first.Clock),first.Clock);
        var a=await expiry.RunBatchAsync(1);Assert.Equal(1,a.Examined);Assert.Equal(1,a.Failed);Assert.NotNull(a.NextCursor);
        var b=await expiry.RunBatchAsync(1,a.NextCursor);Assert.Equal(1,b.Expired);Assert.NotNull(b.NextCursor);
        var c=await expiry.RunBatchAsync(1,b.NextCursor);Assert.Equal(1,c.Expired);Assert.Null(c.NextCursor);
        Assert.Equal(work,await db.WorkItems.CountAsync());Assert.Equal(mail,await db.EmailOutbox.CountAsync());
        await db.Envelopes.Where(x=>x.Id==broken.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SentPdfSha256,broken.SentPdfSha256));
        } finally {await isolated.DisposeAsync();}
    }
    [Fact]
    public async Task Restricted_runtime_can_expire_and_read_canonical_replay_without_mutating_audit_history()
    {
        await using var h=await Shared.Create(fixture);Assert.NotNull(await h.Send());h.Clock.Advance(TimeSpan.FromDays(31));await using var db=fixture.Open();await db.Database.OpenConnectionAsync();
        var connection=(SqlConnection)db.Database.GetDbConnection();await using var command=connection.CreateCommand();command.CommandText="IF DATABASE_PRINCIPAL_ID('app_runtime') IS NULL CREATE USER [app_runtime] WITHOUT LOGIN";await command.ExecuteNonQueryAsync();
        await DatabasePermissions.GrantRuntimeAsync(connection);command.CommandText="EXECUTE AS USER = 'app_runtime'";await command.ExecuteNonQueryAsync();
        try {var service=new SigningExpiry(db,new(db,h.Clock),new(db,h.Clock),h.Clock);Assert.Equal(SigningExpiryOutcome.Expired,(await service.ExpireAsync(h.Envelope.Id)).Outcome);Assert.Equal(SigningExpiryOutcome.AlreadyExpired,(await service.ExpireAsync(h.Envelope.Id)).Outcome);
            command.CommandText="DELETE FROM [AuditEvents]";Assert.Equal(229,(await Assert.ThrowsAsync<SqlException>(async ()=>await command.ExecuteNonQueryAsync())).Number);
        } finally {command.CommandText="REVERT";await command.ExecuteNonQueryAsync();}
    }
    private async Task<SigningExpiryResult> Expire(Shared h) {await using var db=fixture.Open();return await new SigningExpiry(db,new(db,h.Clock),new(db,h.Clock),h.Clock).ExpireAsync(h.Envelope.Id);}
    private async Task<string> Frozen(Guid id) {await using var db=fixture.Open();var e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==id);return JsonSerializer.Serialize(new {e.SentPdfBlob,e.SentPdfSha256,e.ErsdSha256,e.CurrentCopyVersion,e.CurrentFinishId,e.ExpiresAt,e.PurgeAfter,
        signers=await db.Signers.AsNoTracking().Where(x=>x.EnvelopeId==id).OrderBy(x=>x.Id).ToArrayAsync(),fields=await db.Fields.AsNoTracking().Where(x=>x.EnvelopeId==id).OrderBy(x=>x.Id).ToArrayAsync()});}
    private sealed class Faults(bool unknown):DbTransactionInterceptor,ISaveChangesInterceptor {
        private bool armed;
        public ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData e,InterceptionResult<int> result,CancellationToken ct=default) {
            if(e.Context!.ChangeTracker.Entries<AuditEvent>().Any(x=>x.State==EntityState.Added && x.Entity.Event=="expired")) {armed=true;if(!unknown)throw new DbUpdateException("Synthetic expiry audit rollback");}return ValueTask.FromResult(result);
        }
        public override Task TransactionCommittedAsync(System.Data.Common.DbTransaction transaction,TransactionEndEventData e,CancellationToken ct=default) {if(armed)throw new IOException("Synthetic lost expiry acknowledgement");return Task.CompletedTask;}
    }
}
