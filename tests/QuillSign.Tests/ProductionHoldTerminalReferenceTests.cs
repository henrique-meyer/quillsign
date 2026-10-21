using System.Data.Common;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class ProductionHoldTerminalReferenceTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData("void")][InlineData("decline")][InlineData("expire")]
    public async Task Actual_terminal_producers_and_original_anchor_join_the_unchanged_preterminal_bundle(string action)
    {
        var ready=await ProductionRecordSendAdmissionTests.Ready.Create(fixture,requestedDeadline:action=="expire");
        await using var run=new ProductionInvitationWorkerAdmissionTests.Delivered(fixture,ready){WorkId=(await ready.Send())!.InvitationWorkId};
        VerifiedSigner? signer=null;
        if(action!="expire")
        {await run.ClaimAsync();Assert.Equal(WorkOutcome.Completed,(await run.ExecuteAsync()).Outcome);await run.FinishAsync();}
        if(action=="decline")signer=await new ProductionSignerMutationAdmissionTests(fixture).Redeem(run);
        Envelope original;string connection;
        await using(var source=fixture.Open()){original=await source.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==run.Record.Id);connection=source.Database.GetConnectionString()!;}
        if(action=="expire")run.Record.Time.Now=original.ExpiresAt!.Value.AddSeconds(1);
        // Explicit fixture operation seals the ordinary producer's actual SQL
        // before commit. Runtime terminal-hook acceptance is tested separately.
        var operation=await run.Record.Admission.BeginAsync(run.Record.Id,Guid.NewGuid(),"test/terminal-history",action);
        await using(var db=new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(connection).AddInterceptors(new Expected(run.Record.Admission,operation)).Options))
        {
            var audit=new AuditWriter(db,run.Record.Time);var checkpoints=new SignerCheckpointState(db,run.Record.Time);
            if(action=="void")Assert.Equal(SenderVoidOutcome.Voided,(await new SenderVoid(db,checkpoints,audit,run.Record.Time).VoidAsync(ready.Prepared.Sender,original.PublicId,run.Record.Time.Now.AddHours(1),original.RowVersion,true,SenderVoidStatement.Version,"Synthetic terminal",null,null)).Outcome);
            else if(action=="expire")Assert.Equal(SigningExpiryOutcome.Expired,(await new SigningExpiry(db,checkpoints,audit,run.Record.Time).ExpireAsync(run.Record.Id)).Outcome);
            else
            {
                var access=new SignerAccess(db,new(db,run.Record.Time),new(),run.Record.Time);
                var consent=new SignerConsent(db,access,new(run.Record.Keys,run.Record.Time),audit,new(db,()=>ready.Signals,new(){Enabled=true},new(run.Record.Keys),run.Record.Time),run.Record.Time);
                Assert.NotNull(await consent.DeclineAsync(SignerAccessConfiguration.Principal(signer!),original.PublicId,"Synthetic terminal",null,null));
            }
        }
        await run.Record.Admission.CompleteAsync(operation,Convert.ToHexStringLower(SHA256.HashData("synthetic-terminal-history"u8)));
        var command=ProductionHoldWitnessJournalTests.Place(run.Record.Id);
        using var holds=new ProductionSignerMutationAdmissionTests.Holds(fixture,run);
        var state=await holds.Coordinator().SubmitAsync(ProductionHoldWitnessJournalTests.Authority(run.Record.Time,command.Permission),ProductionHoldWitnessJournalTests.Operators,command);
        await using var capture=fixture.Open();await using var tx=await capture.Database.BeginTransactionAsync();
        var snapshot=await new ProductionHoldObjectInventory(capture,run.Record.Keys,run.Record.Time,ready.Prepared.Blobs).CaptureLockedAsync(run.Record.Id,state.RequestRevision,state.RequestFenceHash!);
        using var sql=ProductionHoldSqlInventory.OpenVerified(snapshot.Sql,run.Record.Keys);var objects=ProductionHoldObjectInventory.OpenVerified(snapshot,run.Record.Keys,run.Record.Time);
        var result=await ProductionHoldTerminalReferences.ReadVerifiedLockedAsync(capture,sql.RootElement,objects,run.Record.Keys,[],state,run.Record.Time);
        Assert.Empty(result.Reviews);Assert.Empty(result.Previews);
        var tables=sql.RootElement.GetProperty("Tables").EnumerateArray().ToDictionary(x=>x.GetProperty("Table").GetString()!,x=>x.GetProperty("Rows"));
        var status=action=="void"?"Voided":action=="decline"?"Declined":"Expired";
        Assert.Equal(status,tables["Envelopes"][0].GetProperty("Status").GetString());Assert.Single(tables["ProductionRetentionTerminals"].EnumerateArray());
        var node=JsonNode.Parse(sql.RootElement.GetRawText())!;
        node["Tables"]!.AsArray().Single(x=>x!["Table"]!.GetValue<string>()=="ProductionRetentionTerminals")!["Rows"]![0]!["OriginalAt"]=run.Record.Time.Now.AddDays(1);
        using var changed=JsonDocument.Parse(node.ToJsonString());
        await Assert.ThrowsAsync<InvalidDataException>(()=>ProductionHoldTerminalReferences.ReadVerifiedLockedAsync(capture,changed.RootElement,objects,run.Record.Keys,[],state,run.Record.Time));
        Assert.Null((await run.Record.Journal.ReadAsync(run.Record.Id)).OutstandingOperation);
    }
    private sealed class Expected(ProductionRecordOperationAdmission operations,ProductionRecordOperation scope):DbTransactionInterceptor
    {
        public override async ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction transaction,TransactionEventData data,InterceptionResult result,CancellationToken ct=default)
        {await operations.PrepareOutcomeLockedAsync((QuillSignDbContext)data.Context!,scope,ct);return result;}
    }
}
