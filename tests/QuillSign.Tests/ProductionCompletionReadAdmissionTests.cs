using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Lifecycle;

namespace QuillSign.Tests;

public sealed class ProductionCompletionReadAdmissionTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData("valid")][InlineData("unsettled")][InlineData("used-clock")][InlineData("rehashed-expiry")][InlineData("extra-issued")]
    public void Current_consumed_token_history_joins_original_issuance_and_exact_recorded_consumption_without_rewinding_rows(string fault)
    {
        // Factual graph unit; no claim of a provider or new whole signing flow.
        var at=new DateTimeOffset(2030,1,1,12,0,0,TimeSpan.Zero);var envelope=new Envelope{SenderEmail="synthetic@example.invalid",Status=EnvelopeStatus.Completed,PurgeAfter=at.AddDays(7)};
        var result=new CompletionPublicationResult{EnvelopeId=envelope.Id,CompletedAt=at.AddMinutes(-1),RowVersion=[0,0,0,0,0,0,0,1],RecipeSha256=new byte[32]};
        var member=CompletionAccessState.PartyProjection(envelope.Id,result.Id,result.RowVersion,PartyType.Sender,null,envelope.SenderEmail,null,null);
        var token=new AuthToken{EnvelopeId=envelope.Id,PartyType=PartyType.Sender,Email=envelope.SenderEmail,Purpose=TokenPurpose.CompletionAccess,CompletionPublicationId=result.Id,
            CompletionRecipeSha256=result.RecipeSha256,CompletionPartySha256=member.Sha256,TokenSha256=new byte[32],ExpiresAt=at.AddHours(24),UsedAt=at.AddSeconds(1),RowVersion=[0,0,0,0,0,0,0,2]};
        var identity=new CompletionReaderIdentity(token.Id,Convert.ToBase64String(token.RowVersion),envelope.Id,envelope.PublicId,PartyType.Sender,null,token.Email,result.Id,new('0',64),
            Convert.ToHexStringLower(member.Sha256),Guid.NewGuid(),token.UsedAt.Value,at.AddHours(1));
        AuditEvent Audit(int sequence,string name,string data,PartyType party,string? email,DateTimeOffset time){var a=new AuditEvent{Id=sequence,EnvelopeId=envelope.Id,Sequence=sequence,Event=name,DataJson=data,ActorType=party,ActorEmail=email,At=time};a.Hash=AuditHash.Compute(a);return a;}
        var audits=new List<AuditEvent>{Audit(1,"completion_access_issued",CompletionAccess.Issued(token),PartyType.System,null,at),Audit(2,"completion_access_redeemed",CompletionAccess.Consumed(identity),PartyType.Sender,token.Email,identity.RedeemedAt)};
        var hash=new string('a',64);var issued=Guid.NewGuid();var consumed=Guid.NewGuid();
        var state=new HoldWitnessState(8,hash,0,null,null,null,new Dictionary<Guid,HoldWitnessHold>(),hash,new Dictionary<Guid,string>{{issued,ProductionCompletionReadAdmission.Receipt(envelope.Id,issued,"completion/issue",token.Id.ToString("N"))},{consumed,ProductionCompletionReadAdmission.Receipt(envelope.Id,consumed,"completion/redeem",token.Id.ToString("N"))}},true,hash,
            new Dictionary<Guid,HoldWitnessOperation>{{issued,new(issued,"completion/issue",token.Id.ToString("N"),0,null,hash,hash,1)},{consumed,new(consumed,"completion/redeem",token.Id.ToString("N"),0,null,hash,hash,4)}},
            new Dictionary<Guid,HoldWitnessOutcome>{{issued,new(hash,hash,3)},{consumed,new(hash,hash,7)}});
        if(fault=="unsettled")state=state with{SettledOperations=new Dictionary<Guid,string>{{issued,hash}}};
        if(fault=="used-clock")token.UsedAt=token.UsedAt.Value.AddTicks(1);
        if(fault=="rehashed-expiry"){identity=identity with{ExpiresAt=at.AddDays(2)};audits[1]=Audit(2,"completion_access_redeemed",CompletionAccess.Consumed(identity),PartyType.Sender,token.Email,identity.RedeemedAt);}
        if(fault=="extra-issued")audits.Add(Audit(3,"completion_access_issued","{}",PartyType.System,null,at));
        using var sql=JsonDocument.Parse(JsonSerializer.Serialize(new{RecordId=envelope.Id,CapturedAt=at.AddMinutes(1),Tables=new object[]{new{Table="Envelopes",Rows=new[]{envelope}},new{Table="CompletionPublicationResults",Rows=new[]{result}},
            new{Table="Signers",Rows=Array.Empty<Signer>()},new{Table="Recipients",Rows=Array.Empty<Recipient>()},new{Table="AuthTokens",Rows=new[]{token}},new{Table="AuditEvents",Rows=audits}}},new JsonSerializerOptions{Converters={new System.Text.Json.Serialization.JsonStringEnumConverter()}}));
        if(fault=="valid"){var history=ProductionHoldCompletionAccessReferences.ReadVerified(sql.RootElement,state);Assert.Equal(token.Id,Assert.Single(history.Tokens));Assert.Equal(2,history.Audits.Count);Assert.NotNull(token.UsedAt);}
        else Assert.Throws<InvalidDataException>(()=>ProductionHoldCompletionAccessReferences.ReadVerified(sql.RootElement,state));
    }
    [Fact]
    public async Task Same_parent_access_outcome_settles_exact_committed_SQL_and_pending_hold_blocks_new_actions()
    {
        var run=await ProductionRecordOperationAdmissionTests.Run.Create(fixture,false);var operations=run.Gate();await operations.InitializeAsync(run.Id);
        var access=new ProductionCompletionReadAdmission(operations,run.Clock);
        ProductionRecordOperation? scope;
        await using(var db=fixture.Open())
        {
            await using var tx=await db.Database.BeginTransactionAsync();
            scope=await access.BeginLockedAsync(db,run.Id,"completion/issue",Guid.NewGuid().ToString("N"),default);Assert.NotNull(scope);
            await db.Envelopes.Where(x=>x.Id==run.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Message,"Exact component access result"));
            await access.OutcomeLockedAsync(db,scope,default);await tx.CommitAsync();
        }
        await access.CompleteAsync(scope,default);Assert.Null((await run.Journal().ReadAsync(run.Id)).OutstandingOperation);
        await access.DemandAsync(run.Id,run.Clock.Now.AddMinutes(1),default);
        var command=ProductionHoldWitnessJournalTests.Place(run.Id);
        await run.Journal().IntentAsync(ProductionHoldWitnessJournalTests.Authority(run.Clock,command.Permission),ProductionHoldWitnessJournalTests.Operators,command,Guid.NewGuid());
        await Assert.ThrowsAsync<InvalidDataException>(()=>access.DemandAsync(run.Id,run.Clock.Now.AddMinutes(1),default));
        await using var blocked=fixture.Open();await using var parent=await blocked.Database.BeginTransactionAsync();
        await Assert.ThrowsAsync<InvalidDataException>(()=>access.BeginLockedAsync(blocked,run.Id,"completion/redeem",Guid.NewGuid().ToString("N"),default));
        Assert.False(blocked.ChangeTracker.HasChanges());Assert.Null((await run.Journal().ReadAsync(run.Id)).OutstandingOperation);
        await parent.RollbackAsync();await parent.DisposeAsync();
        // Actual public issuance refuses before resolving any completion provider.
        var state=new CompletionAccessState(blocked,null!,()=>throw new InvalidOperationException("Unexpected provider"),run.Clock);
        var service=new CompletionAccess(blocked,state,new(run.Keys,run.Clock),new(),new(blocked,run.Clock),run.Clock,()=>throw new InvalidOperationException("Unexpected provider")){HoldAdmission=access};
        var count=await blocked.AuthTokens.CountAsync();
        await Assert.ThrowsAsync<InvalidDataException>(()=>service.IssueAsync(run.Id,PartyType.Sender,null));
        Assert.Equal(count,await blocked.AuthTokens.CountAsync());Assert.Null(blocked.Database.CurrentTransaction);
    }

    [Fact]
    public async Task Hold_arriving_after_first_provider_read_refuses_before_second_read_without_nested_parent()
    {
        var run=await ProductionRecordOperationAdmissionTests.Run.Create(fixture,false);await run.Gate().InitializeAsync(run.Id);
        var access=new ProductionCompletionReadAdmission(run.Gate(),run.Clock);var until=run.Clock.Now.AddMinutes(1);var calls=0;
        await using var db=fixture.Open();await using var tx=await db.Database.BeginTransactionAsync();
        using var restriction=CompletionReadRestriction.Enter(db,()=>access.DemandLockedAsync(db,run.Id,until,default));
        await Assert.ThrowsAsync<InvalidDataException>(async()=>{
            await CompletionReadRestriction.ReadAsync(db,async()=>{
                calls++;var command=ProductionHoldWitnessJournalTests.Place(run.Id);
                await run.Journal().IntentAsync(ProductionHoldWitnessJournalTests.Authority(run.Clock,command.Permission),ProductionHoldWitnessJournalTests.Operators,command,Guid.NewGuid());
            });
            await CompletionReadRestriction.ReadAsync(db,()=>{calls++;return Task.CompletedTask;});
        });
        Assert.Equal(1,calls);Assert.Same(tx,db.Database.CurrentTransaction);Assert.False(db.ChangeTracker.HasChanges());
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Original_deadline_or_changed_SQL_cannot_be_adopted_by_read_authority(bool deadline)
    {
        var run=await ProductionRecordOperationAdmissionTests.Run.Create(fixture,false);await run.Gate().InitializeAsync(run.Id);
        var access=new ProductionCompletionReadAdmission(run.Gate(),run.Clock);var until=run.Clock.Now.AddSeconds(1);
        if(deadline)run.Clock.Now=until;else await run.Edit("Unknown restored state");
        await Assert.ThrowsAsync<InvalidDataException>(()=>access.DemandAsync(run.Id,until,default));
        Assert.Null((await run.Journal().ReadAsync(run.Id)).OutstandingOperation);
    }

    [Theory]
    [InlineData("valid")][InlineData("revision")][InlineData("owner")][InlineData("party")][InlineData("recipe")]
    [InlineData("deadline")][InlineData("future")][InlineData("duplicate")][InlineData("missing")]
    public void Consumed_scope_uses_exact_recorded_token_revision_and_producer_fields_without_cookie_reconstruction(string fault)
    {
        var now=new DateTimeOffset(2030,1,1,12,0,0,TimeSpan.Zero);var id=Guid.NewGuid();
        var token=new AuthToken{EnvelopeId=id,Purpose=TokenPurpose.CompletionAccess,PartyType=PartyType.Sender,Email="synthetic@example.invalid",CompletionPublicationId=Guid.NewGuid(),
            CompletionRecipeSha256=new byte[32],CompletionPartySha256=new byte[32],RowVersion=[0,0,0,0,0,0,0,8],UsedAt=now,ExpiresAt=now.AddHours(24)};
        var identity=new CompletionReaderIdentity(token.Id,Convert.ToBase64String(token.RowVersion),id,id.ToString("N"),token.PartyType,null,token.Email,
            token.CompletionPublicationId.Value,new('0',64),new('0',64),Guid.NewGuid(),now,now.AddHours(1));
        var original=CompletionAccess.Consumed(identity);var node=JsonNode.Parse(original)!.AsObject();
        switch(fault){
            case "revision":node["TokenRevision"]=Convert.ToBase64String(new byte[8]);break;
            case "owner":node["EnvelopeId"]=Guid.NewGuid();break;
            case "party":node["party"]="Signer";break;
            case "recipe":node["RecipeSha256"]=new string('a',64);break;
            case "deadline":node["RedeemedAt"]=now.AddTicks(1);break;
            case "future":node["Future"]=true;break;
            case "missing":node.Remove("SessionId");break;
        }
        var value=fault=="duplicate"?original[..^1]+",\"SessionId\":\""+Guid.NewGuid()+"\"}":node.ToJsonString();
        if(fault=="valid")Assert.Equal(identity,ProductionHoldCompletionAccessReferences.ReadConsumption(original,token,id.ToString("N")));
        else Assert.True(Record.Exception(()=>ProductionHoldCompletionAccessReferences.ReadConsumption(value,token,id.ToString("N"))) is InvalidDataException or KeyNotFoundException);
        Assert.DoesNotContain("cookie",original,StringComparison.OrdinalIgnoreCase);Assert.DoesNotContain("Receipt",original,StringComparison.Ordinal);
    }
}
