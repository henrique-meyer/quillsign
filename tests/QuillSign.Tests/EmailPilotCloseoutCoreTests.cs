using System.Data.Common;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class EmailPilotCloseoutCoreTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    private static readonly JsonSerializerOptions Json=new(){Converters={new JsonStringEnumConverter()}};
    private static string Raw<T>(T value)=>JsonSerializer.Serialize(value,Json);

    [Theory]
    [InlineData("work-body")][InlineData("work-version")][InlineData("mail-body")][InlineData("mail-version")][InlineData("recipient")][InlineData("due")]
    public void Before_claim_exact_original_pair_rejects_substitution(string fault)
    {
        var (known,mail,item)=Pair();EmailPilotCloseout.DemandQueuedPair(known,mail,item);
        switch(fault) {
            case "work-body":item.PayloadJson+=" ";break;case "work-version":item.RowVersion[0]^=1;break;
            case "mail-body":mail.PayloadJson+=" ";break;case "mail-version":mail.RowVersion[0]^=1;break;
            case "recipient":mail.To="other@example.invalid";break;case "due":item.AvailableAt=item.AvailableAt.AddSeconds(1);break;
        }
        Assert.Throws<InvalidDataException>(()=>EmailPilotCloseout.DemandQueuedPair(known,mail,item));
    }

    [Fact]
    public void After_claim_only_ordinary_completion_token_binding_may_change_payload()
    {
        var keys=new EphemeralDataProtectionProvider();var codec=new CompletionNotificationProtection(keys);
        var (known,mail,item)=Pair();var p=new CompletionNotificationPayload(CompletionNotificationJobs.Version,mail.EnvelopeId!.Value,Guid.NewGuid(),new string('a',64),Convert.ToBase64String(new byte[8]),
            PartyType.Sender,null,new string('b',64),new string('c',64),new string('d',64),true);
        mail.Template=CompletionNotificationJobs.Template;mail.PayloadJson=codec.Protect(p);known=known with{Step=EmailPilotCloseoutStep.CompletionSender,MailJson=Raw(mail)};
        item.Status=WorkStatus.Leased;item.Attempts=1;item.LeaseOwner=Guid.NewGuid();item.LeaseExpiresAt=item.AvailableAt.AddMinutes(5);item.RowVersion=[1,2,3,4,5,6,7,9];
        mail.Attempts=1;mail.SubmissionStartedAt=item.AvailableAt.AddSeconds(1);mail.RowVersion=[1,2,3,4,5,6,7,9];mail.PayloadJson=codec.Protect(p with{LastTokenId=Guid.NewGuid()});
        EmailPilotCloseout.DemandOriginalQueue(known,mail,item,codec);
        mail.PayloadJson=codec.Protect(p with{LastTokenId=Guid.NewGuid(),PublicationId=Guid.NewGuid()});
        Assert.Throws<InvalidDataException>(()=>EmailPilotCloseout.DemandOriginalQueue(known,mail,item,codec));
    }

    [Theory]
    [InlineData("work-body")][InlineData("template")][InlineData("recipient")][InlineData("attachments")][InlineData("mail-body")]
    public void After_claim_preserves_all_original_void_body_and_delivery_scope(string fault)
    {
        var (known,mail,item)=Pair();EmailPilotCloseout.DemandOriginalQueue(known,mail,item,null);
        switch(fault){case "work-body":item.PayloadJson+=" ";break;case "template":mail.Template="sender-verification";break;
            case "recipient":mail.To="other@example.invalid";break;case "attachments":mail.AttachmentsJson="[1]";break;case "mail-body":mail.PayloadJson+=" ";break;}
        Assert.Throws<InvalidDataException>(()=>EmailPilotCloseout.DemandOriginalQueue(known,mail,item,null));
    }

    [Theory]
    [InlineData("window")][InlineData("parent")][InlineData("same-record")][InlineData("work")][InlineData("utc")][InlineData("capability")]
    public void Closed_configuration_rejects_expansion_or_ambiguous_identity(string fault)
    {
        var o=Options();o.Validate();var before=o.Capture();
        switch(fault){case "window":o.Until=o.StartsAt.AddMinutes(30).AddTicks(1);break;case "parent":o.AccountingParentRunIds=[o.CompletionParentRunId,o.CompletionParentRunId];break;
            case "same-record":o.DeclineRecordId=o.CompletionRecordId;break;case "work":o.VoidWorkIds[0]=o.CompletionWorkIds[0];break;
            case "utc":o.StartsAt=o.StartsAt.ToOffset(TimeSpan.FromHours(1));break;case "capability":o.CapabilitySha256="";break;}
        Assert.Throws<InvalidOperationException>(o.Validate);Assert.Equal(10,EmailPilotCloseoutLimits.ApplicationAttempts);
        Assert.Equal(31429362,EmailPilotCloseoutLimits.EncodedBytes);Assert.Equal(12,EmailPilotCloseoutLimits.PriorApplicationAttempts);
        Assert.NotEqual(Guid.Empty,before.AuthorizationId);
    }

    [Fact]
    public void Default_disabled_runtime_composes_without_resolving_SQL_or_transport()
    {
        var services=new ServiceCollection();services.AddSingleton(new EmailOptions());services.AddSingleton(new WorkOptions());
        services.AddRestrictedEmailPilotRuntime(new ConfigurationBuilder().Build());using var provider=services.BuildServiceProvider();using var scope=provider.CreateScope();
        Assert.False(scope.ServiceProvider.GetRequiredService<EmailPilotCloseout>().Available);
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<EmailPilotEnvelopeAccess>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<EmailPilotWorkAuthority>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<EmailPilotSender>());
    }

    [Fact]
    public async Task Unknown_counter_commit_ack_retains_exact_consumed_row_and_prevents_second_step()
    {
        await using var owner=fixture.Open();var h=Header();owner.Add(h);await owner.SaveChangesAsync();
        var options=new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(owner.Database.GetConnectionString()).AddInterceptors(new LostAcknowledgement()).Options;
        var original=Operation(h.Id);
        await using(var db=new QuillSignDbContext(options)) {
            await using var tx=await db.Database.BeginTransactionAsync();db.Add(original);await db.SaveChangesAsync();
            await Assert.ThrowsAsync<IOException>(()=>tx.CommitAsync());
        }
        var observed=await owner.EmailPilotCloseoutOperations.AsNoTracking().SingleAsync(x=>x.Id==original.Id);
        Assert.Equal(original.EncodedBytes,observed.EncodedBytes);Assert.Equal(original.ProtectedReceipt,observed.ProtectedReceipt);
        var repeat=Operation(h.Id);owner.Add(repeat);await Assert.ThrowsAsync<DbUpdateException>(()=>owner.SaveChangesAsync());
    }

    private sealed class LostAcknowledgement:DbTransactionInterceptor
    {
        public override Task TransactionCommittedAsync(DbTransaction transaction,TransactionEndEventData eventData,CancellationToken ct=default)=>throw new IOException("Synthetic lost closeout acknowledgement.");
    }

    [Fact]
    public async Task New_SQL_header_and_counter_rows_are_append_only_and_duplicate_step_cannot_refund()
    {
        await using var db=fixture.Open();Assert.False(db.Database.HasPendingModelChanges());var h=Header();db.EmailPilotCloseouts.Add(h);await db.SaveChangesAsync();
        var op=Operation(h.Id);db.EmailPilotCloseoutOperations.Add(op);await db.SaveChangesAsync();
        h.ProtectedManifest="changed";await Assert.ThrowsAsync<InvalidOperationException>(()=>db.SaveChangesAsync());db.ChangeTracker.Clear();
        var duplicate=Operation(h.Id);duplicate.Id=Guid.NewGuid();db.EmailPilotCloseoutOperations.Add(duplicate);
        await Assert.ThrowsAsync<DbUpdateException>(()=>db.SaveChangesAsync());db.ChangeTracker.Clear();
        Assert.Equal(1,await db.EmailPilotCloseoutOperations.CountAsync(x=>x.CloseoutId==h.Id));
        var saved=await db.EmailPilotCloseoutOperations.SingleAsync(x=>x.Id==op.Id);db.Remove(saved);
        await Assert.ThrowsAsync<InvalidOperationException>(()=>db.SaveChangesAsync());
    }

    [Theory]
    [InlineData("over-window")][InlineData("offset")][InlineData("secret-expiry")]
    public async Task SQL_independently_rejects_unbounded_header(string fault)
    {
        await using var db=fixture.Open();var h=Header();switch(fault){case "over-window":h.Until=h.CreatedAt.AddMinutes(31);break;
            case "offset":h.CreatedAt=h.CreatedAt.ToOffset(TimeSpan.FromHours(1));break;case "secret-expiry":h.DeleteAfter=h.Until;break;}
        db.EmailPilotCloseouts.Add(h);await Assert.ThrowsAsync<DbUpdateException>(()=>db.SaveChangesAsync());
    }

    [Fact]
    public async Task Database_UTC_cleanup_is_exact_due_and_keeps_all_consumed_tombstones()
    {
        await using var db=fixture.Open();var past=Header(DateTimeOffset.UtcNow.AddDays(-8));var future=Header();db.AddRange(past,future);await db.SaveChangesAsync();
        var op=Operation(past.Id);op.At=past.CreatedAt.AddMinutes(1);db.Add(op);await db.SaveChangesAsync();
        await db.Database.ExecuteSqlInterpolatedAsync($"EXEC dbo.RemoveExpiredEmailPilotCloseoutSecret @Id={future.Id}");
        Assert.NotNull((await db.EmailPilotCloseouts.AsNoTracking().SingleAsync(x=>x.Id==future.Id)).ProtectedManifest);
        await db.Database.ExecuteSqlInterpolatedAsync($"EXEC dbo.RemoveExpiredEmailPilotCloseoutSecret @Id={past.Id}");
        Assert.Null((await db.EmailPilotCloseouts.AsNoTracking().SingleAsync(x=>x.Id==past.Id)).ProtectedManifest);
        Assert.True(await db.EmailPilotCloseoutOperations.AnyAsync(x=>x.Id==op.Id));
        await db.Database.ExecuteSqlInterpolatedAsync($"EXEC dbo.RemoveExpiredEmailPilotCloseoutSecret @Id={past.Id}");
        Assert.True(await db.EmailPilotCloseouts.AnyAsync(x=>x.Id==past.Id));
    }

    private static (EmailPilotCloseoutQueue,EmailOutbox,WorkItem) Pair()
    {
        var e=Guid.NewGuid();var m=new EmailOutbox{EnvelopeId=e,To="sender@example.invalid",Template=VoidNotificationJobs.Template,PayloadJson="original protected body",RowVersion=[1,2,3,4,5,6,7,8]};
        var w=new WorkItem{Id=m.Id,EnvelopeId=e,Kind=WorkKind.Email,PayloadJson="{}",AvailableAt=m.AvailableAt,RowVersion=[1,2,3,4,5,6,7,8]};
        return(new(EmailPilotCloseoutStep.VoidSender,e,m.Id,Raw(m),Raw(w)),m,w);
    }
    private static EmailPilotCloseoutOptions Options()
    {string Id()=>Guid.NewGuid().ToString("N");var a=Id();var b=Id();var at=DateTimeOffset.UtcNow;return new(){Enabled=true,AuthorizationId=Id(),CapabilitySha256=new string('a',64),StartsAt=at,Until=at.AddMinutes(30),
        AccountingParentRunIds=[a,b],CompletionParentRunId=a,VoidParentRunId=b,CompletionRecordId=Id(),VoidRecordId=Id(),DeclineRecordId=Id(),CompletionWorkIds=[Id(),Id(),Id(),Id()],VoidWorkIds=[Id(),Id()]};}
    private static EmailPilotCloseoutHeaderRecord Header(DateTimeOffset? at=null)
    {var start=at??DateTimeOffset.UtcNow;return new(){Id=Guid.NewGuid(),CreatedAt=start,Until=start.AddMinutes(30),DeleteAfter=start.AddDays(7),CapabilitySha256=new byte[32],ManifestSha256=new byte[32],ProtectedManifest="cipher"};}
    private static EmailPilotCloseoutOperationRecord Operation(Guid id)=>new(){Id=Guid.NewGuid(),CloseoutId=id,Kind=1,Step=0,SubjectEnvelopeId=Guid.NewGuid(),WorkId=Guid.NewGuid(),At=DateTimeOffset.UtcNow,EncodedBytes=1,RequestSha256=new byte[32],ProtectedReceipt="cipher"};
}
