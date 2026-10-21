using System.Data.Common;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using QuillSign.Data;
using QuillSign.Email.Pilot;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class EmailPilotCloseoutAliasTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    private static readonly JsonSerializerOptions Json=new(){Converters={new JsonStringEnumConverter()}};
    private static string Raw<T>(T value)=>JsonSerializer.Serialize(value,Json);

    [Theory]
    [InlineData("mail-status")][InlineData("work-status")][InlineData("mail-attempt")][InlineData("work-attempt")]
    [InlineData("intent")][InlineData("provider")][InlineData("provider-id")][InlineData("mail-lease")][InlineData("work-lease")]
    [InlineData("mail-error")][InlineData("work-error")][InlineData("body")][InlineData("attachments")][InlineData("version")]
    public void Only_exact_original_preprovider_failure_can_derive_alias(string fault)
    {
        var (mail,work)=Failed(VoidNotificationJobs.Template);EmailPilotCloseout.FailedBeforeProvider(mail,work,mail.EnvelopeId!.Value,mail.Template);
        switch(fault){case "mail-status":mail.Status=EmailStatus.Queued;break;case "work-status":work.Status=WorkStatus.Queued;break;
            case "mail-attempt":mail.Attempts=1;break;case "work-attempt":work.Attempts=0;break;case "intent":mail.SubmissionStartedAt=mail.AvailableAt;break;
            case "provider":mail.Provider="captured";break;case "provider-id":mail.ProviderMessageId="unknown";break;case "mail-lease":mail.LeaseOwner=Guid.NewGuid();break;
            case "work-lease":work.LeaseExpiresAt=work.AvailableAt;break;case "mail-error":mail.LastError="other";break;case "work-error":work.LastError="other";break;
            case "body":work.PayloadJson+=" ";break;case "attachments":mail.AttachmentsJson="[1]";break;case "version":mail.RowVersion=[];break;}
        Assert.Throws<InvalidDataException>(()=>EmailPilotCloseout.NewAliasPair(Guid.NewGuid(),mail,work,mail.AvailableAt.AddMinutes(1)));
    }

    [Theory]
    [InlineData(CompletionNotificationJobs.Template)][InlineData(VoidNotificationJobs.Template)]
    public void Alias_preserves_exact_payload_and_old_failed_bytes_with_distinct_closed_identity(string template)
    {
        var (mail,work)=Failed(template);var before=(Raw(mail),Raw(work));var authorization=Guid.NewGuid();var at=mail.AvailableAt.AddMinutes(1);
        var alias=EmailPilotCloseout.NewAliasPair(authorization,mail,work,at);
        Assert.Equal(before,(Raw(mail),Raw(work)));Assert.NotEqual(mail.Id,alias.Mail.Id);Assert.Equal(alias.Mail.Id,alias.Work.Id);
        Assert.Equal(EmailPilotCloseout.AliasId(authorization,mail.Id),alias.Mail.Id);
        Assert.NotEqual(alias.Mail.Id,EmailPilotCloseout.AliasId(Guid.NewGuid(),mail.Id));
        Assert.Equal(mail.PayloadJson,alias.Mail.PayloadJson);Assert.Equal(mail.To,alias.Mail.To);Assert.Equal(mail.EnvelopeId,alias.Mail.EnvelopeId);
        Assert.Equal(EmailStatus.Queued,alias.Mail.Status);Assert.Equal(WorkStatus.Queued,alias.Work.Status);Assert.Equal(0,alias.Work.Attempts);Assert.Equal(0,alias.Mail.Attempts);
        Assert.Null(alias.Mail.SubmissionStartedAt);Assert.Null(alias.Mail.LastError);Assert.Null(alias.Work.LastError);Assert.Equal(at,alias.Mail.AvailableAt);
        Assert.Equal(template==CompletionNotificationJobs.Template?CompletionNotificationJobs.WorkJson(alias.Mail.Id):VoidNotificationJobs.WorkJson(alias.Mail.Id),alias.Work.PayloadJson);
        Assert.Equal(10,EmailPilotCloseoutLimits.ApplicationAttempts);Assert.Equal(31429362,EmailPilotCloseoutLimits.EncodedBytes);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Six_alias_pairs_and_header_are_atomic_and_keep_original_rows_exact(bool commit)
    {
        await using var db=fixture.Open();var originals=await OriginalRows(db);var captured=originals.Select(x=>(Mail:Raw(x.Mail),Work:Raw(x.Work))).ToArray();
        var header=Header();var pairs=new List<EmailPilotCloseoutQueue>();
        await using(var tx=await db.Database.BeginTransactionAsync()) {
            for(var n=0;n<originals.Length;n++)pairs.Add(await EmailPilotCloseout.InsertAliasPairLockedAsync(db,header.Id,(EmailPilotCloseoutStep)n,originals[n].Mail,originals[n].Work,header.CreatedAt));
            Assert.All(pairs,x=>{Assert.NotEqual(Guid.Empty,x.OriginalId);Assert.NotNull(x.OriginalMailJson);Assert.Equal(8,JsonSerializer.Deserialize<WorkItem>(x.WorkJson,Json)!.RowVersion.Length);});
            header.ProtectedManifest=Raw(pairs);db.Add(header);await db.SaveChangesAsync();
            if(commit)await tx.CommitAsync();else await tx.RollbackAsync();
        }
        db.ChangeTracker.Clear();Assert.Equal(commit,await db.EmailPilotCloseouts.AnyAsync(x=>x.Id==header.Id));
        Assert.Equal(commit?6:0,await db.WorkItems.CountAsync(x=>pairs.Select(p=>p.WorkId).Contains(x.Id)));
        for(var n=0;n<originals.Length;n++) {
            Assert.Equal(captured[n].Mail,Raw(await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==originals[n].Mail.Id)));
            Assert.Equal(captured[n].Work,Raw(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==originals[n].Work.Id)));
        }
    }

    [Fact]
    public async Task Lost_atomic_commit_ack_preserves_same_six_ids_and_refuses_recapture_or_second_alias()
    {
        await using var owner=fixture.Open();var originals=await OriginalRows(owner);var captured=originals.Select(x=>(Mail:Raw(x.Mail),Work:Raw(x.Work))).ToArray();var header=Header();
        var options=new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(owner.Database.GetConnectionString()).AddInterceptors(new LostAck()).Options;
        var aliases=new List<Guid>();await using(var db=new QuillSignDbContext(options)) {
            await using var tx=await db.Database.BeginTransactionAsync();for(var n=0;n<originals.Length;n++)
                aliases.Add((await EmailPilotCloseout.InsertAliasPairLockedAsync(db,header.Id,(EmailPilotCloseoutStep)n,originals[n].Mail,originals[n].Work,header.CreatedAt)).WorkId);
            db.Add(header);await db.SaveChangesAsync();await Assert.ThrowsAsync<IOException>(()=>tx.CommitAsync());
        }
        Assert.True(await owner.EmailPilotCloseouts.AnyAsync(x=>x.Id==header.Id));Assert.Equal(6,await owner.WorkItems.CountAsync(x=>aliases.Contains(x.Id)));
        await using(var tx=await owner.Database.BeginTransactionAsync()) {
            await Assert.ThrowsAsync<InvalidDataException>(()=>EmailPilotCloseout.InsertAliasPairLockedAsync(owner,header.Id,EmailPilotCloseoutStep.CompletionSender,originals[0].Mail,originals[0].Work,header.CreatedAt));
            await tx.RollbackAsync();
        }
        for(var n=0;n<originals.Length;n++){Assert.Equal(captured[n].Mail,Raw(await owner.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==originals[n].Mail.Id)));
            Assert.Equal(captured[n].Work,Raw(await owner.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==originals[n].Work.Id)));}
    }

    [Fact]
    public async Task Admission_refusal_never_discards_a_callers_unrelated_unsaved_changes()
    {
        await using var db=fixture.Open();var record=new Envelope{SenderEmail="sender@example.invalid"};db.Add(record);
        var core=new EmailPilotCloseout(new(),new(),new(),()=>db,()=>throw new Exception("No ledger"),()=>throw new Exception("No key"),TimeProvider.System);
        await Assert.ThrowsAsync<InvalidDataException>(()=>core.CreateAsync("invalid"));
        Assert.Equal(EntityState.Added,db.Entry(record).State);Assert.True(db.ChangeTracker.HasChanges());
    }

    private static (EmailOutbox Mail,WorkItem Work) Failed(string template)
    {
        var mail=new EmailOutbox{EnvelopeId=Guid.NewGuid(),To="sender@example.invalid",Template=template,PayloadJson="{\"Protected\":\"original-ciphertext\"}",
            Status=EmailStatus.Failed,Attempts=0,LastError="pilot-delivery-unavailable",AvailableAt=DateTimeOffset.UtcNow.AddHours(-1),RowVersion=new byte[8]};
        return(mail,new(){Id=mail.Id,EnvelopeId=mail.EnvelopeId,Kind=WorkKind.Email,Status=WorkStatus.Failed,Attempts=1,LastError="pilot-delivery-unavailable",
            PayloadJson=template==CompletionNotificationJobs.Template?CompletionNotificationJobs.WorkJson(mail.Id):VoidNotificationJobs.WorkJson(mail.Id),AvailableAt=mail.AvailableAt,RowVersion=new byte[8]});
    }
    private static async Task<(EmailOutbox Mail,WorkItem Work)[]> OriginalRows(QuillSignDbContext db)
    {
        var result=Enumerable.Range(0,6).Select(n=>Failed(n<4?CompletionNotificationJobs.Template:VoidNotificationJobs.Template)).ToArray();
        foreach(var pair in result){var envelope=new Envelope{Id=pair.Mail.EnvelopeId!.Value,PublicId=Guid.NewGuid().ToString("N"),SenderEmail="sender@example.invalid"};
            db.Add(envelope);db.Add(pair.Mail);db.Add(pair.Work);}await db.SaveChangesAsync();return result;
    }
    private static EmailPilotCloseoutHeaderRecord Header(){var at=DateTimeOffset.UtcNow;return new(){Id=Guid.NewGuid(),CreatedAt=at,Until=at.AddMinutes(30),DeleteAfter=at.AddDays(7),CapabilitySha256=new byte[32],ManifestSha256=new byte[32],ProtectedManifest="test-only atomic carrier"};}
    private sealed class LostAck:DbTransactionInterceptor
    {public override Task TransactionCommittedAsync(DbTransaction transaction,TransactionEndEventData eventData,CancellationToken ct=default)=>throw new IOException("Synthetic lost alias commit acknowledgement.");}
}
