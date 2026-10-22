using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class EmailPilotInitialAliasRecognitionTests
{
    [Fact]
    public async Task Producer_header_only_aliases_remain_closed_after_configuration_and_secret_loss()
    {
        await using var fixture=new SqlDatabaseFixture();await fixture.InitializeAsync();
        await using var db=fixture.Open();var at=DateTimeOffset.UtcNow.AddMinutes(-1);var auth=Guid.NewGuid();
        var keys=new EphemeralDataProtectionProvider();var proof=new EmailPilotProtection(keys);
        var parent=new EmailPilotRunRecord{Id=Guid.NewGuid(),CreatedAt=at.AddHours(-2),ExpiresAt=at.AddHours(-1),CapabilitySha256=new byte[32],ManifestSha256=new byte[32]};
        db.Add(parent);var records=new[]{new Envelope{SenderEmail="sender@example.invalid"},new Envelope{SenderEmail="sender@example.invalid"}};
        db.AddRange(records);await db.SaveChangesAsync();
        foreach(var record in records)db.Add(new EmailPilotEnrollmentRecord{RunId=parent.Id,SubjectEnvelopeId=record.Id,EnrolledAt=at.AddHours(-2),
            Scenario=record==records[0]?EmailPilotScenario.Completion:EmailPilotScenario.Void,ProtectedBinding="synthetic-immutable-cohort"});
        var originals=new List<(EmailOutbox Mail,WorkItem Work)>();
        for(var n=0;n<6;n++) {
            var mail=new EmailOutbox{EnvelopeId=records[n<4?0:1].Id,To="sender@example.invalid",Template=n<4?CompletionNotificationJobs.Template:VoidNotificationJobs.Template,
                PayloadJson="{\"Protected\":\"original-ciphertext\"}",Status=EmailStatus.Failed,LastError="pilot-delivery-unavailable",AvailableAt=at.AddHours(-1)};
            var work=new WorkItem{Id=mail.Id,EnvelopeId=mail.EnvelopeId,Kind=WorkKind.Email,Status=WorkStatus.Failed,Attempts=1,LastError=mail.LastError,AvailableAt=mail.AvailableAt,
                PayloadJson=n<4?CompletionNotificationJobs.WorkJson(mail.Id):VoidNotificationJobs.WorkJson(mail.Id)};
            db.AddRange(mail,work);originals.Add((mail,work));
        }
        await db.SaveChangesAsync();var originalBytes=originals.Select(x=>JsonSerializer.Serialize(new {x.Mail,x.Work})).ToArray();
        var pairs=new List<EmailPilotCloseoutQueue>();await using(var tx=await db.Database.BeginTransactionAsync()) {
            foreach(var (pair,n) in originals.Select((x,n)=>(x,n)))pairs.Add(await EmailPilotCloseout.InsertAliasPairLockedAsync(db,auth,(EmailPilotCloseoutStep)n,pair.Mail,pair.Work,at));
            var manifest=new EmailPilotCloseoutManifest(EmailPilotCloseoutLimits.Version,auth,at,at.AddMinutes(30),at.AddDays(1),new string('a',64),[],pairs.ToArray(),new string('b',64));
            var cipher=proof.Protect(auth,"bounded-failed-notice-closeout-manifest-v1",manifest);
            Assert.Equal(6,proof.Read<EmailPilotCloseoutManifest>(auth,"bounded-failed-notice-closeout-manifest-v1",cipher,65536).Queue.Length);
            db.Add(new EmailPilotCloseoutHeaderRecord{Id=auth,CreatedAt=at,Until=at.AddMinutes(30),DeleteAfter=at.AddDays(1),ProtectedManifest=cipher,
                CapabilitySha256=new byte[32],ManifestSha256=SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(manifest)))});
            await db.SaveChangesAsync();await tx.CommitAsync();
        }
        Assert.Empty(await db.EmailPilotCloseoutOperations.ToArrayAsync());db.ChangeTracker.Clear();
        var options=new WorkOptions{Enabled=true};var closeout=new EmailPilotCloseout(new(),new(),options,()=>db,()=>throw new InvalidOperationException("No authority"),()=>proof,TimeProvider.System);
        var cleared=new EmailPilotCloseout(new(){Enabled=true,StartsAt=at,Until=at.AddMinutes(30)},new(),options,()=>db,()=>throw new InvalidOperationException("No authority"),()=>proof,TimeProvider.System);
        var authority=new EmailPilotWorkAuthority(new(),new(),options,new(),()=>throw new InvalidOperationException("No authority"),()=>db,()=>throw new InvalidOperationException("No source"),TimeProvider.System);
        var dispatch=new EmailPilotDispatch(db,new(),()=>authority,(_,_,_)=>throw new InvalidOperationException("No provider"),null!);
        foreach(var erase in new[]{false,true}) {
            if(erase){await db.EmailPilotCloseouts.Where(x=>x.Id==auth).ExecuteUpdateAsync(x=>x.SetProperty(y=>y.ProtectedManifest,(string?)null));}
            foreach(var pair in pairs) {
                Assert.True(await closeout.IsKnownWorkAsync(pair.WorkId));
                var before=await Rows(db,pair.WorkId);
                foreach(var service in new EmailPilotCloseout?[]{null,closeout,cleared}) {
                    if(ReferenceEquals(service,cleared))await Assert.ThrowsAsync<InvalidOperationException>(()=>new WorkStore(db,options,TimeProvider.System,service).ClaimAsync(pair.WorkId,default));
                    else await Assert.ThrowsAsync<InvalidDataException>(()=>new WorkStore(db,options,TimeProvider.System,service).ClaimAsync(pair.WorkId,default));
                    db.ChangeTracker.Clear();Assert.Equal(before,await Rows(db,pair.WorkId));
                }
                var lease=new WorkLease(pair.WorkId,Guid.NewGuid(),WorkKind.Email,1,DateTimeOffset.UtcNow.AddMinutes(3));
                await using(var tx=await db.Database.BeginTransactionAsync()) {
                    var work=await db.WorkItems.SingleAsync(x=>x.Id==pair.WorkId);work.Status=WorkStatus.Leased;work.Attempts=1;work.LeaseOwner=lease.Owner;work.LeaseExpiresAt=lease.Until;
                    await db.SaveChangesAsync();db.ChangeTracker.Clear();var leased=await Rows(db,pair.WorkId);
                    await Assert.ThrowsAsync<InvalidDataException>(()=>closeout.ReadAliasLockedAsync(db,lease,"sender@example.invalid"));
                    await Assert.ThrowsAsync<InvalidDataException>(()=>dispatch.ReadAliasLockedAsync(db,lease,"sender@example.invalid"));
                    await Assert.ThrowsAsync<InvalidDataException>(()=>closeout.ReadWorkAsync(lease));
                    Assert.Equal(leased,await Rows(db,pair.WorkId));await tx.RollbackAsync();
                }
                db.ChangeTracker.Clear();
            }
        }
        // Candidate mutations cannot exclude the original immutable cohort.
        foreach(var fault in new[]{"kind","both-associations","mismatched","missing-work","missing-mail","missing-original-work","missing-original-mail"}) {
            var pair=pairs[0];await using var tx=await db.Database.BeginTransactionAsync();
            var work=await db.WorkItems.SingleAsync(x=>x.Id==pair.WorkId);var mail=await db.EmailOutbox.SingleAsync(x=>x.Id==pair.WorkId);
            var outside=new Envelope{SenderEmail="sender@example.invalid"};db.Add(outside);await db.SaveChangesAsync();
            switch(fault) {
                case "kind":work.Kind=WorkKind.Rendering;break;
                case "both-associations":work.EnvelopeId=outside.Id;mail.EnvelopeId=outside.Id;break;
                case "mismatched":mail.EnvelopeId=outside.Id;break;
                case "missing-work":db.Remove(work);break;
                case "missing-mail":db.Remove(mail);break;
                case "missing-original-work":db.Remove(await db.WorkItems.SingleAsync(x=>x.Id==pair.OriginalId));break;
                case "missing-original-mail":db.Remove(await db.EmailOutbox.SingleAsync(x=>x.Id==pair.OriginalId));break;
            }
            await db.SaveChangesAsync();db.ChangeTracker.Clear();
            if(fault is "missing-original-work" or "missing-original-mail")Assert.True(await EmailPilotCloseout.RecognizesWorkAsync(db,pair.WorkId));
            else await Assert.ThrowsAsync<InvalidDataException>(()=>EmailPilotCloseout.RecognizesWorkAsync(db,pair.WorkId));
            await tx.RollbackAsync();db.ChangeTracker.Clear();
        }
        var ordinary=new EmailOutbox{EnvelopeId=records[0].Id,To="sender@example.invalid",AvailableAt=at};
        db.Add(ordinary);db.Add(new WorkItem{Id=ordinary.Id,EnvelopeId=ordinary.EnvelopeId,Kind=WorkKind.Email,PayloadJson="{}",AvailableAt=at});await db.SaveChangesAsync();db.ChangeTracker.Clear();
        Assert.False(await closeout.IsKnownWorkAsync(ordinary.Id));
        Assert.NotNull((await new WorkStore(db,options,TimeProvider.System,closeout).ClaimAsync(ordinary.Id,default)).Lease);
        db.ChangeTracker.Clear();
        await using(var tx=await db.Database.BeginTransactionAsync()) {
            db.Add(new EmailPilotCloseoutHeaderRecord{Id=Guid.NewGuid(),CreatedAt=at,Until=at.AddMinutes(30),DeleteAfter=at.AddDays(1),CapabilitySha256=new byte[32],ManifestSha256=new byte[32]});
            await db.SaveChangesAsync();db.ChangeTracker.Clear();
            await Assert.ThrowsAsync<InvalidDataException>(()=>closeout.IsKnownWorkAsync(ordinary.Id));
            await tx.RollbackAsync();
        }
        db.ChangeTracker.Clear();
        await using(var tx=await db.Database.BeginTransactionAsync()) {
            db.AddRange(Enumerable.Range(0,4097).Select(_=>new WorkItem{EnvelopeId=records[0].Id,Kind=WorkKind.Rendering,PayloadJson="{}",AvailableAt=at}));
            await db.SaveChangesAsync();db.ChangeTracker.Clear();
            await Assert.ThrowsAsync<InvalidDataException>(()=>closeout.IsKnownWorkAsync(ordinary.Id));
            await tx.RollbackAsync();
        }
        db.ChangeTracker.Clear();
        for(var n=0;n<6;n++) {
            var original=originals[n];Assert.Equal(originalBytes[n],JsonSerializer.Serialize(new {Mail=await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==original.Mail.Id),Work=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==original.Work.Id)}));
        }
    }

    private static async Task<string> Rows(QuillSignDbContext db,Guid id)=>JsonSerializer.Serialize(new {
        Mail=await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id),Work=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id)});
}
