using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Lifecycle;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class ProductionCompletionMailRuntimeTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    private static CompletionNotificationPayload Payload()=>new(CompletionNotificationJobs.Version,Guid.NewGuid(),Guid.NewGuid(),new('a',64),
        Convert.ToBase64String(new byte[8]),PartyType.Sender,null,new('b',64),new('c',64),new('d',64),false);

    [Fact]
    public void Canonical_original_and_issued_payloads_preserve_scope_but_never_confer_dispatch_authority()
    {
        var keys=new EphemeralDataProtectionProvider();var gate=new ProductionCompletionMailAdmission(keys,TimeProvider.System);
        var protection=new CompletionNotificationProtection(keys);var p=Payload();
        Assert.Equal(p,gate.Read(protection.Protect(p)));
        var issued=p with{LastTokenId=Guid.NewGuid()};Assert.Equal(issued,gate.Read(protection.Protect(issued)));
        Assert.Equal(CompletionNotificationJobs.Digest(p),CompletionNotificationJobs.Digest(issued));
    }

    [Theory]
    [InlineData("future")][InlineData("duplicate")][InlineData("wrapper")][InlineData("trailing")]
    public void Authenticated_unknown_or_noncanonical_payload_and_wrapper_shapes_fail_closed(string fault)
    {
        var keys=new EphemeralDataProtectionProvider();var gate=new ProductionCompletionMailAdmission(keys,TimeProvider.System);
        var plain=JsonSerializer.Serialize(Payload());
        plain=fault switch {"future"=>plain[..^1]+",\"Future\":true}","duplicate"=>plain[..^1]+",\"LastTokenId\":null}","trailing"=>plain+" ",_=>plain};
        var raw=JsonSerializer.Serialize(new ProtectedWorkPayload(keys.CreateProtector("QuillSign.CompletionNotification.v1").Protect(plain)));
        if(fault=="wrapper")raw=raw[..^1]+",\"Future\":true}";
        Assert.Throws<ProductionWorkBlockedException>(()=>gate.Read(raw));
    }

    [Fact]
    public void Existing_attempt_and_submission_producer_bytes_are_unchanged()
    {
        var p=Payload() with{LastTokenId=Guid.NewGuid()};var id=CompletionNotificationJobs.Id(p);
        var at=new DateTimeOffset(2030,1,1,12,0,0,TimeSpan.Zero);byte[] executed=[1,2],certificate=[3,4];
        Assert.Equal(JsonSerializer.Serialize(new {version=CompletionNotificationJobs.Version,notificationId=id,scopeSha256=CompletionNotificationJobs.Digest(p),tokenId=p.LastTokenId,
            ExpiresAt=at,templateVersion=CompletionEmailTemplate.Version,linkOnly=false,executedSha256="0102",certificateSha256="0304",
            meaning="Submission prepared; no provider acceptance or delivery is confirmed."}),
            CompletionNotificationDelivery.AttemptEvidence(id,p,at,false,executed,certificate));
        Assert.Equal(JsonSerializer.Serialize(new {version=CompletionNotificationJobs.Version,notificationId=id,scopeSha256=CompletionNotificationJobs.Digest(p),tokenId=p.LastTokenId,
            provider="Synthetic",providerMessageId="synthetic-receipt",linkOnly=false,templateVersion=CompletionEmailTemplate.Version,executedSha256="0102",certificateSha256="0304",
            meaning="Provider accepted the message; inbox delivery, receipt and saving are not confirmed."}),
            CompletionNotificationDelivery.SubmittedEvidence(id,p,"Synthetic","synthetic-receipt",false,executed,certificate));
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public void Actual_composer_mode_retains_exact_pair_or_size_only_zero_attachments_and_canonical_audit_mode(bool linkOnly)
    {
        var executed="%PDF-1.7\nSynthetic executed\n%%EOF"u8.ToArray();var certificate="%PDF-1.7\nSynthetic certificate\n%%EOF"u8.ToArray();
        var verified=new PublishedCompletion(Guid.NewGuid(),DateTimeOffset.UtcNow,null!,null!,executed,certificate);
        PdfEmailAttachment[] pair=[new("executed.pdf",executed),new("certificate.pdf",certificate)];
        var message=new OutgoingEmail("synthetic@example.invalid","Synthetic","Text","<p>Text</p>",Attachments:linkOnly?[]:pair);
        CompletionNotificationDelivery.DemandAttachmentMode(verified,new(message,linkOnly));
        var p=Payload() with{LastTokenId=Guid.NewGuid()};var id=CompletionNotificationJobs.Id(p);
        using var attempt=JsonDocument.Parse(CompletionNotificationDelivery.AttemptEvidence(id,p,DateTimeOffset.UtcNow.AddHours(1),linkOnly,executed,certificate));
        using var submitted=JsonDocument.Parse(CompletionNotificationDelivery.SubmittedEvidence(id,p,"Synthetic","synthetic-receipt",linkOnly,executed,certificate));
        Assert.Equal(linkOnly,attempt.RootElement.GetProperty("linkOnly").GetBoolean());Assert.Equal(linkOnly,submitted.RootElement.GetProperty("linkOnly").GetBoolean());
        Assert.Throws<ProductionWorkBlockedException>(()=>CompletionNotificationDelivery.DemandAttachmentMode(verified,new(message with{Attachments=linkOnly?pair:[]},linkOnly)));
        Assert.Throws<ProductionWorkBlockedException>(()=>CompletionNotificationDelivery.DemandAttachmentMode(verified,new(message with{Attachments=null},linkOnly)));
        var wrong=new PdfEmailAttachment("wrong.pdf","%PDF-1.7\nChanged source\n%%EOF"u8.ToArray());
        Assert.Throws<ProductionWorkBlockedException>(()=>CompletionNotificationDelivery.DemandAttachmentMode(verified,new(message with{Attachments=[pair[0],wrong]},false)));
    }

    [Fact]
    public async Task Missing_opt_in_admission_refuses_before_any_query_token_or_transport()
    {
        await using var db=fixture.Open();var sender=new SendDraftWorkflowTests.FakeSender();
        var options=new EmailOptions{Enabled=true};
        var delivery=new CompletionNotificationDelivery(db,null!,null!,null!,null!,null!,sender,options,null!,TimeProvider.System);
        var admission=new ProductionWorkAdmission(fixture.Open,null!);
        var mail=new EmailOutbox{EnvelopeId=Guid.NewGuid(),To="synthetic@example.invalid",Template=CompletionNotificationJobs.Template};
        await Assert.ThrowsAsync<ProductionWorkBlockedException>(()=>delivery.ExecuteAdmittedAsync(
            new(mail.Id,Guid.NewGuid(),WorkKind.Email,1,DateTimeOffset.UtcNow.AddMinutes(5)),mail,admission,default));
        Assert.Equal(0,sender.Calls);Assert.False(db.ChangeTracker.HasChanges());Assert.Null(db.Database.CurrentTransaction);
    }

    [Fact]
    public async Task A_completion_template_on_an_incomplete_parent_never_claims_or_mutates_either_row()
    {
        await using var run=await ProductionRuntimeAdmissionTests.Run.Create(fixture);
        await using var db=fixture.Open();
        await db.EmailOutbox.Where(x=>x.Id==run.WorkId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Template,CompletionNotificationJobs.Template));
        var before=JsonSerializer.Serialize(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==run.WorkId));
        var mailBefore=JsonSerializer.Serialize(await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==run.WorkId));
        var admission=new ProductionWorkAdmission(fixture.Open,run.Admission){CompletionMail=new(run.Keys,run.Time)};
        var claim=await new WorkStore(db,new(){Enabled=true},run.Time,admission).ClaimAsync(run.WorkId,default);
        Assert.Null(claim.Lease);Assert.False(claim.Terminal);
        Assert.Equal(before,JsonSerializer.Serialize(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==run.WorkId)));
        Assert.Equal(mailBefore,JsonSerializer.Serialize(await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==run.WorkId)));
        Assert.False(await db.AuthTokens.AnyAsync(x=>x.EnvelopeId==run.Id));Assert.Equal(0,run.Captured.Calls);
        Assert.Null((await run.Journal.ReadAsync(run.Id)).OutstandingOperation);
    }

    [Fact]
    public async Task First_read_crossing_original_deadline_prevents_second_IO_and_default_reads_remain_unchanged()
    {
        await using var db=fixture.Open();await using var tx=await db.Database.BeginTransactionAsync();
        var now=DateTimeOffset.UtcNow;var until=now.AddSeconds(1);var calls=0;
        using(var scope=CompletionReadRestriction.Enter(db,()=>{if(now>=until)throw new InvalidDataException("Synthetic original deadline.");}))
        {
            await Assert.ThrowsAsync<InvalidDataException>(async()=>{
                await CompletionReadRestriction.ReadAsync(db,()=>{calls++;now=until;return Task.CompletedTask;});
                await CompletionReadRestriction.ReadAsync(db,()=>{calls++;return Task.CompletedTask;});
            });
            Assert.Equal(1,calls);
        }
        await CompletionReadRestriction.ReadAsync(db,()=>{calls++;return Task.CompletedTask;});Assert.Equal(2,calls);
        await tx.RollbackAsync();
    }

    [Fact]
    public async Task Read_restriction_isolated_child_flow_cannot_clear_parent_and_disposed_physical_transaction_refuses_before_IO()
    {
        await using var db=fixture.Open();await using var tx=await db.Database.BeginTransactionAsync();var parent=0;var child=0;
        using var scope=CompletionReadRestriction.Enter(db,()=>parent++);
        await using(var wrong=fixture.Open())
        {
            var wrongCalled=false;
            await Assert.ThrowsAsync<InvalidDataException>(()=>CompletionReadRestriction.ReadAsync(wrong,()=>{wrongCalled=true;return Task.CompletedTask;}));
            Assert.False(wrongCalled);
        }
        await Task.Run(async()=>{
            await using var other=fixture.Open();await using var own=await other.Database.BeginTransactionAsync();
            using(var nested=CompletionReadRestriction.Enter(other,()=>child++))await CompletionReadRestriction.ReadAsync(other,()=>Task.CompletedTask);
            await own.RollbackAsync();
        });
        var before=parent;await CompletionReadRestriction.ReadAsync(db,()=>Task.CompletedTask);Assert.Equal(before+2,parent);Assert.Equal(3,child);
        await tx.RollbackAsync();await tx.DisposeAsync();
        var called=false;
        await Assert.ThrowsAsync<InvalidDataException>(()=>CompletionReadRestriction.ReadAsync(db,()=>{called=true;return Task.CompletedTask;}));Assert.False(called);
    }
}
