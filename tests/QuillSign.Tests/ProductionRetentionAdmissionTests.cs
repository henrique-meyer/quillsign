using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Legal;
using QuillSign.Lifecycle;

namespace QuillSign.Tests;

public sealed class ProductionRetentionAdmissionContractTests
{
    internal static readonly DateTimeOffset Now = new DateTimeOffset(2031, 4, 5, 6, 7, 8, TimeSpan.Zero).AddTicks(1234567);
    internal static RecordLifecycleOptions Settings() => new() { Mode="Production", Production=new() {
        Version="synthetic-v1", ArchiveResponsibility="Synthetic test archive responsibility.",
        AbandonedDraftDays=3, ExpiredDays=30, DeclinedDays=31, VoidedDays=32, CompletedDays=365 } };
    internal static ElectronicRecordOptions Policies() => new() {
        PaperCopyInstructions="Synthetic paper instructions.", PaperCopyFees="Synthetic paper fees.",
        WithdrawalInstructions="Synthetic withdrawal instructions.", WithdrawalConsequences="Synthetic withdrawal consequences.",
        ContactUpdateInstructions="Synthetic contact instructions.", AccessRequirements="Synthetic access requirements.",
        RetentionNotice="Synthetic operator retention notice; exact frozen intervals appear below." };

    [Theory]
    [InlineData("")][InlineData("production")][InlineData("Other")][InlineData(" Production")]
    public void An_unknown_or_implicit_mode_never_admits_a_record(string mode)
    {
        var options=Settings();options.Mode=mode;
        Assert.Throws<InvalidOperationException>(()=>ProductionRetentionAdmission.Prepare("sender@example.invalid",Now,options,Policies()));
    }

    [Fact]
    public void The_default_preserves_demo_admission_and_does_not_infer_mode_from_completed_days()
    {
        var options=Settings();options.Mode="Demo";options.Production.CompletedDays=0;
        var plan=ProductionRetentionAdmission.Prepare("SENDER@example.invalid",Now,options,new());
        Assert.True(plan.Envelope.IsDemo);Assert.Null(plan.Policy);Assert.Equal(Now,plan.Envelope.CreatedAt);
        Assert.Equal("sender@example.invalid",plan.Envelope.SenderEmail);
    }

    [Theory]
    [InlineData("paper")][InlineData("fees")][InlineData("withdraw")][InlineData("consequences")]
    [InlineData("contact")][InlineData("access")][InlineData("retention")][InlineData("demo-profile")]
    public void Every_operator_policy_is_required_before_production_admission(string missing)
    {
        var p=Policies();
        switch(missing) {
            case "paper":p.PaperCopyInstructions="";break;case "fees":p.PaperCopyFees="";break;
            case "withdraw":p.WithdrawalInstructions="";break;case "consequences":p.WithdrawalConsequences="";break;
            case "contact":p.ContactUpdateInstructions="";break;case "access":p.AccessRequirements="";break;
            case "retention":p.RetentionNotice="";break;case "demo-profile":p.Profile="SyntheticDemo";break;
        }
        Assert.Throws<DisclosureRejectedException>(()=>ProductionRetentionAdmission.Prepare("sender@example.invalid",Now,Settings(),p));
    }

    [Fact]
    public void Policy_preflight_preserves_exact_origin_and_copies_configuration_before_later_mutation()
    {
        var options=Settings();var plan=ProductionRetentionAdmission.Prepare("sender@example.invalid",Now,options,Policies());
        options.Production.CompletedDays=1;options.Production.ArchiveResponsibility="Changed settings.";options.Mode="Demo";
        Assert.False(plan.Envelope.IsDemo);Assert.Equal(Now,plan.Envelope.CreatedAt);Assert.Equal(365,plan.Policy!.CompletedDays);
        Assert.Equal("Synthetic test archive responsibility.",plan.Policy.ArchiveResponsibility);
        var e=plan.Envelope;var frozen=ProductionRetentionPolicyContract.Freeze(e.Id,ProductionRetentionLedger.Seconds(e.CreatedAt),plan.Policy);
        var enrolled=new VerifiedProductionRetention(frozen,e.CreatedAt,Now,1,new string('0',64));
        var result=ProductionRetentionDisclosure.Build(e,"Synthetic {{retention_notice}} — NO AGREEMENT",enrolled,Policies());
        Assert.True(ElectronicRecordDisclosure.Verify(result));Assert.Equal(ProductionRetentionDisclosure.Version,result.Version);
        Assert.Contains("365 days from actual completion",result.Text);Assert.Contains("31 days from actual decline",result.Text);
        Assert.Contains(Now.AddDays(3).ToString("O",System.Globalization.CultureInfo.InvariantCulture),result.Text);
        Assert.Contains("Synthetic {{retention_notice}} — NO AGREEMENT",result.Text);
        Assert.Contains(ProductionRetentionPolicyContract.Digest(frozen),result.Text);
        Assert.Contains("this policy sets no automatic deletion deadline",result.Text);
    }

    [Theory]
    [InlineData("record")][InlineData("clock")][InlineData("mode")]
    public void A_disclosure_cannot_rebind_verified_policy_to_a_different_record_or_clock(string change)
    {
        var plan=ProductionRetentionAdmission.Prepare("sender@example.invalid",Now,Settings(),Policies());var e=plan.Envelope;
        var frozen=ProductionRetentionPolicyContract.Freeze(e.Id,ProductionRetentionLedger.Seconds(Now),plan.Policy!);
        var enrolled=new VerifiedProductionRetention(frozen,Now,Now,1,new string('0',64));
        if(change=="record")e.Id=Guid.NewGuid();if(change=="clock")e.CreatedAt=Now.AddTicks(1);if(change=="mode")e.IsDemo=true;
        Assert.Throws<DisclosureRejectedException>(()=>ProductionRetentionDisclosure.Build(e,"Synthetic NO AGREEMENT",enrolled,Policies()));
    }

    [Fact]
    public void Indefinite_retention_is_explicit_and_does_not_become_a_case_hold_or_erasure_promise()
    {
        var options=Settings();options.Production.CompletedDays=0;
        var plan=ProductionRetentionAdmission.Prepare("sender@example.invalid",Now,options,Policies());var e=plan.Envelope;
        var frozen=ProductionRetentionPolicyContract.Freeze(e.Id,ProductionRetentionLedger.Seconds(Now),plan.Policy!);
        var result=ProductionRetentionDisclosure.Build(e,"Synthetic NO AGREEMENT",new(frozen,Now,Now,1,new string('0',64)),Policies());
        Assert.Contains("explicitly selected indefinite retention",result.Text);
        Assert.Contains("separate from a case-specific legal hold",result.Text);
        Assert.Contains("not a promise of immediate physical erasure",result.Text);
        Assert.DoesNotContain("0 days from actual completion",result.Text);
    }

    [Fact]
    public void Missing_intervals_or_invalid_original_clocks_fail_before_creation()
    {
        var options=Settings();options.Production.CompletedDays=null;
        Assert.Throws<InvalidOperationException>(()=>ProductionRetentionAdmission.Prepare("sender@example.invalid",Now,options,Policies()));
        Assert.Throws<InvalidOperationException>(()=>ProductionRetentionAdmission.Prepare("sender@example.invalid",Now.ToOffset(TimeSpan.FromHours(1)),Settings(),Policies()));
        Assert.Throws<InvalidDataException>(()=>ProductionRetentionAdmission.Prepare("sender@example.invalid",DateTimeOffset.MaxValue,Settings(),Policies()));
    }
}

public sealed class ProductionRetentionAdmissionSqlTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    private sealed class Clock : TimeProvider { public override DateTimeOffset GetUtcNow()=>ProductionRetentionAdmissionContractTests.Now; }
    [Fact]
    public async Task Creation_and_rollback_share_the_normal_request_transaction_without_implicit_verification()
    {
        Guid id;
        await using(var db=fixture.Open()) {
            await using var tx=await db.Database.BeginTransactionAsync();var clock=new Clock();
            var e=await new ProductionRetentionAdmission(db,new(db,clock),clock).CreateLockedAsync("sender@example.invalid",
                ProductionRetentionAdmissionContractTests.Settings(),ProductionRetentionAdmissionContractTests.Policies());id=e.Id;
            Assert.False(e.IsDemo);Assert.Null(e.SenderVerifiedAt);Assert.Null(e.SentAt);
            var saved=await new ProductionRetentionLedger(db,new(db,clock),clock).ReadLockedAsync(id);
            Assert.Equal(ProductionEnrollmentKind.Enrolled,saved.Kind);Assert.Equal(365,saved.Enrollment!.Snapshot.Policy.CompletedDays);
            Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==id).ToArrayAsync());
            Assert.False(await db.EmailOutbox.AnyAsync(x=>x.EnvelopeId==id));
            await tx.RollbackAsync();
        }
        await using var check=fixture.Open();Assert.False(await check.Envelopes.AnyAsync(x=>x.Id==id));
        Assert.False(await check.ProductionRetentionPolicies.AnyAsync(x=>x.EnvelopeId==id));
    }

    [Fact]
    public async Task Invalid_operator_policy_writes_nothing_and_demo_has_no_production_enrollment()
    {
        await using var db=fixture.Open();await using var tx=await db.Database.BeginTransactionAsync();var clock=new Clock();
        var admission=new ProductionRetentionAdmission(db,new(db,clock),clock);var before=await db.Envelopes.CountAsync();
        await Assert.ThrowsAsync<DisclosureRejectedException>(()=>admission.CreateLockedAsync("sender@example.invalid",
            ProductionRetentionAdmissionContractTests.Settings(),new()));
        Assert.Equal(before,await db.Envelopes.CountAsync());Assert.Empty(db.ChangeTracker.Entries());
        var demo=await admission.CreateLockedAsync("sender@example.invalid",new(),new());
        Assert.True(demo.IsDemo);Assert.False(await db.ProductionRetentionPolicies.AnyAsync(x=>x.EnvelopeId==demo.Id));
        Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==demo.Id));await tx.RollbackAsync();
    }

    [Fact]
    public async Task A_later_configuration_change_cannot_move_a_saved_draft_deadline()
    {
        var settings=ProductionRetentionAdmissionContractTests.Settings();var clock=new Clock();Guid id;
        await using(var db=fixture.Open()) {
            await using var tx=await db.Database.BeginTransactionAsync();
            var e=await new ProductionRetentionAdmission(db,new(db,clock),clock).CreateLockedAsync("sender@example.invalid",settings,
                ProductionRetentionAdmissionContractTests.Policies());id=e.Id;await tx.CommitAsync();
        }
        settings.Mode="Demo";settings.Production.AbandonedDraftDays=365;
        await using var check=fixture.Open();await using var read=await check.Database.BeginTransactionAsync();
        var saved=await check.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==id);
        var result=await ProductionRecordRetentionAccess.ReadLockedAsync(check,saved,clock);
        Assert.Equal(ProductionRecordStage.Draft,result.Stage);
        Assert.Equal(clock.GetUtcNow().AddDays(3),result.Deadline);
        Assert.Single(await check.AuditEvents.Where(x=>x.EnvelopeId==id).ToArrayAsync());
        Assert.False(await check.ProductionRetentionTerminals.AnyAsync(x=>x.EnvelopeId==id));
    }

    [Fact]
    public async Task A_sent_record_does_not_inherit_the_abandoned_draft_cleanup_clock()
    {
        await using var h=await SendDraftWorkflowTests.Harness.Create(fixture,browser:true,
            productionRetention:ProductionRetentionAdmissionContractTests.Settings().Production);
        Assert.NotNull(await h.Send());h.Clock.Advance(TimeSpan.FromDays(5));
        await using var db=fixture.Open();await using var tx=await db.Database.BeginTransactionAsync();
        var e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Envelope.Id);
        var result=await ProductionRecordRetentionAccess.ReadLockedAsync(db,e,h.Clock);
        Assert.Equal(ProductionRecordStage.Signing,result.Stage);Assert.Null(result.Deadline);
        Assert.NotNull(result.Enrollment);
        Assert.False(await db.ProductionRetentionTerminals.AnyAsync(x=>x.EnvelopeId==e.Id));
    }
}
