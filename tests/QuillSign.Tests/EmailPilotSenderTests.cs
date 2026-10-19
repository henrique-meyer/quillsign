using System.Data.Common;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Amazon;
using Amazon.Runtime;
using Amazon.SimpleEmailV2;
using Amazon.SimpleEmailV2.Model;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using MimeKit;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Sender;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class EmailPilotSenderTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Disabled_sender_does_not_resolve_any_authority_database_or_credentials()
    {
        var sender = new EmailPilotSender(new(), new(), new(), () => throw new Exception("No authority"),
            () => throw new Exception("No ledger"), () => throw new Exception("No SQL"), _ => throw new Exception("No credentials"), TimeProvider.System);
        await Assert.ThrowsAsync<EmailPilotTransportRefusedException>(() => sender.SendAsync(null!, null!));
    }

    [Fact]
    public async Task Actual_claim_reserves_exact_wire_bytes_once_before_lazy_raw_provider_access()
    {
        await using var h = New(); var (id, lease) = await h.Claim();
        using var client = new CaptureSes(); var factories = 0;
        var sender = h.Sender(settings => { factories++; return new SesPreparedEmailTransport(client, settings); });
        var message = h.Message(id) with { Attachments = [new("executed.pdf", "%PDF-1.7\nSynthetic non-agreement\n%%EOF"u8.ToArray())] };
        Assert.Equal(new EmailDelivery("Ses", "synthetic-id"), await sender.SendAsync(lease, message));
        Assert.False(h.Email.Enabled); Assert.Equal(1, factories); Assert.Equal(1, client.Calls);
        var saved = await h.Db.EmailPilotReservations.AsNoTracking().SingleAsync(x => x.SubjectEnvelopeId == id);
        Assert.Equal(client.Bytes!.Length, saved.EncodedBytes); Assert.Equal(SHA256.HashData(client.Bytes), saved.RequestSha256);
        var request = client.Request!; Assert.Null(request.Content.Simple); Assert.Null(request.Content.Template);
        Assert.Equal(message.To, Assert.Single(request.Destination.ToAddresses)); Assert.Empty(request.Destination.CcAddresses ?? []); Assert.Empty(request.Destination.BccAddresses ?? []);
        Assert.Equal(h.Email.FromEmail, request.FromEmailAddress); Assert.Equal(h.Email.Ses.ConfigurationSet, request.ConfigurationSetName);
        using var raw = new MemoryStream(client.Bytes); using var mime = await MimeMessage.LoadAsync(raw);
        Assert.Single(mime.To); Assert.Empty(mime.Cc); Assert.Empty(mime.Bcc); Assert.Equal(message.Subject, mime.Subject);
        Assert.Single(mime.Attachments); Assert.False(request.Content.Raw.Data.CanRead);
        // Newly generated Date/Message-ID on replay never grants a second call.
        await Assert.ThrowsAsync<EmailPilotTransportRefusedException>(() => sender.SendAsync(lease, message));
        Assert.Equal(1, factories); Assert.Equal(1, client.Calls); Assert.Equal(1, (await h.Ledger.ReadBudgetAsync())!.ApplicationAttempts);
    }

    [Theory]
    [InlineData("recipient")][InlineData("envelope")][InlineData("lease")][InlineData("expired")][InlineData("suppressed")]
    [InlineData("disabled")][InlineData("work-disabled")][InlineData("public-email")][InlineData("provider")][InlineData("oversize")][InlineData("cancelled")][InlineData("sender-config")]
    public async Task Invalid_inputs_expiry_suppression_and_gates_never_resolve_provider(string change)
    {
        await using var h = New(); var (id, lease) = await h.Claim(); var message = h.Message(id); var factories = 0;
        if (change == "recipient") message = message with { To = h.Options.Mailboxes.FirstSigner };
        if (change == "envelope") message = message with { EnvelopeId = Guid.NewGuid() };
        if (change == "lease") lease = lease with { Owner = Guid.NewGuid() };
        if (change == "expired") h.Clock.Now = lease.Until;
        if (change == "suppressed") { h.Db.Suppressions.Add(new() { Email = message.To }); await h.Db.SaveChangesAsync(); }
        if (change == "disabled") h.Options.Enabled = false;
        if (change == "work-disabled") h.Work.Enabled = false;
        if (change == "public-email") h.Email.Enabled = true;
        if (change == "provider") h.Email.Provider = "Smtp";
        if (change == "sender-config") h.Email.FromEmail = "";
        if (change == "oversize") message = message with { Text = new string('x', PreparedRawMime.MaximumBytes) };
        using var cts = new CancellationTokenSource(); if (change == "cancelled") cts.Cancel();
        var sender = h.Sender(_ => { factories++; throw new Exception("No credentials expected"); });
        Assert.NotNull(await Record.ExceptionAsync(() => sender.SendAsync(lease, message, cts.Token)));
        Assert.Equal(0, factories); Assert.False(await h.Db.EmailPilotReservations.AnyAsync(x => x.SubjectEnvelopeId == id));
    }

    [Fact]
    public async Task Exhausted_application_budget_cannot_resolve_credentials_or_add_a_reservation()
    {
        await using var h = New(); var (id, lease) = await h.Claim(); var factories = 0;
        for (var i = 0; i < EmailPilotLimits.ApplicationAttempts; i++)
            Assert.Equal(EmailPilotReservationOutcome.Reserved, await h.Ledger.ReserveAsync(new(Guid.NewGuid(), id, Guid.NewGuid(),
                EmailPilotAttemptKind.Application, EmailPilotRole.Sender, 1, new string('a', 64)), h.Options.Mailboxes.Sender));
        await Assert.ThrowsAsync<EmailPilotTransportRefusedException>(() => h.Sender(_ => { factories++; throw new Exception("No credentials"); }).SendAsync(lease, h.Message(id)));
        Assert.Equal(0, factories); Assert.Equal(EmailPilotLimits.ApplicationAttempts, (await h.Ledger.ReadBudgetAsync())!.ApplicationAttempts);
    }

    [Fact]
    public async Task Factory_that_crosses_lease_expiry_cannot_call_the_provider()
    {
        await using var h = New(); var (id, lease) = await h.Claim(); var calls = 0;
        var sender = h.Sender(_ => { h.Clock.Now = lease.Until; return new CaptureTransport(() => calls++); });
        await Assert.ThrowsAsync<EmailPilotTransportRefusedException>(() => sender.SendAsync(lease, h.Message(id)));
        Assert.Equal(0, calls); Assert.Equal(1, await h.Db.EmailPilotReservations.CountAsync(x => x.SubjectEnvelopeId == id));
    }

    [Fact]
    public async Task Suppression_received_during_lazy_factory_prevents_the_provider_call()
    {
        await using var h = New(); var (id, lease) = await h.Claim(); var calls = 0;
        var sender = h.Sender(_ => {
            h.Db.Suppressions.Add(new() { Email = h.Options.Mailboxes.Sender }); h.Db.SaveChanges();
            return new CaptureTransport(() => calls++);
        });
        await Assert.ThrowsAsync<RecipientSuppressedException>(() => sender.SendAsync(lease, h.Message(id)));
        Assert.Equal(0, calls); Assert.Equal(1, await h.Db.EmailPilotReservations.CountAsync(x => x.SubjectEnvelopeId == id));
    }

    [Theory]
    [InlineData("expiry")][InlineData("public-email")][InlineData("capability")][InlineData("source")][InlineData("settings")][InlineData("suppression")][InlineData("lost-ack")]
    public async Task Changes_or_lost_ack_after_real_reservation_commit_never_reach_credentials_and_never_refund(string change)
    {
        await using var h = New(); var (id, lease) = await h.Claim(); var factories = 0;
        await using var reservationDb = h.Open(new AfterCommit(async () => {
            if (change == "expiry") h.Clock.Now = lease.Until;
            if (change == "public-email") h.Email.Enabled = true;
            if (change == "capability") h.Admission.CapabilitySha256 = new string('a', 64);
            if (change == "source") await h.Db.WorkItems.Where(x => x.Id == lease.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.PayloadJson, "{}"));
            if (change == "settings") h.Email.Ses.ConfigurationSet = "changed";
            if (change == "suppression") { h.Db.Suppressions.Add(new() { Email = h.Options.Mailboxes.Sender }); await h.Db.SaveChangesAsync(); }
            if (change == "lost-ack") throw new IOException("Synthetic lost reservation acknowledgement.");
        }));
        var sender = h.Sender(_ => { factories++; throw new Exception("No credentials expected"); }, () => h.For(reservationDb));
        Assert.NotNull(await Record.ExceptionAsync(() => sender.SendAsync(lease, h.Message(id))));
        Assert.Equal(0, factories); Assert.Equal(1, await h.Db.EmailPilotReservations.CountAsync(x => x.SubjectEnvelopeId == id));
        if (change == "lost-ack")
        {
            await Assert.ThrowsAsync<EmailPilotTransportRefusedException>(() => h.Sender(_ => { factories++; throw new Exception("No replay"); }).SendAsync(lease, h.Message(id)));
            Assert.Equal(0, factories);
        }
    }

    [Theory]
    [InlineData("factory")][InlineData("definite")][InlineData("unknown")][InlineData("cancelled")]
    public async Task Provider_or_credential_failures_consume_attempt_without_replay(string failure)
    {
        await using var h = New(); var (id, lease) = await h.Claim(); var factories = 0; using var client = new CaptureSes();
        client.Failure = failure switch { "definite" => new AmazonSimpleEmailServiceV2Exception("Synthetic rejection") { StatusCode = HttpStatusCode.BadRequest },
            "cancelled" => new OperationCanceledException("Synthetic unknown submission"), _ => new IOException("Synthetic unknown submission") };
        var sender = h.Sender(settings => { factories++; if (failure == "factory") throw new IOException("Synthetic credential failure"); return new SesPreparedEmailTransport(client, settings); });
        Assert.NotNull(await Record.ExceptionAsync(() => sender.SendAsync(lease, h.Message(id))));
        await Assert.ThrowsAsync<EmailPilotTransportRefusedException>(() => sender.SendAsync(lease, h.Message(id)));
        Assert.Equal(1, factories); Assert.Equal(failure == "factory" ? 0 : 1, client.Calls);
        Assert.Equal(1, (await h.Ledger.ReadBudgetAsync())!.ApplicationAttempts);
    }

    [Fact]
    public async Task Concurrent_same_attempt_across_independent_contexts_allows_only_one_provider_call()
    {
        await using var h = New(); var (id, lease) = await h.Claim(); var calls = 0;
        async Task<Exception?> Send()
        {
            await using var db = fixture.Open();
            var service = h.Sender(_ => new CaptureTransport(() => Interlocked.Increment(ref calls)), db: db);
            return await Record.ExceptionAsync(() => service.SendAsync(lease, h.Message(id)));
        }
        var results = await Task.WhenAll(Send(), Send());
        Assert.Equal(1, calls); Assert.Single(results, x => x is null); Assert.Single(results, x => x is EmailPilotTransportRefusedException);
        Assert.Equal(1, await h.Db.EmailPilotReservations.CountAsync(x => x.SubjectEnvelopeId == id));
    }

    [Theory]
    [InlineData("retry")][InlineData("region")][InlineData("endpoint")][InlineData("sender")][InlineData("http")]
    public async Task Raw_adapter_refuses_unsafe_client_or_mismatched_sender_before_sdk_call(string change)
    {
        using var client = new CaptureSes(); var settings = new EmailPilotSesSettings("sender@example.invalid", "Synthetic", "us-east-1", "synthetic");
        var prepared = await PreparedRawMime.PrepareAsync(new("recipient@example.invalid", "Synthetic", "Text", "HTML"), settings.FromEmail, settings.FromName);
        if (change == "retry") ((AmazonSimpleEmailServiceV2Config)client.Config).MaxErrorRetry = 1;
        if (change == "http") ((AmazonSimpleEmailServiceV2Config)client.Config).UseHttp = true;
        if (change == "region") settings = settings with { Region = "us-east-2" };
        if (change == "endpoint") ((AmazonSimpleEmailServiceV2Config)client.Config).ServiceURL = "https://example.invalid";
        if (change == "sender") settings = settings with { FromEmail = "other@example.invalid" };
        await Assert.ThrowsAsync<EmailPilotTransportRefusedException>(() => new SesPreparedEmailTransport(client, settings).SendAsync(prepared, default));
        Assert.Equal(0, client.Calls);
    }

    private Harness New() => new(fixture.Open());
    private sealed class Harness(QuillSignDbContext db) : IAsyncDisposable
    {
        internal readonly QuillSignDbContext Db = db;
        internal readonly EmailPilotOptions Options = new() { Enabled = true, RunId = Guid.NewGuid().ToString("N") };
        internal readonly EmailOptions Email = new() { FromEmail = "noreply@example.invalid", Ses = new() { Region = "us-east-1", ConfigurationSet = "synthetic" } };
        internal readonly WorkOptions Work = new() { Enabled = true };
        internal readonly EmailPilotAdmissionOptions Admission = new() { CapabilitySha256 = Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(Capability))) };
        internal readonly EmailPilotAdmissionTests.Clock Clock = new();
        private readonly IDataProtectionProvider keys = new EphemeralDataProtectionProvider();
        private const string Capability = "1234567890123456789012345678901234567890123";
        internal EmailPilotLedger Ledger => For(Db);
        internal EmailPilotLedger For(QuillSignDbContext context) => new(Options, Email, () => context, () => new(keys), Clock);
        internal QuillSignDbContext Open(DbTransactionInterceptor interceptor) => new(new DbContextOptionsBuilder<QuillSignDbContext>()
            .UseSqlServer(Db.Database.GetConnectionString()).AddInterceptors(interceptor).Options);
        internal async Task<(Guid, WorkLease)> Claim()
        {
            Options.Mailboxes = new("sender-" + Options.RunId + "@example.invalid", "first@example.invalid", "second@example.invalid", "recipient@example.invalid");
            var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
                ["ConnectionStrings:Database"] = "configured", ["Storage:Provider"] = "Azurite" }).Build();
            var payload = new EmailPayloadProtection(keys);
            var service = new EmailPilotAdmission(Options, Admission, Email, Work, new SenderOptions(), () => new(Email, Work, config), () => Ledger,
                () => new(Db, new EmailPilotAdmissionTests.Signals(), payload, Work, Email, Clock), () => payload, Clock);
            var admitted = (await service.RequestAsync(Capability, EmailPilotScenario.Completion))!;
            return (admitted.EnvelopeId, (await new WorkStore(Db, Work, Clock).ClaimAsync(admitted.VerificationWorkId, default)).Lease!);
        }
        internal OutgoingEmail Message(Guid id) => new(Options.Mailboxes.Sender, "Synthetic non-agreement", "Text", "<p>Text</p>", id);
        internal EmailPilotSender Sender(Func<EmailPilotSesSettings,IPreparedEmailTransport> provider, Func<EmailPilotLedger>? ledger = null, QuillSignDbContext? db = null)
        {
            var context = db ?? Db;
            return new(Options, Email, Work, () => new(Options, Email, Work, Admission, () => For(context), () => context, () => new(keys), Clock),
                ledger ?? (() => For(context)), () => context, provider, Clock);
        }
        public ValueTask DisposeAsync() => Db.DisposeAsync();
    }
    private sealed class AfterCommit(Func<Task> after) : DbTransactionInterceptor
    { public override async Task TransactionCommittedAsync(DbTransaction transaction, TransactionEndEventData eventData, CancellationToken ct = default) => await after(); }
    private sealed class CaptureTransport(Action call) : IPreparedEmailTransport
    { public Task<EmailDelivery> SendAsync(PreparedRawMime message, CancellationToken ct) { ct.ThrowIfCancellationRequested(); call(); return Task.FromResult(new EmailDelivery("Synthetic", "synthetic-id")); } }
    private sealed class CaptureSes() : AmazonSimpleEmailServiceV2Client(new AnonymousAWSCredentials(), new AmazonSimpleEmailServiceV2Config { RegionEndpoint = RegionEndpoint.USEast1, MaxErrorRetry = 0 })
    {
        internal int Calls; internal SendEmailRequest? Request; internal byte[]? Bytes; internal Exception? Failure;
        public override async Task<SendEmailResponse> SendEmailAsync(SendEmailRequest request, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested(); Calls++; Request = request;
            using var bytes = new MemoryStream(); await request.Content.Raw.Data.CopyToAsync(bytes, cancellationToken); Bytes = bytes.ToArray();
            if (Failure is not null) throw Failure; return new() { MessageId = "synthetic-id" };
        }
    }
}
