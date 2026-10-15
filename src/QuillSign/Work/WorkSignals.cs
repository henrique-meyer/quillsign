using System.Globalization;
using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Storage.Queues;

namespace QuillSign.Work;

public sealed class WorkOptions
{
    public bool Enabled { get; set; }
    public string QueueServiceUri { get; set; } = "";
    public string QueueName { get; set; } = "";
    public string HintContainer { get; set; } = "";
    public int MaximumAttempts { get; set; } = 5;
    public int LeaseSeconds { get; set; } = 300;
    public int VisibilitySeconds { get; set; } = 360;
}

public sealed record WorkDelivery(string MessageId, string PopReceipt, Guid? WorkId);

public interface IWorkSignals
{
    Task PutHintAsync(Guid id, DateTimeOffset due, CancellationToken cancellationToken);
    Task RemoveHintAsync(Guid id, CancellationToken cancellationToken);
    Task PublishAsync(Guid id, TimeSpan delay, CancellationToken cancellationToken);
    Task<WorkDelivery?> ReceiveAsync(CancellationToken cancellationToken);
    Task DeferAsync(WorkDelivery delivery, TimeSpan delay, CancellationToken cancellationToken);
    Task AcknowledgeAsync(WorkDelivery delivery, CancellationToken cancellationToken);
    Task<int> RecoverAsync(DateTimeOffset now, CancellationToken cancellationToken);
    Task VerifyAsync(CancellationToken cancellationToken);
}

public sealed class AzureWorkSignals(QueueClient queue, BlobContainerClient hints, WorkOptions options, bool local) : IWorkSignals
{
    private async Task EnsureLocalAsync(CancellationToken cancellationToken)
    {
        if (!local) return;
        await queue.CreateIfNotExistsAsync(cancellationToken: cancellationToken);
        await hints.CreateIfNotExistsAsync(PublicAccessType.None, cancellationToken: cancellationToken);
    }

    public async Task PutHintAsync(Guid id, DateTimeOffset due, CancellationToken cancellationToken)
    {
        await EnsureLocalAsync(cancellationToken);
        // Hints have no user data. SQL, not the scheduling hint, owns the work state.
        await hints.GetBlobClient(id.ToString("N")).UploadAsync(BinaryData.FromString(""), new BlobUploadOptions
        {
            Metadata = new Dictionary<string, string> { ["due"] = due.UtcTicks.ToString(CultureInfo.InvariantCulture) }
        }, cancellationToken);
    }

    public async Task RemoveHintAsync(Guid id, CancellationToken cancellationToken)
        => await hints.GetBlobClient(id.ToString("N")).DeleteIfExistsAsync(cancellationToken: cancellationToken);

    public async Task PublishAsync(Guid id, TimeSpan delay, CancellationToken cancellationToken)
    {
        await EnsureLocalAsync(cancellationToken);
        await queue.SendMessageAsync(id.ToString("N"), delay, TimeSpan.FromSeconds(-1), cancellationToken);
    }

    public async Task<WorkDelivery?> ReceiveAsync(CancellationToken cancellationToken)
    {
        await EnsureLocalAsync(cancellationToken);
        var message = (await queue.ReceiveMessageAsync(TimeSpan.FromSeconds(options.VisibilitySeconds), cancellationToken)).Value;
        return message is null ? null : new WorkDelivery(message.MessageId, message.PopReceipt,
            Guid.TryParseExact(message.MessageText, "N", out var id) ? id : null);
    }

    public async Task DeferAsync(WorkDelivery delivery, TimeSpan delay, CancellationToken cancellationToken)
        => await queue.UpdateMessageAsync(delivery.MessageId, delivery.PopReceipt,
            delivery.WorkId?.ToString("N") ?? "invalid", delay, cancellationToken);

    public async Task AcknowledgeAsync(WorkDelivery delivery, CancellationToken cancellationToken)
        => await queue.DeleteMessageAsync(delivery.MessageId, delivery.PopReceipt, cancellationToken);

    public async Task<int> RecoverAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        await EnsureLocalAsync(cancellationToken);
        var count = 0;
        // Bound one recovery run; rotate page order through the continuation cursor so
        // many pending items do not starve later pages. No SQL or key-ring access here.
        var cursorBlob = hints.GetBlobClient("recovery-cursor");
        string? cursor = null;
        try { cursor = (await cursorBlob.DownloadContentAsync(cancellationToken)).Value.Content.ToString(); }
        catch (RequestFailedException e) when (e.Status == 404) { }
        var pages = hints.GetBlobsAsync(new GetBlobsOptions { Traits = BlobTraits.Metadata }, cancellationToken).AsPages(string.IsNullOrEmpty(cursor) ? null : cursor, 256);
        await foreach (var page in pages.WithCancellation(cancellationToken))
        {
            foreach (var hint in page.Values)
            {
                if (!Guid.TryParseExact(hint.Name, "N", out var id)) continue;
                if (!hint.Metadata.TryGetValue("due", out var due) || !long.TryParse(due, CultureInfo.InvariantCulture, out var ticks) || ticks <= now.UtcTicks)
                { await PublishAsync(id, TimeSpan.Zero, cancellationToken); count++; }
            }
            await cursorBlob.UploadAsync(BinaryData.FromString(page.ContinuationToken ?? ""), overwrite: true, cancellationToken);
            break;
        }
        return count;
    }

    public async Task VerifyAsync(CancellationToken cancellationToken)
    {
        await EnsureLocalAsync(cancellationToken);
        await queue.GetPropertiesAsync(cancellationToken);
        await hints.GetPropertiesAsync(cancellationToken: cancellationToken);
    }
}
