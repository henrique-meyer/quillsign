using QuillSign.Data;
using QuillSign.Lifecycle;

namespace QuillSign.Work;

public sealed class WorkProcessor(WorkStore store, IWorkSignals signals, IEnumerable<IWorkHandler> handlers, TimeProvider time)
{
    public async Task<bool> RunOnceAsync(CancellationToken cancellationToken)
    {
        var delivery = await signals.ReceiveAsync(cancellationToken);
        if (delivery is null) return false; // Empty queue must never open SQL.
        if (delivery.WorkId is not { } id)
        { await signals.AcknowledgeAsync(delivery, cancellationToken); return true; }
        // A storage hint can postpone a wake, never authorize execution. Missing or
        // malformed hints still require SQL's authoritative available-at/lease gate.
        DateTimeOffset? scheduled;
        try { scheduled = await signals.ReadDueAsync(id, cancellationToken); }
        catch (Exception e) when (!cancellationToken.IsCancellationRequested &&
            e is Azure.RequestFailedException or IOException or HttpRequestException or TimeoutException or OperationCanceledException)
        {
            await signals.DeferAsync(delivery, TimeSpan.FromMinutes(15), cancellationToken);
            return true; // Preserve the hint and avoid SQL during a storage outage.
        }
        if (scheduled > time.GetUtcNow())
        {
            await signals.DeferAsync(delivery, Delay(scheduled.Value), cancellationToken);
            return true;
        }
        WorkClaim claim;
        try { claim = await store.ClaimAsync(id, cancellationToken); }
        catch (ProductionWorkBlockedException)
        {
            await signals.DeferAsync(delivery, TimeSpan.FromMinutes(15), cancellationToken);
            return true;
        }
        catch (Exception e) when (SqlResume.IsUnavailable(e))
        {
            // A database paused on allowance exhaustion must not cause a hot loop.
            var delay = TimeSpan.FromMinutes(15);
            await signals.PutHintAsync(id, time.GetUtcNow() + delay, cancellationToken);
            await signals.DeferAsync(delivery, delay, cancellationToken);
            return true;
        }
        if(claim.PrivateRefused){var delay=TimeSpan.FromMinutes(15);await signals.PutHintAsync(id,time.GetUtcNow()+delay,cancellationToken);await signals.DeferAsync(delivery,delay,cancellationToken);return true;}
        if (claim.Terminal || claim.PrivateHandoff)
        {
            await signals.RemoveHintAsync(id, cancellationToken);
            await signals.AcknowledgeAsync(delivery, cancellationToken);
            return true;
        }
        if (claim.RetryAt is { } retryAt)
        {
            await signals.DeferAsync(delivery, Delay(retryAt), cancellationToken);
            return true;
        }
        var lease = claim.Lease!;
        var handler = handlers.SingleOrDefault(x => x.Kind == lease.Kind);
        var result = handler is null ? new WorkResult(WorkOutcome.Failed, "unsupported-work-kind") : await handler.ExecuteAsync(lease, cancellationToken);
        var next = await store.FinishAsync(lease, result, cancellationToken);
        if (next is { } due)
        {
            await signals.PutHintAsync(id, due, cancellationToken);
            await signals.DeferAsync(delivery, Delay(due), cancellationToken);
        }
        else
        {
            await signals.RemoveHintAsync(id, cancellationToken);
            await signals.AcknowledgeAsync(delivery, cancellationToken);
        }
        return true;
    }

    private TimeSpan Delay(DateTimeOffset due) => TimeSpan.FromSeconds(Math.Clamp((due - time.GetUtcNow()).TotalSeconds, 1, 7 * 24 * 60 * 60));
}
