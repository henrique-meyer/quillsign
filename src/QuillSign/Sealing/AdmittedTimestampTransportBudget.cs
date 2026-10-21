using System.Diagnostics;

namespace QuillSign.Sealing;

// One monotonically consumed budget for the physical request/response awaits.
// No wall-clock authority is granted here: the original caller/lease token and
// all admission checks remain mandatory while this budget is paused.
internal sealed class AdmittedTimestampTransportBudget
{
    private readonly long maximumTicks;
    private long consumedTicks;
    private int active,stopped;
    internal AdmittedTimestampTransportBudget(TimeSpan maximum)
    {
        if(maximum<=TimeSpan.Zero || maximum>TimeSpan.FromMinutes(1))throw new ArgumentOutOfRangeException(nameof(maximum));
        maximumTicks=maximum.Ticks;
    }
    internal async Task<T> ExecuteAsync<T>(Func<CancellationToken,Task<T>> io,CancellationToken authority)
    {
        authority.ThrowIfCancellationRequested();
        if(Interlocked.CompareExchange(ref active,1,0)!=0)throw new InvalidOperationException("Timestamp transport awaits must be sequential.");
        try
        {
            var remaining=maximumTicks-Interlocked.Read(ref consumedTicks);
            if(Volatile.Read(ref stopped)!=0 || remaining<=0)throw new OperationCanceledException("The original timestamp transport budget is exhausted.");
            using var timeout=CancellationTokenSource.CreateLinkedTokenSource(authority);
            timeout.CancelAfter(TimeSpan.FromTicks(remaining));
            var started=Stopwatch.GetTimestamp();
            T result;
            try {result=await io(timeout.Token);}
            finally {Interlocked.Add(ref consumedTicks,Stopwatch.GetElapsedTime(started).Ticks);}
            if(Interlocked.Read(ref consumedTicks)>=maximumTicks || timeout.IsCancellationRequested)
            {
                if(result is IDisposable disposable)disposable.Dispose();
                authority.ThrowIfCancellationRequested();
                throw new OperationCanceledException("The original timestamp transport budget is exhausted.",timeout.Token);
            }
            return result;
        }
        catch {Volatile.Write(ref stopped,1);throw;}
        finally {Volatile.Write(ref active,0);}
    }
}
