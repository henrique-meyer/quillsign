using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using QuillSign.Data;

namespace QuillSign.Completion;

// Additional lifetime restriction only. Existing storage capabilities remain
// mandatory. No caller callback here can create or widen read authority.
internal static class CompletionReadRestriction
{
    private static readonly AsyncLocal<Scope?> Current=new();
    internal static IDisposable Enter(QuillSignDbContext db,Action demand)
    {
        var physical=db.Database.CurrentTransaction?.GetDbTransaction()??throw new InvalidOperationException("A live caller transaction is required.");
        if(physical.Connection is null)throw new InvalidOperationException("A live caller transaction is required.");
        var scope=new Scope(db,physical,demand,Current.Value);scope.Demand(db);Current.Value=scope;return scope;
    }
    internal static IDisposable Enter(QuillSignDbContext db,Func<Task> demand)
    {
        var physical=db.Database.CurrentTransaction?.GetDbTransaction()??throw new InvalidOperationException("A live caller transaction is required.");
        if(physical.Connection is null)throw new InvalidOperationException("A live caller transaction is required.");
        var scope=new Scope(db,physical,()=>{},Current.Value,demand);scope.Demand(db);Current.Value=scope;return scope;
    }
    internal static async Task ReadAsync(QuillSignDbContext db,Func<Task> read)
    {
        var scope=Current.Value;if(scope is not null)await scope.DemandAsync(db);await read();if(scope is not null)await scope.DemandAsync(db);
    }
    internal static async Task<T> ReadAsync<T>(QuillSignDbContext db,Func<Task<T>> read)
    {
        var scope=Current.Value;if(scope is not null)await scope.DemandAsync(db);var result=await read();if(scope is not null)await scope.DemandAsync(db);return result;
    }
    private sealed class Scope(QuillSignDbContext db,DbTransaction physical,Action demand,Scope? previous,Func<Task>? asyncDemand=null):IDisposable
    {
        private bool closed;
        internal void Demand(QuillSignDbContext current)
        {
            if(closed || !ReferenceEquals(db,current) || physical.Connection is null || !ReferenceEquals(current.Database.CurrentTransaction?.GetDbTransaction(),physical))
                throw new InvalidDataException("Completion read lifetime is unavailable.");
            demand();
        }
        internal async Task DemandAsync(QuillSignDbContext current){Demand(current);if(asyncDemand is not null){await asyncDemand();Demand(current);}}
        public void Dispose()
        {
            if(closed)return;
            closed=true;
            if(ReferenceEquals(Current.Value,this))Current.Value=previous;
        }
    }
}
