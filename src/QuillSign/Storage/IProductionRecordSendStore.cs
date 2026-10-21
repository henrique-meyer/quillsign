using System.Security.Claims;
using QuillSign.Lifecycle;

namespace QuillSign.Storage;

// Separate one-object Send contract; it cannot weaken upload's two-object plan.
internal interface IProductionRecordSendStore
{
    Task<ProductionRecordWriteReceipt> WriteAsync(ProductionRecordOperation scope, ClaimsPrincipal sender,
        ProductionRecordWriteDescriptor item, Stream source, bool mayWrite, ProductionRecordWriteReceipt? saved,
        Func<CancellationToken, Task> demand, CancellationToken ct = default);
}
