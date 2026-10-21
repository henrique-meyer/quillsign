using System.Security.Claims;
using QuillSign.Lifecycle;

namespace QuillSign.Storage;

// Private upload-only provider contract. A replay can read the exact attempted
// object, but cannot stage or commit it again. No delete/protection API is exposed.
internal interface IProductionRecordUploadStore
{
    Task<ProductionRecordWriteReceipt> WriteAsync(ProductionRecordOperation scope, ClaimsPrincipal sender, ProductionRecordWriteDescriptor item,
        Stream source, bool mayWrite, ProductionRecordWriteReceipt? saved, Func<CancellationToken, Task> demand,
        CancellationToken ct = default);
}
