using QuillSign.Sealing;
using QuillSign.Storage;

namespace QuillSign.Lifecycle;

internal sealed partial class VerifiedCompletionEffectReceipt
{
    // Called only by the concrete composed writer/engine boundary after their
    // exact bytes/version/protection/request validation, never from HTTP input.
    internal static VerifiedCompletionEffectReceipt FromStored(CompletionEffectDescriptor effect,ProductionCompletionStored actual)
    {
        if(ProductionCompletionProtocol.Tsa(effect.Effect))throw ProductionCompletionProtocol.Invalid();
        var receipt=new CompletionEffectReceipt(effect,ProductionCompletionProtocol.Digest(actual),actual.Receipt,actual.Final);
        return new(receipt);
    }
    internal static VerifiedCompletionEffectReceipt FromTimestamp(CompletionEffectDescriptor effect,ProductionTimestampRequest request,ProductionTimestampResponse response)
    {
        if(!ProductionCompletionProtocol.Tsa(effect.Effect)||effect.Sha256!=request.Sha256||effect.MaximumRequests!=1)throw ProductionCompletionProtocol.Invalid();
        return new(new(effect,ProductionCompletionProtocol.Digest(new{Request=request,Response=response}),null));
    }
}
