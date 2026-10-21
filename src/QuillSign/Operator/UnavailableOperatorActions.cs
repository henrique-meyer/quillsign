namespace QuillSign.Operator;
internal sealed class UnavailableOperatorActions:IProductionOperatorActions
{
    private static UnauthorizedAccessException Denied()=>new("Private operator controls are unavailable.");
    public Task<ProductionOperatorView> StatusAsync(HttpContext c,Guid id,bool inspect,CancellationToken ct)=>throw Denied();
    public Task<ProductionOperatorReview> ReviewAsync(HttpContext c,Guid id,string op,Guid? hold,string purpose,string reason,string reference,CancellationToken ct)=>throw Denied();
    public Task<string> ExecuteAsync(HttpContext c,string token,CancellationToken ct)=>throw Denied();
    public Task<byte[]> ExportAsync(HttpContext c,Guid id,string purpose,CancellationToken ct)=>throw Denied();
}
