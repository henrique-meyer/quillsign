using QuillSign.Lifecycle;

namespace QuillSign.Operator;

public sealed class ProductionOperatorOptions
{
    public bool Enabled { get; set; }
    public string Issuer { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string ClientSecret { get; set; } = "";
    public ProductionOperatorIdentity[] Grants { get; set; } = [];
    internal ProductionOperatorPolicy Policy()
    {
        if(!Enabled)return new(false,[]);
        if(!Uri.TryCreate(Issuer,UriKind.Absolute,out var uri)||uri.Scheme!="https"||uri.UserInfo.Length!=0||uri.Query.Length!=0||uri.Fragment.Length!=0||
            !ProductionOperatorAuthority.Text(ClientId,256)||!ProductionOperatorAuthority.Text(ClientSecret,4096)||Grants is not {Length:>=1 and <=256})throw Invalid();
        var grants=Grants.Select(x=>new ProductionOperatorGrant(Issuer,x.Subject,Permissions(x))).ToArray();
        if(grants.Any(x=>!ProductionOperatorAuthority.Text(x.Subject,256))||grants.Select(x=>x.Subject).Distinct(StringComparer.Ordinal).Count()!=grants.Length)throw Invalid();
        return new(true,grants);
    }
    private static IReadOnlySet<ProductionOperatorPermission> Permissions(ProductionOperatorIdentity g)
    {
        var p=new HashSet<ProductionOperatorPermission>();
        if(g.Status)p.Add(ProductionOperatorPermission.Status);if(g.PlaceHold)p.Add(ProductionOperatorPermission.PlaceHold);
        if(g.ReleaseHold)p.Add(ProductionOperatorPermission.ReleaseHold);if(g.ReadEvidence)p.Add(ProductionOperatorPermission.ReadEvidence);
        return p.Count>0?p:throw Invalid();
    }
    internal static InvalidOperationException Invalid()=>new("Configure the complete private operator identity and storage boundary before enabling it.");
}
public sealed class ProductionOperatorIdentity
{
    public string Subject { get; set; }="";
    public bool Status { get; set; }
    public bool PlaceHold { get; set; }
    public bool ReleaseHold { get; set; }
    public bool ReadEvidence { get; set; }
}
