using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;
using QuillSign.Data;

namespace QuillSign.Signing;

public sealed record SignerFieldViewData(SignerReadContext Context,SignerFieldSnapshot Snapshot,AdoptedSignatureData? Marks)
{
    public int Missing => Snapshot.Fields.Count(f => f.Required && !f.Filled && f.Type != FieldType.DateSigned);
    public int Stale => Snapshot.Fields.Count(f => f.Stale);
    public static string Status(SignerFieldItem f) => f.Type == FieldType.DateSigned ? "Set by the server at Finish" :
        f.Stale ? "Reapply or clear: adopted marks changed" : f.Filled ? "Saved" : f.Required ? "Required — missing" : "Optional — empty";
    public static string Label(SignerFieldItem f) => string.IsNullOrWhiteSpace(f.Label) ? f.Type switch {
        FieldType.FullName => "Full name",FieldType.DateSigned => "Date signed",_ => f.Type.ToString() } : f.Label;
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    public string ToJson() => JsonSerializer.Serialize(new { Snapshot,Marks },Json);
}

// No mutations or receipt refresh. The last snapshot must match the exact verified mark pair.
public sealed class SignerFieldView(SignerAccess access,SignerFields fields,SignatureAdoption adoption,SignerPdfAccess pdf)
{
    public async Task<SignerFieldViewData?> ReadAsync(ClaimsPrincipal user,string publicId,bool verifyPdf,CancellationToken ct)
    {
        var context=await access.GetContextAsync(user,publicId,ct); if(context?.ConsentAt is null)return null;
        if(verifyPdf)_=await pdf.PrepareAsync(user,context,ct);
        var marks=context.SignatureAdoptionId is null ? null : await adoption.ReadCurrentAsync(user,publicId,ct);
        var snapshot=await fields.GetAsync(user,publicId,ct); if(snapshot is null)return null;
        if(snapshot.AdoptionId!=marks?.Id)throw new InvalidDataException("Current marks could not be verified. Reload before applying or reviewing them.");
        context=await access.GetContextAsync(user,publicId,ct);
        if(context?.ConsentAt is null || context.SignatureAdoptionId!=snapshot.AdoptionId)return null;
        return new(context,snapshot,marks);
    }
}
