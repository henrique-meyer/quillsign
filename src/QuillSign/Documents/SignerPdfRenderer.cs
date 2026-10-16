using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PdfSharp.Drawing;
using PdfSharp.Pdf;
using PdfSharp.Pdf.IO;
using QuillSign.Data;
using QuillSign.Signing;

namespace QuillSign.Documents;

public sealed record SignerPdfField(Guid Id,Guid EnvelopeId,Guid? SignerId,byte[] Revision,FieldType Type,int Page,
    decimal X,decimal Y,decimal Width,decimal Height,bool Required,string? Value,DateTimeOffset? FilledAt,PartyType? FilledBy,
    Guid? AdoptionId=null,byte[]? ImageSha256=null);
public sealed record SignerPdfMarks(Guid AdoptionId,Guid SignatureObjectId,Guid InitialsObjectId,byte[] Signature,byte[] Initials,
    byte[] SignatureSha256,byte[] InitialsSha256,string NormalizationVersion);
public sealed record SignerPdfRequest(Guid EnvelopeId,Guid SignerId,string FullName,DateTimeOffset FinishAt,
    Guid? AdoptionId,IReadOnlyList<SignerPdfField> Fields,SignerPdfMarks? Marks=null);
public sealed record RenderedSignerPdf(byte[] Bytes,byte[] Sha256,byte[] SourceSha256,byte[] BindingSha256,
    Guid EnvelopeId,Guid SignerId,Guid? AdoptionId,DateTimeOffset FinishAt,string RendererVersion);

// Pure renderer. Its caller must authorize locked server state and own publication/audit/Finish.
// No client DTO, database, storage or signing-state mutation is exposed here.
public sealed class SignerPdfRenderer
{
    public const string Version="signer-pdf-v1";
    private readonly long maximumBytes; private readonly int maximumPages,maximumFields;
    public SignerPdfRenderer(long maximumBytes,int maximumPages,int maximumFields)
    {
        if(maximumBytes<1 || maximumPages is <1 or >200 || maximumFields is <1 or >200)throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        this.maximumBytes=Math.Min(maximumBytes,64*1024*1024); this.maximumPages=maximumPages; this.maximumFields=maximumFields;
    }
    public RenderedSignerPdf Render(byte[] source,byte[] expectedHash,IReadOnlyList<PageGeometry> expectedPages,SignerPdfRequest request)
    {
        if(source is null || source.LongLength is <16 || source.LongLength>maximumBytes || expectedHash is not { Length:32 } ||
            expectedPages is null || expectedPages.Count<1 || expectedPages.Count>maximumPages || request is null ||
            request.EnvelopeId==Guid.Empty || request.SignerId==Guid.Empty || request.FinishAt==default || request.Fields is null || request.Fields.Count>maximumFields)
            throw Rejected();
        lock(SenderPdfRenderer.RenderGate)
        {
            var bytes=source.ToArray(); var hash=SHA256.HashData(bytes); if(!Same(hash,expectedHash))throw Rejected();
            var pages=expectedPages.Select(p=>p is not null && p.MediaBox is { Length:4 } && p.CropBox is { Length:4 } ?
                p with { MediaBox=p.MediaBox.ToArray(),CropBox=p.CropBox.ToArray() } : throw Rejected()).ToArray();
            var fields=request.Fields.Select(f=>f is not null && f.Revision is { Length:8 } && (f.ImageSha256 is null or { Length:32 }) ?
                f with { Revision=f.Revision.ToArray(),ImageSha256=f.ImageSha256?.ToArray() } : throw Rejected())
                .OrderBy(f=>f.Page).ThenBy(f=>f.Y).ThenBy(f=>f.X).ThenBy(f=>f.Id).ToArray();
            var finish=request.FinishAt.ToUniversalTime(); var name=Canonical(request.FullName); if(string.IsNullOrWhiteSpace(name))throw Rejected();
            var marks=OwnMarks(request.Marks,request.AdoptionId);
            var ids=new HashSet<Guid>(); var values=new Dictionary<Guid,string>();
            foreach(var field in fields)
            {
                if(field.Id==Guid.Empty || !ids.Add(field.Id) || field.EnvelopeId!=request.EnvelopeId || field.SignerId!=request.SignerId ||
                    !Enum.IsDefined(field.Type) || field.Page<1 || field.Page>pages.Length || !FieldGeometry.InBounds(field.X,field.Y,field.Width,field.Height))throw Rejected();
                if(field.Type==FieldType.DateSigned)
                {
                    if(field.Value is not null || field.FilledAt is not null || field.FilledBy is not null || field.AdoptionId is not null || field.ImageSha256 is not null)throw Rejected();
                    values.Add(field.Id,finish.ToString("yyyy-MM-dd",CultureInfo.InvariantCulture)); continue;
                }
                var empty=field.Value is null && field.FilledAt is null && field.FilledBy is null && field.AdoptionId is null && field.ImageSha256 is null;
                if(empty) { if(field.Required)throw Rejected(); continue; }
                if(field.Value is null || field.FilledAt is null || field.FilledAt>finish || field.FilledBy!=PartyType.Signer)throw Rejected();
                if(field.Type is FieldType.Signature or FieldType.Initials)
                {
                    if(marks is null || field.AdoptionId!=marks.AdoptionId ||
                        field.Value!=(field.Type==FieldType.Signature ? marks.SignatureObjectId : marks.InitialsObjectId).ToString("N") ||
                        !Same(field.ImageSha256,field.Type==FieldType.Signature ? marks.SignatureSha256 : marks.InitialsSha256))throw Rejected();
                    values.Add(field.Id,field.Value); continue;
                }
                if(field.AdoptionId is not null || field.ImageSha256 is not null)throw Rejected();
                var value=Canonical(field.Value);
                if(field.Type==FieldType.FullName && value!=name)throw Rejected();
                if(field.Type==FieldType.Text && string.IsNullOrWhiteSpace(value)) { if(field.Required)throw Rejected(); continue; }
                SenderPdfRenderer.ValidateValue(new(field.Id,null,field.Type==FieldType.FullName ? "Text" : field.Type.ToString(),field.Page,field.X,field.Y,field.Width,field.Height,value));
                values.Add(field.Id,field.Type==FieldType.FullName ? name : value);
            }
            using var input=new MemoryStream(bytes,false); using var normalized=new MemoryStream();
            var actualPages=new PdfValidation(new() { MaximumBytes=maximumBytes,MaximumPages=maximumPages }).Rewrite(input,new BoundedDocumentStream(normalized,maximumBytes));
            if(!SenderPdfRenderer.GeometryMatches(actualPages,pages))throw Rejected();
            EmbeddedPdfFont.EnsureInitialized(); normalized.Position=0;
            using var document=PdfReader.Open(normalized,PdfDocumentOpenMode.Modify);
            for(var i=0;i<document.PageCount;i++)
            {
                var onPage=fields.Where(f=>f.Page==i+1 && values.ContainsKey(f.Id)).ToArray(); if(onPage.Length==0)continue;
                var page=document.Pages[i]; var p=actualPages[i]; var rotation=page.Rotate;
                var width=p.Rotation is 90 or 270 ? p.Height : p.Width; var height=p.Rotation is 90 or 270 ? p.Width : p.Height;
                page.Rotate=0;
                try
                {
                    using var g=XGraphics.FromPdfPage(page,XGraphicsPdfPageOptions.Append); g.MultiplyTransform(SenderPdfRenderer.DisplayToGraphics(p));
                    foreach(var f in onPage)
                    {
                        var box=new XRect((double)f.X*width,(double)f.Y*height,(double)f.Width*width,(double)f.Height*height);
                        if(f.Type is FieldType.Signature or FieldType.Initials)DrawImage(g,f.Type==FieldType.Signature ? marks!.Signature : marks!.Initials,box);
                        else if(f.Type==FieldType.Checkbox)SenderPdfRenderer.DrawCheckbox(g,values[f.Id]=="true",box);
                        else SenderPdfRenderer.DrawText(g,values[f.Id],box);
                    }
                }
                finally { page.Rotate=rotation; }
            }
            using var output=new MemoryStream(); document.Save(new BoundedDocumentStream(output,maximumBytes),false); var rendered=output.ToArray();
            var binding=SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {
                renderer=Version,request.EnvelopeId,request.SignerId,sourceSha256=Convert.ToHexStringLower(hash),fullName=name,finishAt=finish,request.AdoptionId,
                signatureSha256=marks?.SignatureSha256,initialsSha256=marks?.InitialsSha256,normalization=marks?.NormalizationVersion,
                fields=fields.OrderBy(f=>f.Id).Select(f=>new { f.Id,f.Revision,f.Type,f.Page,f.X,f.Y,f.Width,f.Height,f.Required,
                    value=values.GetValueOrDefault(f.Id),f.FilledAt,f.FilledBy,f.AdoptionId,f.ImageSha256 }) }));
            return new(rendered,SHA256.HashData(rendered),hash,binding,request.EnvelopeId,request.SignerId,request.AdoptionId,finish,Version);
        }
    }
    private static SignerPdfMarks? OwnMarks(SignerPdfMarks? source,Guid? adoptionId)
    {
        if(source is null) { if(adoptionId is not null)throw Rejected(); return null; }
        if(source.AdoptionId==Guid.Empty || source.AdoptionId!=adoptionId || source.SignatureObjectId==Guid.Empty || source.InitialsObjectId==Guid.Empty ||
            source.SignatureObjectId==source.InitialsObjectId || source.NormalizationVersion!=SignaturePng.Version ||
            source.Signature is not { Length:>=57 and <=SignaturePng.MaximumBytes } || source.Initials is not { Length:>=57 and <=SignaturePng.MaximumBytes } ||
            source.SignatureSha256 is not { Length:32 } || source.InitialsSha256 is not { Length:32 })throw Rejected();
        var owned=source with { Signature=source.Signature.ToArray(),Initials=source.Initials.ToArray(),SignatureSha256=source.SignatureSha256.ToArray(),InitialsSha256=source.InitialsSha256.ToArray() };
        try
        {
            foreach(var (image,hash) in new[]{(owned.Signature,owned.SignatureSha256),(owned.Initials,owned.InitialsSha256)})
                if(!Same(SHA256.HashData(image),hash) || !SignaturePng.Normalize(image).Bytes.AsSpan().SequenceEqual(image))throw Rejected();
        }
        catch(SignatureImageRejectedException) { throw Rejected(); }
        return owned;
    }
    private static string Canonical(string value)
    {
        if(value is null || value.Length>4000)throw Rejected();
        try { _=new UTF8Encoding(false,true).GetBytes(value); return value.Replace("\r\n","\n").Replace('\r','\n').Normalize(NormalizationForm.FormC); }
        catch(ArgumentException) { throw Rejected(); }
    }
    private static void DrawImage(XGraphics g,byte[] bytes,XRect box)
    {
        if(Math.Min(box.Width,box.Height)<8)throw Rejected();
        using var stream=new MemoryStream(bytes,0,bytes.Length,false,true); using var image=XImage.FromStream(stream);
        var scale=Math.Min(box.Width/image.PixelWidth,box.Height/image.PixelHeight); var w=image.PixelWidth*scale; var h=image.PixelHeight*scale;
        if(Math.Min(w,h)<8)throw Rejected();
        g.DrawImage(image,box.X+(box.Width-w)/2,box.Y+(box.Height-h)/2,w,h);
    }
    private static bool Same(byte[]? a,byte[] b)=>a is { Length:32 } && CryptographicOperations.FixedTimeEquals(a,b);
    private static DocumentRejectedException Rejected()=>new("The signer field snapshot, mark binding or PDF could not be verified for rendering.");
}
