using System.Security.Cryptography;

namespace QuillSign.Documents;

public enum OfficeSourceKind {Pptx}
public sealed class OfficeConversionOptions {public bool PptxEnabled {get;set;}}

// Constructed only by a successful family gate; callers cannot substitute later source bytes.
public sealed class ValidatedOfficeSource:IDisposable
{
    private readonly object gate=new();private byte[]? bytes;private readonly byte[] hash;
    internal ValidatedOfficeSource(byte[] bytes,OfficeSourceKind kind,int pages,double width,double height){this.bytes=bytes;hash=SHA256.HashData(bytes);Length=bytes.Length;Kind=kind;ExpectedPages=pages;Width=width;Height=height;}
    public OfficeSourceKind Kind {get;}
    public long Length {get;}
    public int ExpectedPages {get;}
    public double Width {get;}
    public double Height {get;}
    public byte[] OriginalSha256 {get{lock(gate){ObjectDisposedException.ThrowIf(bytes is null,this);return hash.ToArray();}}}
    public Stream OpenRead(){lock(gate){ObjectDisposedException.ThrowIf(bytes is null,this);return new MemoryStream(bytes!.ToArray(),false);}}
    public void Dispose(){lock(gate){if(bytes is null)return;Array.Clear(bytes);Array.Clear(hash);bytes=null;}}
}

// Internal component: no public intake, persistence, new work producer or sandbox fallback.
public sealed class StaticOfficeConverter(OfficeConversionOptions options,GotenbergDocxConverter converter)
{
    public async Task<DocxConversion> ConvertAsync(ValidatedOfficeSource package,CancellationToken ct=default)
    {
        ct.ThrowIfCancellationRequested();ArgumentNullException.ThrowIfNull(package);
        if(package.Kind!=OfficeSourceKind.Pptx || !options.PptxEnabled)throw new DocumentConversionUnavailableException("This Office format is not enabled.");
        var expected=package.OriginalSha256;
        DocxConversion result;
        try {result=await converter.ConvertOfficeAsync(package,ct);}
        catch {Array.Clear(expected);throw;}
        var matches=CryptographicOperations.FixedTimeEquals(expected,result.OriginalSha256);Array.Clear(expected);
        if(!matches)
        {Array.Clear(result.Pdf);Array.Clear(result.PdfSha256);Array.Clear(result.OriginalSha256);throw new InvalidDataException("Converted source verification failed.");}
        if(result.Pages.Count!=package.ExpectedPages || result.Pages.Any(x=>x.Rotation!=0||x.UserUnit!=1||Math.Abs(x.Width-package.Width)>.1||Math.Abs(x.Height-package.Height)>.1))
        {Array.Clear(result.Pdf);Array.Clear(result.PdfSha256);Array.Clear(result.OriginalSha256);throw new DocumentRejectedException("The converted slide pages did not match the supported presentation. Export a PDF and try again.");}
        return result;
    }
}
