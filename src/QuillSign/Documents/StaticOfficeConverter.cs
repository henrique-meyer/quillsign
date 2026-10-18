using System.Security.Cryptography;

namespace QuillSign.Documents;

public enum OfficeSourceKind {Pptx,Xlsx,Odt}
public sealed class OfficeConversionOptions {public bool PptxEnabled {get;set;}public bool XlsxEnabled {get;set;}public bool OdtEnabled {get;set;}}

// Constructed only by a successful family gate; callers cannot substitute later source bytes.
public sealed class ValidatedOfficeSource:IDisposable
{
    private readonly object gate=new();private byte[]? bytes;private byte[]? conversion;private readonly byte[] hash;private readonly byte[] conversionHash;
    internal ValidatedOfficeSource(byte[] bytes,OfficeSourceKind kind,int pages,double width,double height,byte[]? conversion=null){this.bytes=bytes;this.conversion=conversion??bytes;hash=SHA256.HashData(bytes);conversionHash=SHA256.HashData(this.conversion);Length=bytes.Length;ConversionLength=this.conversion.Length;Kind=kind;ExpectedPages=pages;Width=width;Height=height;}
    public OfficeSourceKind Kind {get;}
    public long Length {get;}
    internal long ConversionLength {get;}
    public int ExpectedPages {get;}
    public double Width {get;}
    public double Height {get;}
    public byte[] OriginalSha256 {get{lock(gate){ObjectDisposedException.ThrowIf(bytes is null,this);return hash.ToArray();}}}
    internal byte[] ConversionSha256 {get{lock(gate){ObjectDisposedException.ThrowIf(bytes is null,this);return conversionHash.ToArray();}}}
    public Stream OpenRead(){lock(gate){ObjectDisposedException.ThrowIf(bytes is null,this);return new MemoryStream(bytes!.ToArray(),false);}}
    internal Stream OpenConversionRead(){lock(gate){ObjectDisposedException.ThrowIf(bytes is null,this);return new MemoryStream(conversion!.ToArray(),false);}}
    public void Dispose(){lock(gate){if(bytes is null)return;Array.Clear(bytes);if(!ReferenceEquals(bytes,conversion)&&conversion is not null)Array.Clear(conversion);Array.Clear(hash);Array.Clear(conversionHash);bytes=conversion=null;}}
}

// Internal component: no public intake, persistence, new work producer or sandbox fallback.
public sealed class StaticOfficeConverter(OfficeConversionOptions options,GotenbergDocxConverter converter)
{
    public async Task<DocxConversion> ConvertAsync(ValidatedOfficeSource package,CancellationToken ct=default)
    {
        ct.ThrowIfCancellationRequested();ArgumentNullException.ThrowIfNull(package);
        if(!(package.Kind==OfficeSourceKind.Pptx&&options.PptxEnabled||package.Kind==OfficeSourceKind.Xlsx&&options.XlsxEnabled||package.Kind==OfficeSourceKind.Odt&&options.OdtEnabled))throw new DocumentConversionUnavailableException("This Office format is not enabled.");
        var originalHash=package.OriginalSha256;var expected=package.ConversionSha256;
        DocxConversion result;
        try {result=await converter.ConvertOfficeAsync(package,ct);}
        catch {Array.Clear(expected);Array.Clear(originalHash);throw;}
        var matches=CryptographicOperations.FixedTimeEquals(expected,result.OriginalSha256);Array.Clear(expected);
        if(!matches)
        {Array.Clear(result.Pdf);Array.Clear(result.PdfSha256);Array.Clear(result.OriginalSha256);Array.Clear(originalHash);throw new InvalidDataException("Converted source verification failed.");}
        if(package.ExpectedPages>0&&result.Pages.Count!=package.ExpectedPages || result.Pages.Any(x=>x.Rotation!=0||x.UserUnit!=1||Math.Abs(x.Width-package.Width)>.1||Math.Abs(x.Height-package.Height)>.1))
        {Array.Clear(result.Pdf);Array.Clear(result.PdfSha256);Array.Clear(result.OriginalSha256);Array.Clear(originalHash);throw new DocumentRejectedException("The converted pages did not match the supported Office print profile. Export a PDF and try again.");}
        Array.Clear(result.OriginalSha256);return result with {OriginalSha256=originalHash};
    }
}
