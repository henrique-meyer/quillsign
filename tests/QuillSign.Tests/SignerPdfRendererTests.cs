using System.Security.Cryptography;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Signing;
using PigDocument=UglyToad.PdfPig.PdfDocument;

namespace QuillSign.Tests;

public sealed class SignerPdfRendererTests
{
    [Fact]
    public void All_types_preserve_source_and_hashes_and_derive_name_and_UTC_date_without_mutating_inputs()
    {
        var source=Source(); var request=Request(); var original=source.Bytes.ToArray(); var image=request.Marks!.Signature.ToArray();
        request=request with { FinishAt=new DateTimeOffset(2026,10,16,0,30,0,TimeSpan.FromHours(14)),Fields=request.Fields.Select(f=>f with { FilledAt=f.Type==FieldType.DateSigned ? null : new DateTimeOffset(2026,10,15,9,0,0,TimeSpan.Zero) }).ToArray() };
        var result=Renderer().Render(source.Bytes,SHA256.HashData(source.Bytes),source.Pages,request);
        Assert.Equal(original,source.Bytes); Assert.Equal(image,request.Marks.Signature); Assert.Equal(SHA256.HashData(original),result.SourceSha256); Assert.Equal(SHA256.HashData(result.Bytes),result.Sha256);
        Assert.Equal(32,result.BindingSha256.Length); Assert.Equal(request.EnvelopeId,result.EnvelopeId); Assert.Equal(request.SignerId,result.SignerId); Assert.Equal(SignerPdfRenderer.Version,result.RendererVersion);
        Assert.Equal(TimeSpan.Zero,result.FinishAt.Offset); using var pdf=PigDocument.Open(result.Bytes); Assert.Equal(2,pdf.NumberOfPages);
        foreach(var value in new[]{"Synthetic document","Synthetic signer","2026-10-15","Café","Καλημέρα","Пример","Second line","2028-02-29"})Assert.Contains(value,pdf.GetPage(1).Text);
        Assert.DoesNotContain("Second line",pdf.GetPage(2).Text); Assert.Contains("Synthetic document",pdf.GetPage(2).Text);
        Assert.Equal(2,pdf.GetPage(1).GetImages().Count());
    }
    [Fact]
    public void Sequential_copy_preserves_sender_and_prior_signer_contents_and_snapshot_binding_tracks_changes()
    {
        var source=Source(); var first=Request(); var one=Renderer().Render(source.Bytes,SHA256.HashData(source.Bytes),source.Pages,first);
        var signer2=Guid.NewGuid(); var later=first with { SignerId=signer2,FullName="Later synthetic signer",Fields=first.Fields.Select(f=>f with { Id=Guid.NewGuid(),SignerId=signer2,Page=2,Value=f.Type==FieldType.FullName ? "Later synthetic signer" : f.Value }).ToArray() };
        var two=Renderer().Render(one.Bytes,one.Sha256,source.Pages,later); Assert.Equal(one.Sha256,two.SourceSha256); Assert.NotEqual(one.BindingSha256,two.BindingSha256);
        using var parsed=PigDocument.Open(two.Bytes); Assert.Contains("Synthetic signer",parsed.GetPage(1).Text); Assert.Contains("Later synthetic signer",parsed.GetPage(2).Text); Assert.Contains("Synthetic document",parsed.GetPage(2).Text);
        var order=Renderer().Render(source.Bytes,SHA256.HashData(source.Bytes),source.Pages,first with { Fields=first.Fields.Reverse().ToArray() }); Assert.Equal(one.BindingSha256,order.BindingSha256);
        var revision=first with { Fields=first.Fields.Select(f=>f.Type==FieldType.Text ? f with { Revision=new byte[]{2,0,0,0,0,0,0,0} } : f).ToArray() };
        Assert.NotEqual(one.BindingSha256,Renderer().Render(source.Bytes,SHA256.HashData(source.Bytes),source.Pages,revision).BindingSha256);
    }
    [Fact]
    public void Empty_optional_fields_are_skipped_and_unchecked_is_an_explicit_rendered_response()
    {
        var source=Source(); var request=Request(); var extra=request.Fields.First(f=>f.Type==FieldType.Text) with { Id=Guid.NewGuid(),Page=2,Required=false,Value=null,FilledAt=null,FilledBy=null };
        var result=Renderer().Render(source.Bytes,SHA256.HashData(source.Bytes),source.Pages,request with { Fields=[..request.Fields,extra] });
        using var pdf=PigDocument.Open(result.Bytes); Assert.DoesNotContain("Café",pdf.GetPage(2).Text);
        var whitespace=extra with { Value=" \n ",FilledAt=request.FinishAt.AddMinutes(-1),FilledBy=PartyType.Signer };
        _=Renderer().Render(source.Bytes,SHA256.HashData(source.Bytes),source.Pages,request with { Fields=[..request.Fields,whitespace] });
    }
    [Theory]
    [InlineData("foreign-envelope")][InlineData("foreign-signer")][InlineData("unassigned")][InlineData("missing-id")]
    [InlineData("revision")][InlineData("duplicate")][InlineData("bad-type")][InlineData("bad-page")][InlineData("bounds")][InlineData("tiny")]
    [InlineData("missing-required")][InlineData("blank-required")][InlineData("unfilled")][InlineData("sender-filled")][InlineData("future-filled")]
    [InlineData("name-override")][InlineData("date-override")][InlineData("bad-date")][InlineData("bad-checkbox")][InlineData("overflow")]
    [InlineData("unicode")][InlineData("oversize")][InlineData("control")][InlineData("nonmark-binding")][InlineData("stale-adoption")]
    [InlineData("mark-ref")][InlineData("uppercase-ref")][InlineData("mark-hash")][InlineData("partial-mark")][InlineData("missing-marks")][InlineData("adoption-mismatch")]
    [InlineData("normalization")][InlineData("asset-hash")][InlineData("not-canonical")][InlineData("oversized-image")][InlineData("same-objects")][InlineData("unreadable-mark")]
    public void Invalid_snapshot_or_mark_evidence_fails_closed(string kind)
    {
        var source=Source(); var request=Request(); var fields=request.Fields.ToArray(); var index=Array.FindIndex(fields,f=>f.Type==FieldType.Text); var text=fields[index];
        if(kind is "foreign-envelope" or "foreign-signer" or "unassigned" or "missing-id" or "revision" or "bad-type" or "bad-page" or "bounds" or "tiny" or "missing-required" or "blank-required" or "unfilled" or "sender-filled" or "future-filled" or "overflow" or "unicode" or "oversize" or "control" or "nonmark-binding")
            fields[index]=kind switch {
                "foreign-envelope"=>text with { EnvelopeId=Guid.NewGuid() },"foreign-signer"=>text with { SignerId=Guid.NewGuid() },"unassigned"=>text with { SignerId=null },"missing-id"=>text with { Id=Guid.Empty },
                "revision"=>text with { Revision=[] },"bad-type"=>text with { Type=(FieldType)999 },"bad-page"=>text with { Page=3 },"bounds"=>text with { X=.9m },"tiny"=>text with { Width=.001m,Height=.001m },
                "missing-required"=>text with { Value=null,FilledAt=null,FilledBy=null },"blank-required"=>text with { Value=" " },"unfilled"=>text with { FilledAt=null },"sender-filled"=>text with { FilledBy=PartyType.Sender },"future-filled"=>text with { FilledAt=request.FinishAt.AddSeconds(1) },
                "overflow"=>text with { Value=new string('W',4000) },"unicode"=>text with { Value="漢字" },"oversize"=>text with { Value=new string('x',4001) },"control"=>text with { Value="bad\0text" },_=>text with { AdoptionId=request.AdoptionId } };
        if(kind=="duplicate")fields=[..fields,text];
        foreach(var type in new[]{FieldType.FullName,FieldType.DateSigned,FieldType.Date,FieldType.Checkbox,FieldType.Signature}) {
            var i=Array.FindIndex(fields,f=>f.Type==type); var f=fields[i];
            if(kind=="name-override" && type==FieldType.FullName)fields[i]=f with { Value="Override" };
            if(kind=="date-override" && type==FieldType.DateSigned)fields[i]=f with { Value="2026-10-16" };
            if(kind=="bad-date" && type==FieldType.Date)fields[i]=f with { Value="2026-02-30" };
            if(kind=="bad-checkbox" && type==FieldType.Checkbox)fields[i]=f with { Value="yes" };
            if(type==FieldType.Signature)fields[i]=kind switch { "stale-adoption"=>f with { AdoptionId=Guid.NewGuid() },"mark-ref"=>f with { Value=Guid.NewGuid().ToString("N") },"uppercase-ref"=>f with { Value=f.Value!.ToUpperInvariant() },"mark-hash"=>f with { ImageSha256=new byte[32] },"partial-mark"=>f with { AdoptionId=null },"unreadable-mark"=>f with { Width=.015m },_=>f };
        }
        var marks=request.Marks!;
        marks=kind switch { "normalization"=>marks with { NormalizationVersion="old" },"asset-hash"=>marks with { SignatureSha256=new byte[32] },"not-canonical"=>marks with { Signature=SignatureAdoptionTests.Mark(),SignatureSha256=SHA256.HashData(SignatureAdoptionTests.Mark()) },"oversized-image"=>marks with { Signature=new byte[SignaturePng.MaximumBytes+1] },"same-objects"=>marks with { InitialsObjectId=marks.SignatureObjectId },_=>marks };
        request=request with { Fields=fields,Marks=kind=="missing-marks" ? null : marks,AdoptionId=kind=="adoption-mismatch" ? Guid.NewGuid() : request.AdoptionId };
        RenderedSignerPdf? result=null; Assert.Throws<DocumentRejectedException>(()=>result=Renderer().Render(source.Bytes,SHA256.HashData(source.Bytes),source.Pages,request)); Assert.Null(result);
    }
    [Fact]
    public void Changed_source_geometry_and_memory_limits_fail_before_returning_a_candidate()
    {
        var source=Source(); var request=Request(); var hash=SHA256.HashData(source.Bytes);
        Assert.Throws<DocumentRejectedException>(()=>Renderer().Render([..source.Bytes,0],hash,source.Pages,request));
        Assert.Throws<DocumentRejectedException>(()=>Renderer().Render(source.Bytes,hash,[source.Pages[0] with { UserUnit=2 },source.Pages[1]],request));
        Assert.Throws<DocumentRejectedException>(()=>new SignerPdfRenderer(source.Bytes.Length-1,20,200).Render(source.Bytes,hash,source.Pages,request));
        Assert.Throws<DocumentRejectedException>(()=>new SignerPdfRenderer(source.Bytes.Length+2048,20,200).Render(source.Bytes,hash,source.Pages,request));
        Assert.Throws<DocumentRejectedException>(()=>new SignerPdfRenderer(25*1024*1024,1,200).Render(source.Bytes,hash,source.Pages,request));
        Assert.Throws<DocumentRejectedException>(()=>new SignerPdfRenderer(25*1024*1024,20,1).Render(source.Bytes,hash,source.Pages,request));
    }
    private static SignerPdfRenderer Renderer()=>new(25*1024*1024,20,200);
    [Theory]
    [InlineData("signed")][InlineData("xfa")][InlineData("encrypted")][InlineData("truncated")][InlineData("malformed")]
    public void Source_policy_is_rechecked_even_for_an_exact_hash(string kind)
    {
        var source=Source(); var bytes=kind switch {
            "signed"=>PdfFixtures.Create(catalog:"/AcroForm << /Fields [<< /FT /Sig /V << /Type /Sig /ByteRange [0 1 2 3] /Contents <0000> >> >>] >>"),
            "xfa"=>PdfFixtures.Create(catalog:"/AcroForm << /XFA (synthetic) >>"),"encrypted"=>PdfFixtures.Encrypted(false),
            "truncated"=>source.Bytes[..^10],_=>System.Text.Encoding.ASCII.GetBytes("%PDF-1.7\ninvalid synthetic PDF\n%%EOF") };
        Assert.Throws<DocumentRejectedException>(()=>Renderer().Render(bytes,SHA256.HashData(bytes),source.Pages,Request()));
    }
    [Fact]
    public async Task Sender_and_signer_renderers_share_font_work_safely_and_keep_values_isolated()
    {
        var source=Source(); var hash=SHA256.HashData(source.Bytes);
        var results=await Task.WhenAll(Enumerable.Range(0,6).Select(i=>Task.Run(()=> {
            var name="Parallel synthetic signer "+i;
            if(i%2==0)return new SenderPdfRenderer(25*1024*1024,20,200).Render(source.Bytes,hash,source.Pages,[new(Guid.NewGuid(),null,"Text",1,.1m,.2m,.7m,.1m,name)]).Bytes;
            var request=Request(); return Renderer().Render(source.Bytes,hash,source.Pages,request with { FullName=name,Fields=request.Fields.Select(f=>f.Type==FieldType.FullName ? f with { Value=name } : f).ToArray() }).Bytes;
        })));
        for(var i=0;i<results.Length;i++) { using var pdf=PigDocument.Open(results[i]); Assert.Contains("Parallel synthetic signer "+i,pdf.GetPage(1).Text); for(var j=0;j<results.Length;j++)if(i!=j)Assert.DoesNotContain("Parallel synthetic signer "+j,pdf.GetPage(1).Text); }
    }
    private static (byte[] Bytes,IReadOnlyList<PageGeometry> Pages) Source() { using var input=new MemoryStream(PdfFixtures.Create()); using var output=new MemoryStream(); var pages=new PdfValidation(new()).Rewrite(input,output); return(output.ToArray(),pages); }
    private static SignerPdfRequest Request()
    {
        var env=Guid.NewGuid(); var signer=Guid.NewGuid(); var adoption=Guid.NewGuid(); var sig=SignaturePng.Normalize(SignatureAdoptionTests.Mark()); var init=SignaturePng.Normalize(SignatureAdoptionTests.Mark(80));
        var marks=new SignerPdfMarks(adoption,Guid.NewGuid(),Guid.NewGuid(),sig.Bytes,init.Bytes,sig.Sha256,init.Sha256,SignaturePng.Version); var finish=new DateTimeOffset(2026,10,16,8,0,0,TimeSpan.Zero);
        var fields=Enum.GetValues<FieldType>().Select(type=>new SignerPdfField(Guid.NewGuid(),env,signer,new byte[]{1,0,0,0,0,0,0,0},type,1,.1m,.2m+(int)type*.1m,.7m,.08m,true,
            type switch { FieldType.Signature=>marks.SignatureObjectId.ToString("N"),FieldType.Initials=>marks.InitialsObjectId.ToString("N"),FieldType.FullName=>"Synthetic signer",FieldType.DateSigned=>null,FieldType.Text=>"Cafe\u0301 — Καλημέρα — Пример\nSecond line",FieldType.Checkbox=>"false",_=>"2028-02-29" },
            type==FieldType.DateSigned ? null : finish.AddHours(-1),type==FieldType.DateSigned ? null : PartyType.Signer,
            type is FieldType.Signature or FieldType.Initials ? adoption : null,type==FieldType.Signature ? sig.Sha256 : type==FieldType.Initials ? init.Sha256 : null)).ToArray();
        return new(env,signer,"Synthetic signer",finish,adoption,fields,marks);
    }
}
