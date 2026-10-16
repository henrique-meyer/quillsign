using System.Security.Cryptography;
using PdfSharp.Pdf.IO;
using QuillSign.Completion;
using QuillSign.Documents;
using QuillSign.Sealing;
using QuillSign.Signing;

namespace QuillSign.Tests;

public sealed class CompletionCertificateRendererTests
{
    [Fact]
    public void Existing_preparation_field_bounds_preserve_full_details_instead_of_rejecting_or_truncating_long_party_rows()
    {
        var f=Fixture(); var name=new string('W',512); var role=new string('R',512); var agent=new string('A',2048);
        var evidence=f.Evidence with {Document=f.Evidence.Document with {Name=new string('D',512)},
            Signers=f.Evidence.Signers.Select(s=>s.Order==1 ? s with {Name=name,Role=role,UserAgent=agent} : s).ToArray(),
            Recipients=new[]{new CompletionRecipient(new string('N',512),"recipient@example.invalid")}};
        var packet=new CompletionCertificateRenderer().PreparePacket(f.Source,f.Pages,evidence);
        using var pdf=UglyToad.PdfPig.PdfDocument.Open(packet.AppendixBytes); var text=Compact(Text(pdf));
        // Page headers/footers can interrupt extraction of one long value; count its distinct glyph runs across pages.
        foreach(var (glyph,count) in new[]{('W',512),('R',512),('A',2048),('D',512),('N',512)})
            Assert.Equal(count,System.Text.RegularExpressions.Regex.Matches(text,glyph+"{2,}").Sum(m=>m.Length));
        Assert.Contains("Seesigner1detailsbelow",text); Assert.Contains("Auditchronologythroughsnapshot",text);
    }
    [Fact]
    public void Long_party_rows_repeat_table_headers_and_preserve_all_twenty_signers_without_page_overflow()
    {
        var f=Fixture(); var start=f.Evidence.PreparedAt.AddHours(-2); var template=f.Evidence.Signers[0];
        var signers=Enumerable.Range(1,20).Select(i=>template with {Id=Guid.NewGuid(),Order=i,Name="Synthetic "+new string('W',180)+" "+i,
            Email="synthetic"+i+"@example.invalid",EmailVerifiedAt=start.AddMinutes(i*5),ViewedAt=start.AddMinutes(i*5+1),ConsentedAt=start.AddMinutes(i*5+2),
            FinishedAt=start.AddMinutes(i*5+3),CheckpointAt=start.AddMinutes(i*5+4),CheckpointSha256=i==20 ? f.SourceHash : Hash("checkpoint "+i)}).ToArray();
        var evidence=f.Evidence with {Sender=f.Evidence.Sender with {VerifiedAt=start},Signers=signers};
        var packet=new CompletionCertificateRenderer().PreparePacket(f.Source,f.Pages,evidence);
        using var report=UglyToad.PdfPig.PdfDocument.Open(packet.AppendixBytes); var text=Text(report);
        for(var i=1;i<=20;i++)Assert.Contains("synthetic"+i+"@example.invalid",text);
        Assert.True(report.GetPages().Count(p=>UglyToad.PdfPig.DocumentLayoutAnalysis.TextExtractor.ContentOrderTextExtractor.GetText(p).Contains("Signer / role"))>=2);
        Assert.All(report.GetPages().SelectMany(p=>p.Letters.Select(l=>(p,l))),item=> {
            Assert.InRange(item.l.BoundingBox.Left,-.5,item.p.Width+.5); Assert.InRange(item.l.BoundingBox.Right,-.5,item.p.Width+.5);
            Assert.InRange(item.l.BoundingBox.Bottom,-.5,item.p.Height+.5); Assert.InRange(item.l.BoundingBox.Top,-.5,item.p.Height+.5);
        });
    }
    [Fact]
    public void Tall_normalized_marks_fit_the_certificate_without_stretching_or_crossing_page_bounds()
    {
        var f=Fixture(); var image=SignaturePng.Normalize(TallPng()); var mark=new CompletionMark(image.Bytes,image.Sha256,SignaturePng.Version);
        var evidence=f.Evidence with {Signers=f.Evidence.Signers.Select(s=>s.Order==1 ? s with {Signature=mark} : s).ToArray()};
        var packet=new CompletionCertificateRenderer().PreparePacket(f.Source,f.Pages,evidence);
        using var pdf=UglyToad.PdfPig.PdfDocument.Open(packet.AppendixBytes);
        var embedded=Assert.Single(pdf.GetPages().SelectMany(p=>p.GetImages()),i=>i.WidthInSamples==image.Width && i.HeightInSamples==image.Height);
        Assert.InRange(embedded.BoundingBox.Height,.1,42.6); Assert.InRange(embedded.BoundingBox.Width,.01,113.4);
        Assert.InRange(Math.Abs(embedded.BoundingBox.Width/embedded.BoundingBox.Height-(double)image.Width/image.Height),0,.001);
    }
    [Fact]
    public async Task Real_packet_and_standalone_share_evidence_but_only_standalone_contains_the_executed_file_hash()
    {
        var f=Fixture(); var renderer=new CompletionCertificateRenderer(); var packet=renderer.PreparePacket(f.Source,f.Pages,f.Evidence);
        Assert.Equal(f.SourceHash,packet.SourceSha256); Assert.Equal(SHA256.HashData(packet.Bytes),packet.Sha256); Assert.True(packet.CertificatePages>1);
        Assert.Equal(CompletionCertificateRenderer.Version,packet.RendererVersion);
        using var appended=UglyToad.PdfPig.PdfDocument.Open(packet.AppendixBytes); var text=Text(appended);
        Assert.Contains("SYNTHETIC TEST ONLY - NO AGREEMENT",text); Assert.Contains("DEMO",text); Assert.Contains("Élodie",text);
        Assert.Contains("Not recorded",text); Assert.Contains("[U+202E]",text); Assert.Contains("[U+4E00]",text); Assert.Contains("<script>alert(1)</script>",text);
        Assert.Contains("one-time link to s***@example.invalid",text); Assert.Contains("signer@example.invalid",text);
        for(var i=1;i<=f.Evidence.Events.Count;i++)Assert.Contains("Event "+i+" - synthetic_event_"+i,text);
        Assert.Contains(Convert.ToHexStringLower(packet.EvidenceSha256),Compact(text));
        Assert.Contains("cannot be embedded",text); Assert.DoesNotContain("Executed PDF SHA-256:",text);
        Assert.True(appended.GetPages().SelectMany(p=>p.GetImages()).Count()>=4);
        Assert.All(appended.GetPages(),p=> {var pageText=UglyToad.PdfPig.DocumentLayoutAnalysis.TextExtractor.ContentOrderTextExtractor.GetText(p); Assert.Contains("QuillSign",pageText); Assert.Contains("Certificate page",pageText);});
        await using var seal=await SealFixtures.Create(); var executed=await seal.Engine.SealAsync(packet.Bytes,packet.Sha256);
        var standalone=renderer.PrepareStandalone(f.Evidence,packet,executed);
        Assert.Equal(packet.EvidenceSha256,standalone.EvidenceSha256); Assert.Equal(executed.Sha256,standalone.ExecutedSha256);
        Assert.Equal(SHA256.HashData(standalone.Bytes),standalone.Sha256);
        using var separate=UglyToad.PdfPig.PdfDocument.Open(standalone.Bytes); var separateText=Text(separate);
        Assert.Contains("Executed PDF SHA-256:",separateText); Assert.Contains(Convert.ToHexStringLower(executed.Sha256),Compact(separateText));
        Assert.Contains(executed.CertificateSha256,Compact(separateText)); Assert.Contains(executed.TimestampCertificateSha256,Compact(separateText));
        Assert.Contains(Convert.ToHexStringLower(packet.EvidenceSha256),Compact(separateText));
        Assert.DoesNotContain(Convert.ToHexStringLower(standalone.Sha256),Compact(separateText));
        // Both forms can be sealed by the production engine, independently of envelope mutation/publication.
        var sealedCertificate=await seal.Engine.SealAsync(standalone.Bytes,standalone.Sha256);
        _=await new SealCms(seal.Options,seal.Timestamps).VerifyAsync(sealedCertificate.Bytes,seal.Seal,sealedCertificate.SealedAt,default);
        Assert.Equal(2,seal.Requests);
        if(Environment.GetEnvironmentVariable("QUILLSIGN_COMPLETION_ARTIFACTS") is {Length:>0} path) {
            Directory.CreateDirectory(path); await File.WriteAllBytesAsync(Path.Combine(path,"source.pdf"),f.Source);
            await File.WriteAllBytesAsync(Path.Combine(path,"appendix.pdf"),packet.AppendixBytes); await File.WriteAllBytesAsync(Path.Combine(path,"executed.pdf"),executed.Bytes);
            await File.WriteAllBytesAsync(Path.Combine(path,"certificate.pdf"),sealedCertificate.Bytes);
        }
    }
    [Theory]
    [InlineData(0)][InlineData(90)][InlineData(180)][InlineData(270)]
    public void Packet_preserves_original_page_content_geometry_rotation_and_user_unit(int rotation)
    {
        var f=Fixture(rotation); var packet=new CompletionCertificateRenderer().PreparePacket(f.Source,f.Pages,f.Evidence);
        using var original=PdfReader.Open(new MemoryStream(f.Source),PdfDocumentOpenMode.Import); using var result=PdfReader.Open(new MemoryStream(packet.Bytes),PdfDocumentOpenMode.Import);
        Assert.Equal(original.PageCount+packet.CertificatePages,result.PageCount);
        for(var i=0;i<original.PageCount;i++) {
            Assert.Equal(original.Pages[i].MediaBox,result.Pages[i].MediaBox); Assert.Equal(original.Pages[i].CropBoxReadOnly,result.Pages[i].CropBoxReadOnly);
            Assert.Equal(rotation,result.Pages[i].Rotate); Assert.Equal(1.25,result.Pages[i].Elements.GetReal("/UserUnit"));
        }
        using var before=UglyToad.PdfPig.PdfDocument.Open(f.Source); using var after=UglyToad.PdfPig.PdfDocument.Open(packet.Bytes);
        for(var page=1;page<=before.NumberOfPages;page++)Assert.Equal(before.GetPage(page).Text,after.GetPage(page).Text);
    }
    [Theory]
    [InlineData("order")][InlineData("finish")][InlineData("checkpoint")][InlineData("disclosure")][InlineData("adoption")]
    [InlineData("image-hash")][InlineData("image-canonical")][InlineData("image-size")][InlineData("sequence")][InlineData("previous")]
    [InlineData("anchor")][InlineData("current-hash")][InlineData("email")][InlineData("title")][InlineData("unicode")]
    [InlineData("event-count")][InlineData("agent-size")][InlineData("aggregate")][InlineData("missing-name")]
    public void Incomplete_stale_or_oversized_evidence_never_produces_a_packet(string mode)
    {
        var f=Fixture(); var e=f.Evidence; var signer=e.Signers[0]; var mark=signer.Signature!;
        signer=mode switch {
            "order"=>signer with {Order=2},"finish"=>signer with {FinishedAt=signer.ConsentedAt.AddSeconds(-1)},
            "checkpoint"=>signer with {CheckpointSha256=Hash("other checkpoint")},"disclosure"=>signer with {DisclosureSha256=Hash("other disclosure")},
            "adoption"=>signer with {AdoptionId=null},"image-hash"=>signer with {Signature=mark with {Sha256=Hash("other mark")}},
            "image-canonical"=>signer with {Signature=new(SignatureAdoptionTests.Mark(),SHA256.HashData(SignatureAdoptionTests.Mark()),SignaturePng.Version)},
            "image-size"=>signer with {Signature=mark with {Png=new byte[SignaturePng.MaximumBytes+1]}},"agent-size"=>signer with {UserAgent=new string('x',2049)},
            "missing-name"=>signer with {Name=""},_=>signer};
        e=e with {Signers=new[]{signer}.Concat(e.Signers.Skip(1)).ToArray()};
        if(mode=="checkpoint")e=e with {Signers=e.Signers.Select(s=>s.Order==2 ? s with {CheckpointSha256=Hash("other checkpoint")} : s).ToArray()};
        if(mode=="sequence")e=e with {Events=e.Events.Select(x=>x.Sequence==2 ? x with {Sequence=3} : x).ToArray()};
        if(mode=="previous")e=e with {Events=e.Events.Select(x=>x.Sequence==2 ? x with {PreviousHash=Hash("wrong previous")} : x).ToArray()};
        if(mode=="anchor")e=e with {AuditAnchor=Hash("wrong anchor")};
        if(mode=="current-hash")e=e with {Document=e.Document with {CurrentSha256=Hash("wrong source")}};
        if(mode=="email")e=e with {Sender=e.Sender with {Email="Display Name <sender@example.invalid>"}};
        if(mode=="title")e=e with {Document=e.Document with {Name=new string('x',513)}};
        if(mode=="unicode")e=e with {Document=e.Document with {Name="invalid\uD800"}};
        if(mode=="event-count")e=e with {Events=Enumerable.Repeat(e.Events[0],513).ToArray()};
        if(mode=="aggregate") {
            var events=new List<CompletionEvent>(); var previous=new byte[32];
            for(var i=1;i<=200;i++) {var hash=Hash("large event "+i); events.Add(new(i,e.PreparedAt,"synthetic","System","Synthetic",null,new string('x',1024),previous,hash)); previous=hash;}
            e=e with {Events=events,AuditAnchor=previous};
        }
        Assert.Throws<DocumentRejectedException>(()=>new CompletionCertificateRenderer().PreparePacket(f.Source,f.Pages,e));
    }
    [Theory]
    [InlineData("source")][InlineData("geometry")][InlineData("page-limit")][InlineData("certificate-pages")][InlineData("output-bytes")]
    public void Source_geometry_and_total_output_limits_fail_closed(string mode)
    {
        var f=Fixture(); var renderer=new CompletionCertificateRenderer(); var pages=f.Pages;
        if(mode=="source")f.Source[30]^=1;
        if(mode=="geometry")pages=pages.Select(p=>p with {Width=p.Width+1}).ToArray();
        if(mode=="page-limit")renderer=new(maximumPages:3);
        if(mode=="certificate-pages")renderer=new(maximumCertificatePages:1);
        if(mode=="output-bytes")renderer=new(maximumBytes:4096);
        Assert.Throws<DocumentRejectedException>(()=>renderer.PreparePacket(f.Source,pages,f.Evidence));
    }
    [Theory]
    [InlineData("evidence")][InlineData("packet")][InlineData("source-binding")][InlineData("executed-hash")]
    [InlineData("executed-bytes")][InlineData("pages")][InlineData("seal-time")][InlineData("certificate-id")]
    public void Standalone_rejects_cross_phase_changes_and_inconsistent_verified_engine_results(string mode)
    {
        var f=Fixture(); var renderer=new CompletionCertificateRenderer(); var packet=renderer.PreparePacket(f.Source,f.Pages,f.Evidence);
        // A structurally populated result is sufficient for rejection tests; successful output is tested with the real engine above.
        var executed=new SealedPdf(packet.Bytes,SHA256.HashData(packet.Bytes),packet.Sha256,packet.DocumentPages+packet.CertificatePages,"Synthetic",Convert.ToHexStringLower(Hash("cert")),f.Evidence.PreparedAt.AddSeconds(1),f.Evidence.PreparedAt.AddSeconds(1),Convert.ToHexStringLower(Hash("tsa")),"1.2.3");
        if(mode=="evidence")f=f with {Evidence=f.Evidence with {Sender=f.Evidence.Sender with {Name="Changed name"}}};
        if(mode=="packet")packet=packet with {Bytes=new byte[]{1,2,3}};
        if(mode=="source-binding")executed=executed with {SourceSha256=Hash("other source")};
        if(mode=="executed-hash")executed=executed with {Sha256=Hash("other output")};
        if(mode=="executed-bytes")executed=executed with {Bytes=new byte[]{1,2,3}};
        if(mode=="pages")executed=executed with {PageCount=1};
        if(mode=="seal-time")executed=executed with {SealedAt=f.Evidence.PreparedAt.AddSeconds(-1)};
        if(mode=="certificate-id")executed=executed with {CertificateSha256="unverified"};
        Assert.Throws<DocumentRejectedException>(()=>renderer.PrepareStandalone(f.Evidence,packet,executed));
    }
    [Fact]
    public void Cancellation_prevents_both_rendering_phases_without_a_partial_result()
    {
        var f=Fixture(); var renderer=new CompletionCertificateRenderer(); var cancelled=new CancellationToken(true);
        Assert.ThrowsAny<OperationCanceledException>(()=>renderer.PreparePacket(f.Source,f.Pages,f.Evidence,cancelled));
        Assert.ThrowsAny<OperationCanceledException>(()=>renderer.PrepareStandalone(f.Evidence,null!,null!,cancelled));
    }
    private static string Text(UglyToad.PdfPig.PdfDocument pdf)=>string.Join("\n",pdf.GetPages().Select(p=>UglyToad.PdfPig.DocumentLayoutAnalysis.TextExtractor.ContentOrderTextExtractor.GetText(p)));
    private static string Compact(string text)=>new(text.Where(c=>!char.IsWhiteSpace(c)).ToArray());
    private static byte[] Hash(string value)=>SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value));
    private static byte[] TallPng()
    {
        var header=new byte[13]; System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(header,1); System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(4),1000); header[8]=8; header[9]=6;
        using var raw=new MemoryStream(); for(var i=0;i<1000;i++)raw.Write(new byte[]{0,20,40,80,255});
        using var compressed=new MemoryStream(); using(var z=new System.IO.Compression.ZLibStream(compressed,System.IO.Compression.CompressionLevel.Optimal,true))z.Write(raw.ToArray());
        using var png=new MemoryStream(); png.Write(new byte[]{137,80,78,71,13,10,26,10});
        foreach(var part in new[]{("IHDR",header),("IDAT",compressed.ToArray()),("IEND",Array.Empty<byte>())}) {
            var type=System.Text.Encoding.ASCII.GetBytes(part.Item1); var length=new byte[4]; System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(length,part.Item2.Length); png.Write(length); png.Write(type); png.Write(part.Item2);
            uint crc=uint.MaxValue; foreach(var value in type.Concat(part.Item2)) {crc^=value; for(var bit=0;bit<8;bit++)crc=(crc&1)!=0 ? crc>>1^0xedb88320 : crc>>1;}
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(length,~crc); png.Write(length);
        }
        return png.ToArray();
    }
    private sealed record Inputs(byte[] Source,byte[] SourceHash,IReadOnlyList<PageGeometry> Pages,CompletionEvidence Evidence);
    private static Inputs Fixture(int rotation=0)
    {
        var source=PdfFixtures.Create(rotation:rotation,media:"10 20 622 812",pageEntries:"/CropBox [25 35 600 780] /UserUnit 1.25",text:"SYNTHETIC COMPLETION TEST - NO AGREEMENT");
        using var copy=new MemoryStream(); var pages=new PdfValidation(new() {MaximumBytes=64*1024*1024,MaximumPages=200}).Rewrite(new MemoryStream(source),copy);
        var sourceHash=SHA256.HashData(source); var now=DateTimeOffset.UtcNow.AddMinutes(-1); var disclosure=Hash("synthetic disclosure");
        var image=SignaturePng.Normalize(SignatureAdoptionTests.Mark()); var mark=new CompletionMark(image.Bytes,image.Sha256,SignaturePng.Version);
        var signers=new[]{
            new CompletionSigner(Guid.NewGuid(),1,"Élodie Synthetic","signer@example.invalid","Reviewer",now.AddMinutes(-9),now.AddMinutes(-8),now.AddMinutes(-7),now.AddMinutes(-6),now.AddMinutes(-5),"synthetic-ersd-v1",disclosure,Hash("checkpoint 1"),"127.0.0.1","Synthetic browser <script>alert(1)</script> \u202E \u4E00",Guid.NewGuid(),mark,mark),
            new CompletionSigner(Guid.NewGuid(),2,"Synthetic Second","second@example.invalid",null,now.AddMinutes(-4),now.AddMinutes(-3),now.AddMinutes(-2),now.AddMinutes(-1),now,"synthetic-ersd-v1",disclosure,sourceHash,null,null,Guid.NewGuid(),mark,mark)};
        var events=new List<CompletionEvent>(); var previous=new byte[32];
        for(var i=1;i<=12;i++) {var hash=Hash("synthetic audit "+i); events.Add(new(i,now.AddSeconds(-12+i),"synthetic_event_"+i,"System","Synthetic worker",null,"Synthetic local test",previous,hash)); previous=hash;}
        var evidence=new CompletionEvidence(Guid.NewGuid(),now,true,true,new(Guid.NewGuid(),"Synthetic completion packet - NO AGREEMENT",2,Hash("original"),Hash("converted"),Hash("sent"),sourceHash),
            new(null,"sender@example.invalid",now.AddMinutes(-10)),"synthetic-ersd-v1",disclosure,signers,new[]{new CompletionRecipient("Synthetic recipient","recipient@example.invalid")},events,previous);
        return new(source,sourceHash,pages,evidence);
    }
}
