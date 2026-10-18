using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using MigraDoc.DocumentObjectModel;
using MigraDoc.DocumentObjectModel.Tables;
using MigraDoc.Rendering;
using PdfSharp.Pdf;
using PdfSharp.Pdf.IO;
using QuillSign.Documents;
using QuillSign.Sealing;
using static QuillSign.Completion.CompletionEvidenceValidation;

namespace QuillSign.Completion;

// Pure PDF preparation. A future durable worker owns evidence authorization, sealing and publication.
public sealed class CompletionCertificateRenderer
{
    public const string Version="completion-certificate-v1";
    private readonly long maximumBytes; private readonly int maximumPages,maximumCertificatePages;
    public CompletionCertificateRenderer(long maximumBytes=64*1024*1024,int maximumPages=200,int maximumCertificatePages=64)
    {
        if(maximumBytes is <1024 or >64*1024*1024 || maximumPages is <2 or >200 || maximumCertificatePages is <1 or >64)throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        this.maximumBytes=maximumBytes; this.maximumPages=maximumPages; this.maximumCertificatePages=maximumCertificatePages;
    }
    public PreparedCompletionPacket PreparePacket(byte[] source,IReadOnlyList<PageGeometry> expectedPages,CompletionEvidence snapshot,CancellationToken ct=default)
        =>Guard(()=>PreparePacketCore(source,expectedPages,snapshot,ct));
    private PreparedCompletionPacket PreparePacketCore(byte[] source,IReadOnlyList<PageGeometry> expectedPages,CompletionEvidence snapshot,CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if(source is null || source.Length<16 || source.LongLength>maximumBytes || expectedPages is null || expectedPages.Count<1 || expectedPages.Count>=maximumPages)throw Rejected();
        lock(SenderPdfRenderer.RenderGate)
        {
            var evidence=Own(snapshot,ct); var bytes=source.ToArray(); var hash=SHA256.HashData(bytes);
            if(!Same(hash,evidence.Document.CurrentSha256) || expectedPages.Count!=evidence.Document.Pages)throw Rejected();
            var geometry=expectedPages.Select(p=>p is not null && p.MediaBox is {Length:4} && p.CropBox is {Length:4} ? p with {MediaBox=p.MediaBox.ToArray(),CropBox=p.CropBox.ToArray()} : throw Rejected()).ToArray();
            using var normalized=new MemoryStream(); using var input=new MemoryStream(bytes,false);
            var actual=new PdfValidation(new() {MaximumBytes=maximumBytes,MaximumPages=maximumPages}).Rewrite(input,new BoundedDocumentStream(normalized,maximumBytes));
            if(!SenderPdfRenderer.GeometryMatches(actual,geometry))throw Rejected();
            var appendix=Render(evidence,null,ct); using var certificate=PdfReader.Open(new MemoryStream(appendix),PdfDocumentOpenMode.Import);
            if(actual.Count+certificate.PageCount>maximumPages)throw Rejected();
            // Keep source pages in their owning document: importing them drops nonstandard page keys such as UserUnit.
            normalized.Position=0; using var packet=PdfReader.Open(normalized,PdfDocumentOpenMode.Modify);
            foreach(var page in certificate.Pages) {ct.ThrowIfCancellationRequested(); packet.AddPage(page);}
            packet.Info.Title="Executed document and completion evidence"; packet.Info.Creator="QuillSign";
            using var output=new MemoryStream(); packet.Save(new BoundedDocumentStream(output,maximumBytes),false); ct.ThrowIfCancellationRequested(); var prepared=output.ToArray();
            return new(prepared,SHA256.HashData(prepared),hash,Digest(evidence),appendix,actual.Count,certificate.PageCount,Version);
        }
    }
    public RenderedCompletionCertificate PrepareStandalone(CompletionEvidence snapshot,PreparedCompletionPacket packet,SealedPdf executed,CancellationToken ct=default)
        =>Guard(()=>PrepareStandaloneCore(snapshot,packet,executed,ct));
    private RenderedCompletionCertificate PrepareStandaloneCore(CompletionEvidence snapshot,PreparedCompletionPacket packet,SealedPdf executed,CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        lock(SenderPdfRenderer.RenderGate)
        {
            var evidence=Own(snapshot,ct);
            if(packet is null || packet.RendererVersion!=Version || packet.Bytes is null || packet.Bytes.Length<16 || packet.Bytes.LongLength>maximumBytes ||
                packet.DocumentPages!=evidence.Document.Pages || packet.CertificatePages is <1 || packet.CertificatePages>maximumCertificatePages || packet.DocumentPages+packet.CertificatePages>maximumPages ||
                !Same(packet.SourceSha256,evidence.Document.CurrentSha256) || !Same(packet.EvidenceSha256,Digest(evidence)) || !Same(packet.Sha256,SHA256.HashData(packet.Bytes)) ||
                executed is null || executed.Bytes is null || executed.Bytes.Length<16 || executed.Bytes.LongLength>maximumBytes || !Same(executed.SourceSha256,packet.Sha256) ||
                !Same(executed.Sha256,SHA256.HashData(executed.Bytes)) || executed.PageCount!=packet.DocumentPages+packet.CertificatePages ||
                executed.SealedAt<evidence.PreparedAt || executed.TimestampAt==default || string.IsNullOrWhiteSpace(executed.Provider) || executed.Provider.Length>100 ||
                !HexHash(executed.CertificateSha256) || !HexHash(executed.TimestampCertificateSha256) ||
                string.IsNullOrWhiteSpace(executed.TimestampPolicy) || executed.TimestampPolicy.Length>128)throw Rejected();
            // SealedPdf must come from the verified seal engine; this is not a public uploaded-PDF verifier.
            var bytes=Render(evidence,executed,ct); using var pdf=PdfReader.Open(new MemoryStream(bytes),PdfDocumentOpenMode.Import);
            return new(bytes,SHA256.HashData(bytes),packet.EvidenceSha256.ToArray(),executed.Sha256.ToArray(),pdf.PageCount,Version);
        }
    }
    private static bool HexHash(string? value)=>value is {Length:64} && value.All(Uri.IsHexDigit);
    private static T Guard<T>(Func<T> operation)
    {
        try {return operation();}
        catch(Exception error) when(error is PdfReaderException or InvalidOperationException or ArgumentException or FormatException or OverflowException or NotSupportedException or InvalidDataException ||
            error.GetType()==typeof(Exception) && error.TargetSite?.DeclaringType?.Assembly==typeof(PdfReader).Assembly)
        {throw Rejected();}
    }
    private byte[] Render(CompletionEvidence evidence,SealedPdf? executed,CancellationToken ct)
    {
        EmbeddedPdfFont.EnsureInitialized(); MigraDoc.PredefinedFontsAndChars.ErrorFontName=EmbeddedPdfFont.Family;
        var document=new Document(); document.Info.Title="Certificate of completion"; document.Info.Author="QuillSign";
        var normal=document.Styles[StyleNames.Normal]!; normal.Font.Name=EmbeddedPdfFont.Family; normal.Font.Size=9; normal.Font.Bold=false;
        normal.ParagraphFormat.SpaceAfter=4; normal.ParagraphFormat.LineSpacingRule=LineSpacingRule.AtLeast; normal.ParagraphFormat.LineSpacing=12;
        foreach(var name in new[]{StyleNames.Header,StyleNames.Footer}) {document.Styles[name]!.Font.Name=EmbeddedPdfFont.Family; document.Styles[name]!.Font.Size=8;}
        var section=document.AddSection(); section.PageSetup.PageFormat=PageFormat.A4; section.PageSetup.TopMargin=Unit.FromCentimeter(2.2); section.PageSetup.BottomMargin=Unit.FromCentimeter(2);
        section.PageSetup.LeftMargin=Unit.FromCentimeter(1.8); section.PageSetup.RightMargin=Unit.FromCentimeter(1.8); section.PageSetup.HeaderDistance=Unit.FromCentimeter(.8); section.PageSetup.FooterDistance=Unit.FromCentimeter(.8);
        var header=section.Headers.Primary.AddParagraph();
        using(var logo=typeof(CompletionCertificateRenderer).Assembly.GetManifestResourceStream("QuillSign.Brand.LogoMark.png") ?? throw Rejected()) {
            using var copy=new MemoryStream(); logo.CopyTo(copy); var image=header.AddImage("base64:"+Convert.ToBase64String(copy.ToArray())); image.Width=Unit.FromPoint(18); image.LockAspectRatio=true;
        }
        header.AddText("   QuillSign - completion evidence"); header.Format.Font.Color=Color.FromRgb(12,35,64);
        var footer=section.Footers.Primary.AddParagraph(); footer.AddText("Envelope "+evidence.EnvelopeId.ToString("N")+"  |  Certificate page "); footer.AddPageField(); footer.AddText(" of "); footer.AddNumPagesField(); footer.Format.Alignment=ParagraphAlignment.Center;
        Heading(section,"Certificate of completion",18);
        if(evidence.Synthetic)Warning(section,"SYNTHETIC TEST ONLY - NO AGREEMENT");
        if(evidence.Demo)Warning(section,"DEMO - not for legally significant documents.");
        Value(section,"Document",evidence.Document.Name); Value(section,"Envelope",evidence.EnvelopeId.ToString("N")); Value(section,"Document identifier",evidence.Document.Id.ToString("N"));
        Value(section,"Document pages before completion appendix",evidence.Document.Pages.ToString(CultureInfo.InvariantCulture)); Value(section,"Evidence snapshot (UTC)",At(evidence.PreparedAt));
        Paragraph(section,"This certificate records the signing procedure and stored evidence. Signer marks express recorded electronic signing intent; they are not individual signer-held cryptographic certificates.");
        Heading(section,"Document and disclosure bindings");
        Hash(section,"Original file SHA-256",evidence.Document.OriginalSha256); Hash(section,"Converted PDF SHA-256",evidence.Document.ConvertedSha256);
        Hash(section,"Immutable sent PDF SHA-256",evidence.Document.SentSha256); Hash(section,"Last signer checkpoint SHA-256",evidence.Document.CurrentSha256);
        Value(section,"Electronic records disclosure version",evidence.DisclosureVersion); Hash(section,"Disclosure SHA-256",evidence.DisclosureSha256);
        Hash(section,"Pre-seal audit anchor",evidence.AuditAnchor); Hash(section,"Shared completion evidence SHA-256",Digest(evidence));
        if(executed is null)Paragraph(section,"The executed-file hash cannot be embedded in that same file without circularity. See the separately sealed standalone certificate for its exact SHA-256 and verified seal/timestamp details. This PDF's embedded platform signature protects the document and these appended pages.");
        else {
            Heading(section,"Executed PDF seal and timestamp"); Hash(section,"Executed PDF SHA-256",executed.Sha256); Value(section,"Executed PDF total pages",executed.PageCount.ToString(CultureInfo.InvariantCulture));
            Value(section,"Platform seal provider",executed.Provider); TextHash(section,"Platform certificate SHA-256",executed.CertificateSha256); Value(section,"Platform seal time (UTC)",At(executed.SealedAt));
            Value(section,"Timestamp time (UTC)",At(executed.TimestampAt)); TextHash(section,"Timestamp certificate SHA-256",executed.TimestampCertificateSha256); Value(section,"Timestamp policy identifier",executed.TimestampPolicy);
            Value(section,"TSA friendly name","Not recorded; identify the authority by its certificate fingerprint and policy.");
            Paragraph(section,"This certificate is protected by its own embedded platform seal. Its final sealed hash is recorded externally rather than recursively inside itself. A cryptographic seal does not alone establish public CA/Adobe trust, qualified signing or PAdES conformance.");
        }
        Heading(section,"Sender"); Value(section,"Name",Optional(evidence.Sender.Name)); Value(section,"Email",evidence.Sender.Email); Value(section,"Email link verified (UTC)",At(evidence.Sender.VerifiedAt));
        Paragraph(section,"Authentication procedure: email-address control demonstrated by redeeming a one-time link sent to "+Mask(evidence.Sender.Email)+". No account, government identity or optional OTP verification is asserted.");
        Heading(section,"Sequential signers");
        var table=section.AddTable(); table.Borders.Width=.3; table.Borders.Color=Color.FromRgb(205,191,168); table.AddColumn(Unit.FromCentimeter(1.2)); table.AddColumn(Unit.FromCentimeter(7.1)); table.AddColumn(Unit.FromCentimeter(9.1));
        var head=table.AddRow(); head.HeadingFormat=true; head.Shading.Color=Color.FromRgb(244,240,230); head.Cells[0].AddParagraph("Order"); head.Cells[1].AddParagraph("Signer / role"); head.Cells[2].AddParagraph("Email");
        foreach(var signer in evidence.Signers) {var row=table.AddRow(); row.Cells[0].AddParagraph(signer.Order.ToString(CultureInfo.InvariantCulture)); row.Cells[1].AddParagraph(TableText(signer.Name+"\nRole: "+Optional(signer.Role),20,"See signer "+signer.Order+" details below")); row.Cells[2].AddParagraph(TableText(signer.Email,28));}
        foreach(var signer in evidence.Signers) {
            ct.ThrowIfCancellationRequested(); Heading(section,"Signer "+signer.Order);
            Value(section,"Name",signer.Name); Value(section,"Email",signer.Email); Value(section,"Role",Optional(signer.Role));
            Value(section,"One-time email link verified (UTC)",At(signer.EmailVerifiedAt)); Value(section,"Recorded viewed event (UTC)",At(signer.ViewedAt)); Value(section,"Electronic records consent (UTC)",At(signer.ConsentedAt));
            Value(section,"Deliberate Finish accepted (UTC)",At(signer.FinishedAt)); Value(section,"Checkpoint published (UTC)",At(signer.CheckpointAt));
            Value(section,"Client-local time / zone","Not recorded"); Value(section,"Recorded Finish IP",Optional(signer.Ip)); Value(section,"Recorded Finish user agent",Optional(signer.UserAgent));
            Value(section,"Consented disclosure version",signer.DisclosureVersion); Hash(section,"Consented disclosure SHA-256",signer.DisclosureSha256); Hash(section,"Signer checkpoint SHA-256",signer.CheckpointSha256);
            Paragraph(section,"Authentication procedure: email-address control demonstrated by a redeemed one-time link to "+Mask(signer.Email)+". The server records consent and affirmative Finish separately; signing time is the accepted server UTC time, not the later worker publication time.");
            Mark(section,"Applied signature mark",signer.Signature); Mark(section,"Applied initials mark",signer.Initials);
        }
        Heading(section,"Completion recipients");
        if(evidence.Recipients.Count==0)Paragraph(section,"No additional completion recipients.");
        foreach(var recipient in evidence.Recipients)Value(section,Optional(recipient.Name),recipient.Email);
        Heading(section,"Audit chronology through snapshot"); Paragraph(section,"Every event through the evidence snapshot is listed in recorded sequence order with server UTC times and hashes of the canonical records. Later seal, publication and delivery events are recorded externally. Unsupported glyphs/control characters are displayed as U+ escapes; line wrapping does not change the stored values.");
        foreach(var entry in evidence.Events) {
            ct.ThrowIfCancellationRequested(); var first=section.Elements.Count; Heading(section,"Event "+entry.Sequence+" - "+entry.Event,10);
            Value(section,"Recorded UTC",At(entry.At)+" | Actor: "+entry.ActorType+": "+Optional(entry.Actor)); Value(section,"IP",Optional(entry.Ip)+" | User agent: "+Optional(entry.UserAgent));
            if(entry.ContactCorrection is { } correction)
            {
                Value(section,"Contact correction for the same named signer",correction.Name);
                Value(section,"Retired address",correction.OldEmail); Value(section,"Corrected address",correction.NewEmail);
                Value(section,"Contact revision",correction.Number.ToString(CultureInfo.InvariantCulture)+" | "+correction.RevisionId.ToString("N"));
                TextHash(section,"Retired unfinished-entry snapshot SHA-256",correction.RetirementSha256);
                Paragraph(section,"The verified sender authorized this delivery-address correction before Finish. Earlier consent, marks and unfinished entries are retired evidence; they are not signatures by the corrected mailbox. The final effective signer completed fresh access, consent, adoption and Finish.");
            }
            Hash(section,"Previous audit hash",entry.PreviousHash); Hash(section,"Audit event hash",entry.Hash);
            // Keep ordinary event blocks together; large evidence fields must remain able to flow across pages.
            if(Plain(entry.Event+entry.Actor+entry.Ip+entry.UserAgent).Count(c=>c=='\n')<=25)
                for(var index=first;index<section.Elements.Count-1;index++)if(section.Elements[index] is Paragraph paragraph)paragraph.Format.KeepWithNext=true;
        }
        var layout=new DocumentRenderer(document); layout.PrepareDocumentProgress+=(_,_)=>ct.ThrowIfCancellationRequested();
        var renderer=new PdfDocumentRenderer {Document=document,DocumentRenderer=layout};
        try {
            renderer.PrepareRenderPages(); if(renderer.PageCount is <1 || renderer.PageCount>maximumCertificatePages)throw Rejected();
            for(var page=1;page<=renderer.PageCount;page++) {ct.ThrowIfCancellationRequested(); renderer.RenderPages(page,page);}
            using var output=new MemoryStream(); renderer.PdfDocument.Save(new BoundedDocumentStream(output,maximumBytes),false); ct.ThrowIfCancellationRequested(); return output.ToArray();
        }
        finally {renderer.PdfDocument.Dispose();}
    }
    private static string At(DateTimeOffset value)=>value.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'",CultureInfo.InvariantCulture);
    private static string Optional(string? value)=>string.IsNullOrWhiteSpace(value) ? "Not recorded" : value;
    private static string Mask(string email)=>email[..1]+"***"+email[email.LastIndexOf('@')..];
    private static void Heading(Section section,string text,double size=13) {var paragraph=section.AddParagraph(Plain(text)); paragraph.Format.Font.Size=size; paragraph.Format.Font.Color=Color.FromRgb(12,35,64); paragraph.Format.SpaceBefore=10; paragraph.Format.SpaceAfter=5; paragraph.Format.KeepWithNext=true;}
    private static void Warning(Section section,string text) {var paragraph=section.AddParagraph(text); paragraph.Format.Font.Color=Color.FromRgb(120,40,30); paragraph.Format.SpaceAfter=8;}
    private static void Paragraph(Section section,string text) {var plain=Plain(text); var paragraph=section.AddParagraph(plain); if(plain.Length<=1200 && plain.Count(c=>c=='\n')<=12)paragraph.Format.KeepTogether=true;}
    private static void Value(Section section,string label,string value)=>Paragraph(section,label+": "+value);
    private static void Hash(Section section,string label,byte[] hash)=>TextHash(section,label,Convert.ToHexStringLower(hash));
    private static void TextHash(Section section,string label,string hash) {var paragraph=section.AddParagraph(Plain(label+":\n"+hash[..32]+"\n"+hash[32..])); paragraph.Format.KeepTogether=true;}
    private static void Mark(Section section,string label,CompletionMark? mark)
    {
        if(mark is null) {Value(section,label,"No image applied"); return;}
        var paragraph=section.AddParagraph(label+"\n"); paragraph.Format.KeepTogether=true;
        var width=System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(mark.Png.AsSpan(16)); var height=System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(mark.Png.AsSpan(20));
        var image=paragraph.AddImage("base64:"+Convert.ToBase64String(mark.Png)); image.Width=Unit.FromCentimeter(Math.Min(4,1.5*width/height)); image.LockAspectRatio=true;
        var hash=Convert.ToHexStringLower(mark.Sha256); paragraph.AddText("\n"+label+" SHA-256:\n"+hash[..32]+"\n"+hash[32..]);
    }
    private static string TableText(string value,int tokenLimit=20,string? details=null) {var text=Plain(value,tokenLimit); if(text.Count(c=>c=='\n')>40)return details is not null ? Plain(details) : throw Rejected(); return text;}
    private static string Plain(string value,int tokenLimit=32)
    {
        var result=new StringBuilder(); var run=0;
        foreach(var rune in value.EnumerateRunes()) {
            if(rune.Value=='\n') {result.Append('\n'); run=0; continue;}
            var category=Rune.GetUnicodeCategory(rune); var text=category is UnicodeCategory.Control or UnicodeCategory.Format || !EmbeddedPdfFont.Supports(rune) ? "[U+"+rune.Value.ToString("X4",CultureInfo.InvariantCulture)+"]" : rune.ToString();
            if(char.IsWhiteSpace(text,0)) {result.Append(text); run=0; continue;}
            if(run+text.Length>tokenLimit) {result.Append('\n'); run=0;}
            result.Append(text); run+=text.Length;
        }
        return result.ToString();
    }
}
