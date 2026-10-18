using System.Globalization;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace QuillSign.Documents;

// Independent ODF gate. An OPC suffix/content-type checker cannot establish ODT safety.
public sealed class OdtPackageValidation(DocumentOptions limits)
{
    private const string Mime="application/vnd.oasis.opendocument.text",O="urn:oasis:names:tc:opendocument:xmlns:office:1.0",T="urn:oasis:names:tc:opendocument:xmlns:text:1.0",St="urn:oasis:names:tc:opendocument:xmlns:style:1.0",F="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0",Tb="urn:oasis:names:tc:opendocument:xmlns:table:1.0",D="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0",Svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0",X="http://www.w3.org/1999/xlink",M="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0",Meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0",Dc="http://purl.org/dc/elements/1.1/";
    private static readonly Dictionary<string,HashSet<string>> Elements=new(){[O]=Words("document-content document-styles document-meta automatic-styles styles font-face-decls body text master-styles meta"),[T]=Words("p h span s tab line-break"),[St]=Words("style default-style text-properties paragraph-properties table-properties table-column-properties table-row-properties table-cell-properties graphic-properties font-face page-layout page-layout-properties master-page"),[Tb]=Words("table table-column table-row table-cell covered-table-cell"),[D]=Words("frame image"),[Meta]=Words("generator initial-creator creation-date editing-duration editing-cycles document-statistic"),[Dc]=Words("title description subject creator date language")};
    private static readonly Dictionary<string,HashSet<string>> Attributes=new(){[O]=Words("version value-type value string-value boolean-value"),[T]=Words("style-name c outline-level anchor-type"),[St]=Words("name display-name family parent-style-name next-style-name master-page-name page-layout-name font-name font-size-asian font-size-complex font-weight-asian font-weight-complex font-style-asian font-style-complex text-underline-style text-underline-width text-underline-color vertical-align width column-width row-height min-row-height writing-mode"),[F]=Words("font-family font-size font-weight font-style color background-color text-align margin margin-left margin-right margin-top margin-bottom text-indent line-height keep-with-next break-before break-after border border-left border-right border-top border-bottom padding padding-left padding-right padding-top padding-bottom page-width page-height"),[Tb]=Words("name style-name number-columns-repeated number-rows-repeated number-columns-spanned number-rows-spanned"),[D]=Words("name style-name z-index"),[Svg]=Words("width height font-family"),[X]=Words("href type show actuate"),[Meta]=Words("table-count image-count object-count page-count paragraph-count word-count character-count non-whitespace-character-count")};
    public async Task<ValidatedOfficeSource> ValidateAsync(Stream input,long declaredLength,CancellationToken ct=default)
    {
        if(limits.MaximumPages is <1 or >200)throw new InvalidOperationException("Configure supported Office page limits.");
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(15));
        try {using var package=await BoundedOfficePackage.ReadAsync(input,declaredLength,limits,timeout.Token);package.RequireFirstStored("mimetype","application/vnd.oasis.opendocument.text"u8);Validate(package.Parts,limits.MaximumPages,timeout.Token);return new(package.DetachOriginal(),OfficeSourceKind.Odt,0,595.2755905511812,841.8897637795276);}
        catch(OperationCanceledException) when(!ct.IsCancellationRequested){throw Rejected();}
        catch(Exception e) when(e is DocumentRejectedException or System.Xml.XmlException or InvalidDataException or IOException or ArgumentException or OverflowException or NotSupportedException){throw Rejected();}
    }
    private static void Validate(Dictionary<string,byte[]> parts,int maximumPages,CancellationToken ct)
    {
        if(!parts.TryGetValue("mimetype",out var mime)||!mime.AsSpan().SequenceEqual("application/vnd.oasis.opendocument.text"u8)||!parts.TryGetValue("META-INF/manifest.xml",out var manifestBytes)||!parts.ContainsKey("content.xml")||!parts.ContainsKey("styles.xml"))throw Rejected();
        var nodes=0;var manifest=Xml(manifestBytes,ct,ref nodes);if(manifest.Root?.Name!=N(M,"manifest"))throw Rejected();Only(manifest.Root,N(M,"version"));if((string?)manifest.Root.Attribute(N(M,"version")) is not ("1.2" or "1.3"))throw Rejected();var entries=new Dictionary<string,string>(StringComparer.Ordinal);
        foreach(var entry in manifest.Root.Elements())
        {if(entry.Name!=N(M,"file-entry")||entry.HasElements)throw Rejected();Only(entry,N(M,"full-path"),N(M,"media-type"),N(M,"version"));var path=Attr(entry,M,"full-path");var type=(string?)entry.Attribute(N(M,"media-type"))??throw Rejected();if(!entries.TryAdd(path,type)||path is "mimetype" or "META-INF/manifest.xml")throw Rejected();if(entry.Attribute(N(M,"version")) is XAttribute version&&version.Value is not ("1.2" or "1.3"))throw Rejected();}
        var exactNames=parts.Keys.ToHashSet(StringComparer.Ordinal);if(!entries.Remove("/",out var rootType)||rootType!=Mime||entries.Count!=parts.Count-2||entries.Any(x=>!exactNames.Contains(x.Key)))throw Rejected();
        var images=new Dictionary<string,ImageHeaderValidation.Header>(StringComparer.Ordinal);long pixels=0;var documents=new Dictionary<string,XDocument>(StringComparer.Ordinal);var textWork=0;
        foreach(var (name,bytes) in parts)
        {
            ct.ThrowIfCancellationRequested();if(name is "mimetype" or "META-INF/manifest.xml")continue;
            if(Regex.IsMatch(name,@"^Pictures/[A-Za-z0-9_-]{1,64}\.(?:png|jpg|jpeg)$",RegexOptions.CultureInvariant))
            {var kind=name.EndsWith(".png",StringComparison.Ordinal)?"image/png":"image/jpeg";if(entries[name]!=kind||images.Count>=32)throw Rejected();var image=ImageHeaderValidation.Read(bytes,ct);if(image.Mime!=kind||(pixels+=(long)image.Width*image.Height)>48_000_000)throw Rejected();images.Add(name,image);continue;}
            if(name is not ("content.xml" or "styles.xml" or "meta.xml")||entries[name]!="text/xml")throw Rejected();var xml=Xml(bytes,ct,ref nodes);var expected=name switch{"content.xml"=>"document-content","styles.xml"=>"document-styles",_=>"document-meta"};if(xml.Root?.Name!=N(O,expected))throw Rejected();documents.Add(name,xml);
            foreach(var node in xml.Descendants())
            {
                ct.ThrowIfCancellationRequested();if(!Elements.TryGetValue(node.Name.NamespaceName,out var allowed)||!allowed.Contains(node.Name.LocalName))throw Rejected();
                foreach(var attribute in node.Attributes().Where(x=>!x.IsNamespaceDeclaration))
                {
                    if(attribute.Value.Length>512||!Attributes.TryGetValue(attribute.Name.NamespaceName,out var attrs)||!attrs.Contains(attribute.Name.LocalName))throw Rejected();
                    if(attribute.Name.NamespaceName==X&&(node.Name!=N(D,"image")||attribute.Name.LocalName!="href"&&attribute.Value!=(attribute.Name.LocalName switch{"type"=>"simple","show"=>"embed","actuate"=>"onLoad",_=>throw Rejected()})))throw Rejected();
                    if(attribute.Name.LocalName is "font-family" or "font-name"&&(attribute.Value.Contains(':')||attribute.Value.Contains('/')||attribute.Value.Contains('\\')))throw Rejected();
                    if(attribute.Name.NamespaceName==Meta)Integer(attribute.Value,0,100_000);if(attribute.Name==N(D,"z-index"))Integer(attribute.Value,0,64);
                    if(attribute.Name.NamespaceName==F||attribute.Name.NamespaceName==St)Property(attribute);
                    if(attribute.Name.NamespaceName==O&&attribute.Name.LocalName=="version"&&attribute.Value is not ("1.2" or "1.3"))throw Rejected();
                }
                foreach(var text in node.Nodes().OfType<XText>())if((textWork+=text.Value.Length)>50_000)throw Rejected();
                if(node.Name==N(T,"s")){var count=node.Attribute(N(T,"c")) is XAttribute spaces?Integer(spaces.Value,1,100):1;if((textWork+=count)>50_000)throw Rejected();}
                if(node.Name==N(T,"tab")&&(textWork+=8)>50_000)throw Rejected();
                if(node.Name==N(T,"line-break")&&(textWork+=1)>50_000)throw Rejected();
                if(node.Name==N(T,"h")&&node.Attribute(N(T,"outline-level")) is XAttribute heading)Integer(heading.Value,1,10);
            }
        }
        var content=documents["content.xml"].Root!;var styles=documents["styles.xml"].Root!;
        if((string?)content.Attribute(N(O,"version")) is not ("1.2" or "1.3")||(string?)styles.Attribute(N(O,"version")) is not ("1.2" or "1.3"))throw Rejected();
        var bodies=content.Elements(N(O,"body")).ToArray();if(bodies.Length!=1||bodies[0].Elements().Count()!=1||bodies[0].Element(N(O,"text")) is not XElement body||!body.Descendants(N(T,"p")).Concat(body.Descendants(N(T,"h"))).Any(x=>!string.IsNullOrWhiteSpace(x.Value))||body.Descendants().Count(x=>x.Name==N(T,"p")||x.Name==N(T,"h"))>2000)throw Rejected();
        if(documents.Where(x=>x.Key!="content.xml").Any(x=>x.Value.Descendants(N(O,"body")).Any()))throw Rejected();
        var layouts=styles.Descendants(N(St,"page-layout")).Concat(content.Descendants(N(St,"page-layout"))).ToArray();var masters=styles.Descendants(N(St,"master-page")).ToArray();if(layouts.Length!=1||masters.Length!=1||masters[0].HasElements||Attr(masters[0],St,"page-layout-name")!=Attr(layouts[0],St,"name"))throw Rejected();
        var page=layouts[0].Element(N(St,"page-layout-properties"))??throw Rejected();if(layouts[0].Elements().Count()!=1||Math.Abs(Length(Attr(page,F,"page-width"))-595.2755905511812)>.1||Math.Abs(Length(Attr(page,F,"page-height"))-841.8897637795276)>.1)throw Rejected();foreach(var side in new[]{"margin-left","margin-right","margin-top","margin-bottom"})if(page.Attribute(N(F,side)) is XAttribute margin&&Length(margin.Value) is <28 or >85)throw Rejected();
        var styleNames=new HashSet<string>(StringComparer.Ordinal);var fontNames=new HashSet<string>(StringComparer.Ordinal);foreach(var style in documents.Values.SelectMany(x=>x.Descendants()).Where(x=>x.Name==N(St,"style")||x.Name==N(St,"page-layout")||x.Name==N(St,"master-page"))){var name=Attr(style,St,"name");if(!styleNames.Add(name)||styleNames.Count>256)throw Rejected();if(style.Name==N(St,"style")&&Attr(style,St,"family") is not ("paragraph" or "text" or "table" or "table-row" or "table-column" or "table-cell" or "graphic"))throw Rejected();}
        foreach(var style in documents.Values.SelectMany(x=>x.Descendants(N(St,"style"))))
        {var visited=new HashSet<string>(StringComparer.Ordinal){Attr(style,St,"name")};var cursor=style;while(cursor.Attribute(N(St,"parent-style-name")) is XAttribute parent){if(!visited.Add(parent.Value))throw Rejected();cursor=documents.Values.SelectMany(x=>x.Descendants(N(St,"style"))).SingleOrDefault(x=>(string?)x.Attribute(N(St,"name"))==parent.Value)??throw Rejected();}}
        foreach(var font in documents.Values.SelectMany(x=>x.Descendants(N(St,"font-face"))))if(font.HasElements||!fontNames.Add(Attr(font,St,"name"))||fontNames.Count>32)throw Rejected();
        foreach(var attribute in documents.Values.SelectMany(x=>x.Descendants().Attributes()))
        {if(attribute.Name.NamespaceName is T or Tb or D&&attribute.Name.LocalName=="style-name"&&!styleNames.Contains(attribute.Value))throw Rejected();if(attribute.Name.NamespaceName==St&&attribute.Name.LocalName is "parent-style-name" or "next-style-name" or "master-page-name" or "page-layout-name"&&!styleNames.Contains(attribute.Value))throw Rejected();if(attribute.Name==N(St,"font-name")&&!fontNames.Contains(attribute.Value))throw Rejected();}
        var paragraphStyles=documents.Values.SelectMany(x=>x.Descendants(N(St,"style"))).ToDictionary(x=>Attr(x,St,"name"),StringComparer.Ordinal);var defaultParagraphs=documents.Values.SelectMany(x=>x.Descendants(N(St,"default-style"))).Where(x=>(string?)x.Attribute(N(St,"family"))=="paragraph").ToArray();if(defaultParagraphs.Length>1)throw Rejected();var pageWork=1;
        foreach(var paragraph in body.Descendants().Where(x=>x.Name==N(T,"p")||x.Name==N(T,"h")))
        {var inherited=new List<XElement>(defaultParagraphs);var style=(string?)paragraph.Attribute(N(T,"style-name"));while(style is not null){if(!paragraphStyles.TryGetValue(style,out var definition))throw Rejected();inherited.Add(definition);style=(string?)definition.Attribute(N(St,"parent-style-name"));}foreach(var property in inherited.SelectMany(x=>x.Elements(N(St,"paragraph-properties"))))foreach(var side in new[]{"break-before","break-after"})if((string?)property.Attribute(N(F,side))=="page"&&++pageWork>maximumPages)throw Rejected();}
        var references=new HashSet<string>(StringComparer.Ordinal);var frames=body.Descendants(N(D,"frame")).ToArray();if(frames.Length>64)throw Rejected();foreach(var frame in frames)
        {if((string?)frame.Attribute(N(T,"anchor-type"))!="as-char"||frame.Elements().Count()!=1||frame.Element(N(D,"image")) is not XElement image||image.HasElements||!images.ContainsKey(Attr(image,X,"href")))throw Rejected();var width=Length(Attr(frame,Svg,"width"));var height=Length(Attr(frame,Svg,"height"));if(width is <1 or >454||height is <1 or >652)throw Rejected();references.Add(Attr(image,X,"href"));}
        if(body.Descendants(N(D,"image")).Count()!=frames.Length||images.Keys.Any(x=>!references.Contains(x))||documents.Where(x=>x.Key!="content.xml").Any(x=>x.Value.Descendants(N(D,"image")).Any()))throw Rejected();
        foreach(var value in body.Descendants().Attributes().Where(x=>x.Name.NamespaceName==O))
        {if(value.Name.LocalName=="value"&&(!double.TryParse(value.Value,NumberStyles.Float,CultureInfo.InvariantCulture,out var number)||!double.IsFinite(number)||Math.Abs(number)>1e15))throw Rejected();if(value.Name.LocalName=="boolean-value"&&value.Value is not ("true" or "false"))throw Rejected();}
        foreach(var node in body.Descendants().Where(x=>x.Name.NamespaceName==Tb))
        {if(node.Name.LocalName=="table"&&node.Parent!=body||node.Name.LocalName is "table-column" or "table-row"&&node.Parent?.Name!=N(Tb,"table")||node.Name.LocalName=="table-cell"&&node.Parent?.Name!=N(Tb,"table-row"))throw Rejected();}
        var cells=0;var tables=body.Descendants(N(Tb,"table")).ToArray();if(tables.Length>20)throw Rejected();foreach(var table in tables)
        {if(table.Ancestors(N(Tb,"table")).Any()||table.Elements().Any(x=>x.Name!=N(Tb,"table-column")&&x.Name!=N(Tb,"table-row")))throw Rejected();var rows=table.Elements(N(Tb,"table-row")).ToArray();if(rows.Length is <1 or >40||table.Elements(N(Tb,"table-column")).Count()>12)throw Rejected();foreach(var row in rows){if(row.Elements().Count()>12||row.Elements().Any(x=>x.Name!=N(Tb,"table-cell")))throw Rejected();foreach(var cell in row.Elements()){if((cells++)>4000||cell.Attribute(N(O,"value-type")) is XAttribute type&&type.Value is not ("string" or "float" or "boolean"))throw Rejected();}}}
        foreach(var attr in body.Descendants().Attributes().Where(x=>x.Name.NamespaceName==Tb&&x.Name.LocalName is "number-columns-repeated" or "number-rows-repeated" or "number-columns-spanned" or "number-rows-spanned"))if(attr.Value!="1")throw Rejected();
    }
    private static void Property(XAttribute value)
    {
        var name=value.Name.LocalName;var text=value.Value;
        if(name is "font-size" or "font-size-asian" or "font-size-complex"){var n=Length(text);if(n is <8 or >24)throw Rejected();}
        if(name is "font-weight" or "font-weight-asian" or "font-weight-complex"&&text is not ("normal" or "bold"))throw Rejected();
        if(name is "font-style" or "font-style-asian" or "font-style-complex"&&text is not ("normal" or "italic"))throw Rejected();
        if(name.Contains("margin",StringComparison.Ordinal)||name.Contains("padding",StringComparison.Ordinal)||name is "text-indent" or "column-width" or "row-height" or "min-row-height" or "width"){var n=Length(text);if(n<0||n>454)throw Rejected();}
        if(name is "color" or "background-color"&&text!="transparent"&&!Regex.IsMatch(text,@"^#[a-fA-F0-9]{6}$",RegexOptions.CultureInvariant))throw Rejected();
        if(name is "break-before" or "break-after"&&text is not ("auto" or "page"))throw Rejected();
        if(name=="line-height"&&text!="normal"&&(Length(text) is <8 or >36))throw Rejected();
        if(name.StartsWith("border",StringComparison.Ordinal)&&text!="none"&&!Regex.IsMatch(text,@"^(?:0\.[0-9]{1,2}|[1-2])pt (?:solid|dashed|dotted) #[0-9A-Fa-f]{6}$",RegexOptions.CultureInvariant))throw Rejected();
    }
    private static double Length(string text){var match=Regex.Match(text,@"^(?<v>[0-9]{1,3}(?:\.[0-9]{1,8})?)(?<u>cm|mm|in|pt)$",RegexOptions.CultureInvariant);if(!match.Success||!double.TryParse(match.Groups["v"].Value,NumberStyles.AllowDecimalPoint,CultureInfo.InvariantCulture,out var value))throw Rejected();return value*(match.Groups["u"].Value switch{"cm"=>72/2.54,"mm"=>72/25.4,"in"=>72d,_=>1});}
    private static int Integer(string value,int min,int max){if(!int.TryParse(value,NumberStyles.None,CultureInfo.InvariantCulture,out var n)||n<min||n>max)throw Rejected();return n;}
    private static void Only(XElement node,params XName[] names){if(node.Attributes().Any(x=>!x.IsNamespaceDeclaration&&!names.Contains(x.Name)))throw Rejected();}
    private static XName N(string ns,string name)=>XName.Get(name,ns);
    private static string Attr(XElement node,string ns,string name)=>string.IsNullOrWhiteSpace((string?)node.Attribute(N(ns,name)))?throw Rejected():(string)node.Attribute(N(ns,name))!;
    private static HashSet<string> Words(string text)=>new(text.Split(' ',StringSplitOptions.RemoveEmptyEntries),StringComparer.Ordinal);
    private static XDocument Xml(byte[] bytes,CancellationToken ct,ref int nodes)=>BoundedOfficePackage.Xml(bytes,ct,ref nodes,250_000);
    private static DocumentRejectedException Rejected()=>new("This ODT is outside the bounded static profile. Export a PDF and try again.");
}
