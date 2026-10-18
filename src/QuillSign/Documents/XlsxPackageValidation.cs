using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace QuillSign.Documents;

// Values-only SpreadsheetML. Original bytes remain separate from the owned print-profile copy.
public sealed class XlsxPackageValidation(DocumentOptions limits)
{
    private const string S="http://schemas.openxmlformats.org/spreadsheetml/2006/main",R="http://schemas.openxmlformats.org/officeDocument/2006/relationships",Rel="http://schemas.openxmlformats.org/package/2006/relationships",C="http://schemas.openxmlformats.org/package/2006/content-types",A="http://schemas.openxmlformats.org/drawingml/2006/main";
    private const string Core="http://schemas.openxmlformats.org/package/2006/metadata/core-properties",App="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",Vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes";
    private static readonly HashSet<string> Workbook=Words("workbook fileVersion workbookPr bookViews workbookView sheets sheet definedNames calcPr workbookProtection");
    private static readonly HashSet<string> Worksheet=Words("worksheet sheetPr outlinePr pageSetUpPr dimension sheetViews sheetView selection pane sheetFormatPr cols col sheetData row c v is t r rPr rFont b i u strike outline shadow condense extend color sz family charset scheme mergeCells mergeCell printOptions pageMargins pageSetup");
    private static readonly HashSet<string> Styles=Words("styleSheet numFmts fonts font name sz family charset scheme b i u strike outline shadow condense extend color fills fill patternFill fgColor bgColor borders border left right top bottom diagonal start end cellStyleXfs cellXfs xf alignment protection cellStyles cellStyle dxfs tableStyles indexedColors rgbColor colors");
    private static readonly HashSet<string> Attributes=Words("visibility minimized showHorizontalScroll showVerticalScroll showSheetTabs autoFilterDateGrouping appName lastEdited lowestEdited rupBuild date1904 defaultThemeVersion xWindow yWindow windowWidth windowHeight activeTab firstSheet tabRatio name sheetId state id calcId fullCalcOnLoad forceFullCalc calcMode ref count uniqueCount r t s spans ht customHeight hidden outlineLevel collapsed thickTop thickBot defaultRowHeight baseColWidth defaultColWidth customWidth width min max bestFit customFormat style showGridLines showRowColHeaders showZeros rightToLeft tabSelected view workbookViewId zoomScale zoomScaleNormal topLeftCell activeCell sqref pane xSplit ySplit state selection horizontal vertical textRotation wrapText shrinkToFit indent relativeIndent justifyLastLine readingOrder fontId fillId borderId numFmtId xfId applyNumberFormat applyFont applyFill applyBorder applyAlignment applyProtection pivotButton quotePrefix builtinId iLevel locked val rgb indexed theme tint auto patternType diagonalUp diagonalDown colorId name count defaultTableStyle defaultPivotStyle horizontalCentered verticalCentered headings gridLines gridLinesSet left right top bottom header footer paperSize orientation scale fitToWidth fitToHeight pageOrder useFirstPageNumber firstPageNumber blackAndWhite draft cellComments usePrinterDefaults errors horizontalDpi verticalDpi copies autoPageBreaks fitToPage applyStyles summaryBelow summaryRight showOutlineSymbols formatCode code outlineLevelRow outlineLevelCol zeroHeight thickTop thickBottom" );
    private sealed record Part(string Role,string Mime,XName Root);
    private sealed record Link(string Id,string Kind,string Target);
    private static readonly Dictionary<string,HashSet<string>> CriticalAttributes=new(){
        ["workbook"]=Words(""),["sheets"]=Words(""),["sheet"]=Words("name sheetId state"),["definedNames"]=Words(""),["workbookProtection"]=Words(""),["sheetData"]=Words(""),["worksheet"]=Words(""),["cols"]=Words(""),["c"]=Words("r s t"),["v"]=Words(""),["is"]=Words(""),["t"]=Words(""),["si"]=Words(""),["r"]=Words(""),["rPr"]=Words(""),["sst"]=Words("count uniqueCount"),
        ["color"]=Words("rgb indexed theme tint auto"),["fgColor"]=Words("rgb indexed theme tint auto"),["bgColor"]=Words("rgb indexed theme tint auto"),["rgbColor"]=Words("rgb"),["sheetPr"]=Words(""),["dimension"]=Words("ref"),["mergeCell"]=Words("ref"),["mergeCells"]=Words("count"),["pageSetUpPr"]=Words("autoPageBreaks fitToPage"),["row"]=Words("r s spans ht customHeight hidden outlineLevel collapsed thickTop thickBot customFormat"),["col"]=Words("min max width style hidden bestFit customWidth outlineLevel collapsed"),["sheetFormatPr"]=Words("baseColWidth defaultColWidth defaultRowHeight customHeight zeroHeight thickTop thickBottom outlineLevelRow outlineLevelCol"),["pageMargins"]=Words("left right top bottom header footer"),["pageSetup"]=Words("paperSize orientation scale fitToWidth fitToHeight pageOrder useFirstPageNumber firstPageNumber blackAndWhite draft cellComments usePrinterDefaults errors horizontalDpi verticalDpi copies"),["printOptions"]=Words("horizontalCentered verticalCentered headings gridLines gridLinesSet")};

    public async Task<ValidatedOfficeSource> ValidateAsync(Stream input,long declaredLength,CancellationToken ct=default)
    {
        if(limits.MaximumPages is <1 or >200)throw new InvalidOperationException("Configure supported Office page limits.");
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(15));byte[]? derived=null;
        try
        {
            using var package=await BoundedOfficePackage.ReadAsync(input,declaredLength,limits,timeout.Token);
            var result=Validate(package.Parts,timeout.Token);derived=PrintCopy(package.Parts,result.Sheets,timeout.Token);timeout.Token.ThrowIfCancellationRequested();
            var owned=derived;derived=null;return new(package.DetachOriginal(),OfficeSourceKind.Xlsx,result.Sheets.Count,841.8897637795276,595.2755905511812,owned);
        }
        catch(OperationCanceledException) when(!ct.IsCancellationRequested){throw Rejected();}
        catch(Exception e) when(e is DocumentRejectedException or System.Xml.XmlException or InvalidDataException or IOException or ArgumentException or OverflowException or NotSupportedException){throw Rejected();}
        finally {if(derived is not null)Array.Clear(derived);}
    }
    private (Dictionary<string,XDocument> Sheets,int Cells) Validate(Dictionary<string,byte[]> parts,CancellationToken ct)
    {
        if(!parts.TryGetValue("[Content_Types].xml",out var typeBytes)||!parts.ContainsKey("xl/workbook.xml")||!parts.ContainsKey("_rels/.rels"))throw Rejected();
        var nodes=0;var types=Xml(typeBytes,ct,ref nodes);if(types.Root?.Name!=XName.Get("Types",C)||types.Root.Attributes().Any(x=>!x.IsNamespaceDeclaration))throw Rejected();
        var defaults=new Dictionary<string,string>(StringComparer.Ordinal);var overrides=new Dictionary<string,string>(StringComparer.Ordinal);
        foreach(var item in types.Root.Elements())
        {
            if(item.Name==XName.Get("Default",C)){Only(item,"Extension","ContentType");var ext=Attr(item,"Extension");if(ext is not ("xml" or "rels")||!defaults.TryAdd(ext,Attr(item,"ContentType")))throw Rejected();}
            else if(item.Name==XName.Get("Override",C)){Only(item,"PartName","ContentType");var path=Attr(item,"PartName");if(!path.StartsWith('/')||!overrides.TryAdd(path[1..],Attr(item,"ContentType")))throw Rejected();}
            else throw Rejected();
        }
        if(overrides.Any(x=>!parts.ContainsKey(x.Key)))throw Rejected();
        var definitions=new Dictionary<string,Part>(StringComparer.Ordinal);var xmls=new Dictionary<string,XDocument>(StringComparer.Ordinal);var literal=0;
        foreach(var (name,bytes) in parts)
        {
            ct.ThrowIfCancellationRequested();if(name=="[Content_Types].xml")continue;var part=Definition(name);definitions.Add(name,part);
            if((overrides.GetValueOrDefault(name)??defaults.GetValueOrDefault(name.Split('.').Last()))!=part.Mime)throw Rejected();
            var xml=Xml(bytes,ct,ref nodes);if(xml.Root?.Name!=part.Root)throw Rejected();xmls.Add(name,xml);if(part.Role=="rels")continue;
            if(part.Role is "core" or "app"){Metadata(xml,part.Role);continue;}if(part.Role=="theme"){Theme(xml,ct);continue;}
            var allowed=part.Role switch{"workbook"=>Workbook,"worksheet"=>Worksheet,"styles"=>Styles,"strings"=>Words("sst si t r rPr rFont b i u strike outline shadow condense extend color sz family charset scheme"),_=>throw Rejected()};
            foreach(var node in xml.Descendants())
            {
                ct.ThrowIfCancellationRequested();if(node.Name.NamespaceName!=S||!allowed.Contains(node.Name.LocalName))throw Rejected();
                if(node.Name.LocalName=="definedNames"&&node.HasElements)throw Rejected();
                foreach(var attr in node.Attributes().Where(x=>!x.IsNamespaceDeclaration))
                {
                    if(attr.Value.Length>1024)throw Rejected();if(attr.Name==XNamespace.Xml+"space"&&node.Name.LocalName=="t"&&attr.Value is "preserve" or "default")continue;
                    if(part.Role=="workbook"&&node.Name.LocalName=="sheet"&&attr.Name==XName.Get("id",R))continue;
                    if(attr.Name.NamespaceName.Length!=0||!Attributes.Contains(attr.Name.LocalName))throw Rejected();
                    if(CriticalAttributes.TryGetValue(node.Name.LocalName,out var attributeNames)&&!attributeNames.Contains(attr.Name.LocalName))throw Rejected();
                    if(attr.Name.LocalName is "hidden" or "collapsed" or "zeroHeight"&&attr.Value is not ("0" or "false"))throw Rejected();
                    if(attr.Name.LocalName=="visibility"&&attr.Value!="visible")throw Rejected();if(attr.Name.LocalName=="showZeros"&&attr.Value is not ("1" or "true"))throw Rejected();
                    if(attr.Name.LocalName=="count"&&part.Role=="styles"&&Integer(attr.Value,0,100)!=node.Elements().Count())throw Rejected();
                    if(attr.Name.LocalName is "activeCell" or "topLeftCell")Cell(attr.Value);
                    if(attr.Name.LocalName=="sqref")Range(attr.Value);
                }
                if(node.Name.LocalName=="t"&&(node.Value.Length>100||(literal+=node.Value.Length)>50_000))throw Rejected();
                if(node.Name.LocalName is "rFont" or "name"&&node.Attribute("val") is XAttribute font&&(font.Value.Contains(':')||font.Value.Contains('/')||font.Value.Contains('\\')))throw Rejected();
                if(node.Name.LocalName=="sz")Number(Attr(node,"val"),6,30);
                foreach(var value in node.Attributes().Where(x=>!x.IsNamespaceDeclaration))
                {if(value.Name.LocalName=="textRotation")Integer(value.Value,0,180);if(value.Name.LocalName=="indent")Integer(value.Value,0,16);if(value.Name.LocalName=="relativeIndent")Number(value.Value,-16,16);if(value.Name.LocalName=="readingOrder")Integer(value.Value,0,2);if(value.Name.LocalName is "outlineLevel" or "outlineLevelRow" or "outlineLevelCol")Integer(value.Value,0,7);if(value.Name.LocalName is "xSplit" or "ySplit")Number(value.Value,0,3000);if(value.Name.LocalName=="baseColWidth")Integer(value.Value,3,20);}

                if(node.Name.LocalName is "color" or "fgColor" or "bgColor" or "rgbColor")foreach(var color in node.Attributes().Where(x=>!x.IsNamespaceDeclaration))
                {if(color.Name.LocalName=="rgb"&&!Regex.IsMatch(color.Value,@"^(?:[A-Fa-f0-9]{6}|[A-Fa-f0-9]{8})$",RegexOptions.CultureInvariant))throw Rejected();if(color.Name.LocalName=="indexed")Integer(color.Value,0,64);if(color.Name.LocalName=="theme")Integer(color.Value,0,11);if(color.Name.LocalName=="tint")Number(color.Value,-1,1);if(color.Name.LocalName=="auto"&&color.Value is not ("0" or "1" or "false" or "true"))throw Rejected();}
            }
        }
        var links=new Dictionary<string,List<Link>>(StringComparer.Ordinal);var linkCount=0;
        foreach(var (name,xml) in xmls.Where(x=>definitions[x.Key].Role=="rels"))
        {
            if(xml.Root!.Attributes().Any(x=>!x.IsNamespaceDeclaration))throw Rejected();var owner=name=="_rels/.rels"?"":"xl/workbook.xml";var ids=new HashSet<string>(StringComparer.Ordinal);var list=new List<Link>();
            foreach(var node in xml.Root.Elements())
            {
                if(++linkCount>64||node.Name!=XName.Get("Relationship",Rel))throw Rejected();Only(node,"Id","Type","Target","TargetMode");var id=Attr(node,"Id");var kind=Attr(node,"Type");var mode=(string?)node.Attribute("TargetMode");if(id.Length>128||!ids.Add(id)||mode is not (null or "Internal"))throw Rejected();
                var target=Resolve(owner,Attr(node,"Target"));if(!definitions.TryGetValue(target,out var to)||!Allowed(owner,to.Role,kind))throw Rejected();list.Add(new(id,kind,target));
            }
            links.Add(owner,list);
        }
        if(!links.TryGetValue("",out var roots)||roots.Count(x=>x.Kind==R+"/officeDocument"&&x.Target=="xl/workbook.xml")!=1||!links.TryGetValue("xl/workbook.xml",out var workbookLinks))throw Rejected();
        var reached=roots.Select(x=>x.Target).Concat(workbookLinks.Select(x=>x.Target)).ToHashSet(StringComparer.Ordinal);if(definitions.Any(x=>x.Value.Role!="rels"&&!reached.Contains(x.Key)))throw Rejected();
        var workbook=xmls["xl/workbook.xml"].Root!;Unique(workbook,"fileVersion","workbookPr","bookViews","sheets","calcPr");var declarations=workbook.Element(XName.Get("sheets",S))?.Elements(XName.Get("sheet",S)).ToArray()??[];
        if(declarations.Length<1||declarations.Length>Math.Min(10,limits.MaximumPages)||declarations.Length!=definitions.Count(x=>x.Value.Role=="worksheet"))throw Rejected();
        var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);var sheetIds=new HashSet<int>();var targets=new HashSet<string>(StringComparer.Ordinal);var sheets=new Dictionary<string,XDocument>(StringComparer.Ordinal);
        foreach(var sheet in declarations)
        {
            var name=Attr(sheet,"name");if(name.Length>31||name.Any(x=>char.IsControl(x)||"[]:*?/\\".Contains(x))||!names.Add(name)||(string?)sheet.Attribute("state") is not (null or "visible")||!sheetIds.Add(Integer(Attr(sheet,"sheetId"),1,65535)))throw Rejected();
            var id=(string?)sheet.Attribute(XName.Get("id",R));var link=workbookLinks.SingleOrDefault(x=>x.Id==id);if(link is null||link.Kind!=R+"/worksheet"||!targets.Add(link.Target))throw Rejected();sheets.Add(link.Target,xmls[link.Target]);
        }
        var styles=xmls.GetValueOrDefault("xl/styles.xml");var styleCount=StyleCount(styles);var shared=xmls.GetValueOrDefault("xl/sharedStrings.xml");var strings=shared?.Root!.Elements(XName.Get("si",S)).ToArray()??[];if(strings.Length>6000||strings.Any(x=>x.Value.Length>100))throw Rejected();var usage=new int[strings.Length];
        if(shared?.Root?.Attribute("uniqueCount") is XAttribute unique&&Integer(unique.Value,0,6000)!=strings.Length)throw Rejected();var total=0;var displayedText=0;
        foreach(var (name,xml) in sheets){ct.ThrowIfCancellationRequested();var sheet=Sheet(xml,strings,usage,styleCount);total+=sheet.Cells;displayedText+=sheet.Text;if(total>4800||displayedText>50_000)throw Rejected();}
        if(usage.Any(x=>x==0)||shared?.Root?.Attribute("count") is XAttribute count&&Integer(count.Value,0,6000)!=usage.Sum())throw Rejected();
        return(sheets,total);
    }
    private static (int Cells,int Text) Sheet(XDocument xml,XElement[] strings,int[] usage,int styles)
    {
        var root=xml.Root!;Unique(root,"sheetPr","dimension","sheetViews","sheetFormatPr","cols","sheetData","mergeCells","printOptions","pageMargins","pageSetup");var data=root.Element(XName.Get("sheetData",S))??throw Rejected();var rows=data.Elements().ToArray();if(rows.Length>40||data.Elements().Any(x=>x.Name!=XName.Get("row",S)))throw Rejected();
        if(root.Element(XName.Get("dimension",S)) is XElement dimension)Range(Attr(dimension,"ref"));var defaultHeight=15d;if(root.Element(XName.Get("sheetFormatPr",S)) is XElement format&&format.Attribute("defaultRowHeight") is XAttribute height)defaultHeight=Number(height.Value,8,30);
        var defaultWidth=root.Element(XName.Get("sheetFormatPr",S))?.Attribute("defaultColWidth") is XAttribute dw?Number(dw.Value,3,20):8.43;
        var columnWidths=Enumerable.Repeat(defaultWidth,12).ToArray();var seenCols=new HashSet<int>();foreach(var column in root.Element(XName.Get("cols",S))?.Elements()??[]){if(column.Name!=XName.Get("col",S))throw Rejected();var min=Integer(Attr(column,"min"),1,12);var max=Integer(Attr(column,"max"),min,12);var width=column.Attribute("width") is XAttribute value?Number(value.Value,3,20):defaultWidth;if(column.Attribute("style") is XAttribute style)Integer(style.Value,0,styles-1);for(var i=min;i<=max;i++){if(!seenCols.Add(i))throw Rejected();columnWidths[i-1]=width;}}
        var textWork=0;var seenRows=new HashSet<int>();var cells=new Dictionary<(int Column,int Row),bool>();var greatestRow=0;var greatestCol=0;var rowHeights=new Dictionary<int,double>();
        foreach(var row in rows)
        {
            var rowId=Integer(Attr(row,"r"),1,40);if(!seenRows.Add(rowId)||row.Elements().Any(x=>x.Name!=XName.Get("c",S)))throw Rejected();greatestRow=Math.Max(greatestRow,rowId);rowHeights[rowId]=row.Attribute("ht") is XAttribute h?Number(h.Value,8,30):defaultHeight;
            if(row.Attribute("s") is XAttribute rowStyle)Integer(rowStyle.Value,0,styles-1);if(row.Attribute("spans") is XAttribute spans){var split=spans.Value.Split(':');if(split.Length!=2)throw Rejected();var from=Integer(split[0],1,12);Integer(split[1],from,12);}
            foreach(var cell in row.Elements())
            {
                var coordinate=Cell(Attr(cell,"r"));if(coordinate.Row!=rowId||!cells.TryAdd(coordinate,false)||cells.Count>480)throw Rejected();if(cell.Attribute("s") is XAttribute style)Integer(style.Value,0,styles-1);
                greatestCol=Math.Max(greatestCol,coordinate.Column);
                var type=(string?)cell.Attribute("t")??"n";var values=cell.Elements(XName.Get("v",S)).ToArray();var inline=cell.Elements(XName.Get("is",S)).ToArray();if(values.Length>1||inline.Length>1||cell.Elements().Any(x=>x.Name!=XName.Get("v",S)&&x.Name!=XName.Get("is",S)))throw Rejected();var nonempty=false;
                if(type=="inlineStr"){if(values.Length!=0||inline.Length!=1||inline[0].Value.Length>100)throw Rejected();nonempty=inline[0].Value.Length>0;textWork+=inline[0].Value.Length;}
                else {if(inline.Length!=0)throw Rejected();if(values.Length==1){var text=values[0].Value;if(text.Length>64||values[0].HasElements)throw Rejected();if(type=="s"){var at=Integer(text,0,strings.Length-1);usage[at]++;nonempty=strings[at].Value.Length>0;textWork+=strings[at].Value.Length;}else if(type=="b"){if(text is not ("0" or "1"))throw Rejected();nonempty=true;textWork++;}else if(type=="n"){Number(text,-1e15,1e15);nonempty=true;textWork+=text.Length;}else throw Rejected();}else if(type is not ("n" or "s" or "b"))throw Rejected();}
                cells[coordinate]=nonempty;
            }
        }
        if(!cells.Values.Any(x=>x)||columnWidths.Take(greatestCol).Sum()>120||Enumerable.Range(1,greatestRow).Sum(x=>rowHeights.GetValueOrDefault(x,defaultHeight))>600)throw Rejected();
        var occupied=new HashSet<(int,int)>();var merges=root.Element(XName.Get("mergeCells",S))?.Elements().ToArray()??[];if(merges.Length>50)throw Rejected();foreach(var merge in merges){if(merge.Name!=XName.Get("mergeCell",S))throw Rejected();var bounds=Range(Attr(merge,"ref"));for(var row=bounds.From.Row;row<=bounds.To.Row;row++)for(var col=bounds.From.Column;col<=bounds.To.Column;col++){if(!occupied.Add((col,row))||(col!=bounds.From.Column||row!=bounds.From.Row)&&cells.GetValueOrDefault((col,row)))throw Rejected();}}
        return(cells.Count,textWork);
    }
    private static int StyleCount(XDocument? styles)
    {
        if(styles is null)return 1;var root=styles.Root!;Unique(root,"numFmts","fonts","fills","borders","cellStyleXfs","cellXfs","cellStyles","dxfs","tableStyles","colors");if(root.Element(XName.Get("numFmts",S))?.HasElements==true||root.Element(XName.Get("dxfs",S))?.HasElements==true)throw Rejected();
        int Count(string parent,int max){var list=root.Element(XName.Get(parent,S));if(list is null)return 0;var count=list.Elements().Count();if(count>max||list.Attribute("count") is XAttribute declared&&Integer(declared.Value,0,max)!=count)throw Rejected();return count;}
        var fonts=Count("fonts",32);var fills=Count("fills",32);var borders=Count("borders",32);var xfs=Count("cellXfs",100);var baseXfs=Count("cellStyleXfs",100);Count("cellStyles",100);if(fonts<1||fills<1||borders<1||xfs<1)throw Rejected();
        foreach(var xf in root.Descendants(XName.Get("xf",S))){if(xf.Attribute("numFmtId") is XAttribute fmt)Integer(fmt.Value,0,49);if(xf.Attribute("fontId") is XAttribute font)Integer(font.Value,0,fonts-1);if(xf.Attribute("fillId") is XAttribute fill)Integer(fill.Value,0,fills-1);if(xf.Attribute("borderId") is XAttribute border)Integer(border.Value,0,borders-1);if(xf.Attribute("xfId") is XAttribute baseId)Integer(baseId.Value,0,Math.Max(0,baseXfs-1));}
        foreach(var size in root.Descendants(XName.Get("sz",S)))Number(Attr(size,"val"),6,30);return xfs;
    }
    private byte[] PrintCopy(Dictionary<string,byte[]> parts,Dictionary<string,XDocument> sheets,CancellationToken ct)
    {
        using var output=new MemoryStream();using(var zip=new ZipArchive(new BoundedDocumentStream(output,limits.MaximumBytes),ZipArchiveMode.Create,true))foreach(var (name,bytes) in parts)
        {
            ct.ThrowIfCancellationRequested();using var part=zip.CreateEntry(name,CompressionLevel.Optimal).Open();if(!sheets.TryGetValue(name,out var xml)){part.Write(bytes);continue;}
            var root=xml.Root!;var properties=root.Element(XName.Get("sheetPr",S));if(properties is null){properties=new XElement(XName.Get("sheetPr",S));root.AddFirst(properties);}var setup=properties.Element(XName.Get("pageSetUpPr",S));if(setup is null){setup=new XElement(XName.Get("pageSetUpPr",S));properties.Add(setup);}setup.SetAttributeValue("fitToPage","1");setup.SetAttributeValue("autoPageBreaks","0");
            root.Elements(XName.Get("pageMargins",S)).Remove();root.Elements(XName.Get("pageSetup",S)).Remove();root.Add(new XElement(XName.Get("pageMargins",S),new XAttribute("left","0.25"),new XAttribute("right","0.25"),new XAttribute("top","0.25"),new XAttribute("bottom","0.25"),new XAttribute("header","0"),new XAttribute("footer","0")));
            root.Add(new XElement(XName.Get("pageSetup",S),new XAttribute("paperSize","9"),new XAttribute("orientation","landscape"),new XAttribute("fitToWidth","1"),new XAttribute("fitToHeight","1")));
            using var writer=System.Xml.XmlWriter.Create(part,new(){Encoding=new UTF8Encoding(false),CloseOutput=false});xml.Save(writer);
        }
        if(output.Length>limits.MaximumBytes)throw Rejected();return output.ToArray();
    }
    private static void Theme(XDocument xml,CancellationToken ct)
    {
        var additional=Words("camera lightRig rot scene3d sp3d bevelT bevelB spDef lnDef txDef style spPr defPPr sx sy");foreach(var node in xml.Descendants())
        {ct.ThrowIfCancellationRequested();var local=node.Name.LocalName;if(node.Name.NamespaceName!=A||local is "blip" or "blipFill" or "fld"||!PptxPackageValidation.IsStaticDrawingElement(local)&&!additional.Contains(local))throw Rejected();foreach(var attr in node.Attributes().Where(x=>!x.IsNamespaceDeclaration)){if(attr.Name.NamespaceName.Length!=0||attr.Value.Length>4096||!PptxPackageValidation.IsStaticDrawingAttribute(attr.Name.LocalName)&&attr.Name.LocalName is not ("lat" or "lon" or "rev" or "rig" or "cmpd"))throw Rejected();if(attr.Name.LocalName=="typeface"&&(attr.Value.Contains(':')||attr.Value.Contains('/')||attr.Value.Contains('\\')))throw Rejected();}}
    }
    private static void Metadata(XDocument xml,string role)
    {
        var names=Words(role=="core"?"coreProperties title subject creator description language lastModifiedBy revision category contentStatus version keywords lastPrinted created modified identifier":"Properties Application PresentationFormat Slides Notes HiddenSlides MMClips ScaleCrop HeadingPairs TitlesOfParts Manager Company LinksUpToDate SharedDoc HyperlinksChanged AppVersion DocSecurity TotalTime Worksheets vector lpstr lpwstr i4 variant bool");
        foreach(var node in xml.Descendants()){if(!names.Contains(node.Name.LocalName)||node.Name.NamespaceName is not (Core or App or Vt or "http://purl.org/dc/elements/1.1/" or "http://purl.org/dc/terms/"))throw Rejected();foreach(var attr in node.Attributes().Where(x=>!x.IsNamespaceDeclaration)){if(attr.Name==XName.Get("type","http://www.w3.org/2001/XMLSchema-instance")&&attr.Value=="dcterms:W3CDTF")continue;if(node.Name.NamespaceName==Vt&&node.Name.LocalName=="vector"&&attr.Name.NamespaceName.Length==0&&attr.Name.LocalName is "size" or "baseType"){if(attr.Name.LocalName=="size")Integer(attr.Value,0,200);continue;}throw Rejected();}}
    }
    private static Part Definition(string name)=>name switch
    {
        "_rels/.rels" or "xl/_rels/workbook.xml.rels"=>new("rels","application/vnd.openxmlformats-package.relationships+xml",XName.Get("Relationships",Rel)),
        "xl/workbook.xml"=>new("workbook","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",XName.Get("workbook",S)),
        "xl/styles.xml"=>new("styles","application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml",XName.Get("styleSheet",S)),
        "xl/sharedStrings.xml"=>new("strings","application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml",XName.Get("sst",S)),
        "xl/theme/theme1.xml"=>new("theme","application/vnd.openxmlformats-officedocument.theme+xml",XName.Get("theme",A)),
        "docProps/core.xml"=>new("core","application/vnd.openxmlformats-package.core-properties+xml",XName.Get("coreProperties",Core)),
        "docProps/app.xml"=>new("app","application/vnd.openxmlformats-officedocument.extended-properties+xml",XName.Get("Properties",App)),
        _ when Regex.IsMatch(name,@"^xl/worksheets/sheet[1-9][0-9]{0,3}\.xml$",RegexOptions.CultureInvariant)=>new("worksheet","application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml",XName.Get("worksheet",S)),
        _=>throw Rejected()
    };
    private static bool Allowed(string owner,string role,string kind)=>owner.Length==0?kind==R+"/officeDocument"&&role=="workbook"||kind==R+"/extended-properties"&&role=="app"||kind=="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties"&&role=="core":kind==R+"/worksheet"&&role=="worksheet"||kind==R+"/styles"&&role=="styles"||kind==R+"/sharedStrings"&&role=="strings"||kind==R+"/theme"&&role=="theme";
    private static string Resolve(string owner,string target){if(target.Length>512||target.Contains(':')||target.Contains('%')||target.Contains('\\')||target.Contains('?')||target.Contains('#'))throw Rejected();var absolute=target.StartsWith('/');var parts=absolute?new List<string>():owner.Split('/').SkipLast(1).ToList();if(absolute)target=target[1..];foreach(var item in target.Split('/')){if(item==".."){if(parts.Count==0)throw Rejected();parts.RemoveAt(parts.Count-1);}else{if(item.Length==0||item=="."||item!=item.Trim())throw Rejected();parts.Add(item);}}return string.Join('/',parts);}
    private static ((int Column,int Row) From,(int Column,int Row) To) Range(string value){var split=value.Split(':');if(split.Length is <1 or >2)throw Rejected();var start=Cell(split[0]);var end=Cell(split[^1]);if(start.Column>end.Column||start.Row>end.Row)throw Rejected();return(start,end);}
    private static (int Column,int Row) Cell(string value){if(!Regex.IsMatch(value,@"^[A-L][1-9][0-9]?$",RegexOptions.CultureInvariant))throw Rejected();var row=Integer(value[1..],1,40);return(value[0]-'A'+1,row);}
    private static int Integer(string value,int min,int max){if(!int.TryParse(value,NumberStyles.None,CultureInfo.InvariantCulture,out var result)||result<min||result>max)throw Rejected();return result;}
    private static double Number(string value,double min,double max){if(value.Length>64||!double.TryParse(value,NumberStyles.Float,CultureInfo.InvariantCulture,out var result)||!double.IsFinite(result)||result<min||result>max)throw Rejected();return result;}
    private static void Unique(XElement node,params string[] names){foreach(var name in names)if(node.Elements(XName.Get(name,S)).Count()>1)throw Rejected();}
    private static XDocument Xml(byte[] bytes,CancellationToken ct,ref int nodes)=>BoundedOfficePackage.Xml(bytes,ct,ref nodes,250_000);
    private static void Only(XElement node,params string[] allowed){if(node.HasElements||node.Attributes().Any(x=>!x.IsNamespaceDeclaration&&(x.Name.NamespaceName.Length!=0||!allowed.Contains(x.Name.LocalName))))throw Rejected();}
    private static string Attr(XElement node,string name)=>string.IsNullOrWhiteSpace((string?)node.Attribute(name))?throw Rejected():(string)node.Attribute(name)!;
    private static HashSet<string> Words(string value)=>new(value.Split(' ',StringSplitOptions.RemoveEmptyEntries),StringComparer.Ordinal);
    private static DocumentRejectedException Rejected()=>new("This XLSX is outside the bounded values-only profile. Export a PDF and try again.");
}
