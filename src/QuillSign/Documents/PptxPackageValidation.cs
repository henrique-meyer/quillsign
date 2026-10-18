using System.Globalization;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace QuillSign.Documents;

// A closed static PresentationML profile. This is not an extension/MIME allowlist.
public sealed class PptxPackageValidation(DocumentOptions limits)
{
    private const string P="http://schemas.openxmlformats.org/presentationml/2006/main",A="http://schemas.openxmlformats.org/drawingml/2006/main",R="http://schemas.openxmlformats.org/officeDocument/2006/relationships";
    private const string C="http://schemas.openxmlformats.org/package/2006/content-types",Rel="http://schemas.openxmlformats.org/package/2006/relationships";
    private const string Core="http://schemas.openxmlformats.org/package/2006/metadata/core-properties",App="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",Vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes";
    private const string MainMime="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml";
    private static readonly HashSet<string> Presentation=Words("presentation sldMasterIdLst sldMasterId sldIdLst sldId sldSz notesSz defaultTextStyle sld cSld spTree nvGrpSpPr cNvPr cNvGrpSpPr nvPr grpSpPr sp nvSpPr cNvSpPr spPr style txBody clrMapOvr masterClrMapping sldLayout sldMaster sldLayoutIdLst sldLayoutId clrMap txStyles titleStyle bodyStyle otherStyle pic nvPicPr cNvPicPr blipFill grpSp hf presentationPr viewPr notesTextViewPr normalViewPr restoredLeft restoredTop slideViewPr cSldViewPr cViewPr scale sx sy origin gridSpacing guideLst guide tableStyleLst");
    private static readonly HashSet<string> Drawing=Words("theme themeElements clrScheme dk1 lt1 dk2 lt2 accent1 accent2 accent3 accent4 accent5 accent6 hlink folHlink fontScheme majorFont minorFont latin ea cs font fmtScheme fillStyleLst solidFill noFill srgbClr sysClr schemeClr prstClr gradFill gsLst gs lin path fillToRect rect tile lnStyleLst ln prstDash round bevel miter headEnd tailEnd effectStyleLst effectStyle effectLst outerShdw innerShdw glow softEdge bgFillStyleLst objectDefaults extraClrSchemeLst custClrLst xfrm off ext chOff chExt prstGeom avLst gdLst gd ahLst cxnLst pathLst moveTo lnTo close pt arcTo cubicBezTo quadBezTo blipFill blip srcRect stretch fillRect bodyPr spLocks picLocks grpSpLocks tblStyleLst lstStyle p pPr defRPr r rPr t br endParaRPr lvl1pPr lvl2pPr lvl3pPr lvl4pPr lvl5pPr lvl6pPr lvl7pPr lvl8pPr lvl9pPr buNone buChar buFont buSzPct buSzPts buAutoNum tabLst tab spcBef spcAft lnSpc spcPts spcPct noAutofit normAutofit spAutoFit lnRef fillRef effectRef fontRef lumMod lumOff tint shade alpha alphaMod alphaOff satMod satOff hueMod hueOff redMod redOff greenMod greenOff blueMod blueOff complement inv gray gamma invGamma masterClrMapping clrMap sRGBClrDef");
    private static readonly HashSet<string> Attributes=Words("n d l t r varScale lastView blurRad dir id name descr title hidden show showMasterSp showMasterPhAnim preserve userDrawn type orient cx cy x y rot flipH flipV sz dirty b i u strike kern cap baseline lang altLang latinLnBrk fontAlgn marL marR indent algn lvl defTabSz rtl eaLnBrk hangingPunct vert vertOverflow horzOverflow wrap lIns tIns rIns bIns numCol spcCol anchor anchorCtr upright compatLnSpc fromWordArt forceAA prst val lastClr script typeface panose pitchFamily charset idx w h bwMode pos ang scaled focus path cstate dpi rotWithShape dist rad lim cp cyStart cyEnd startAt char fmla fact div panose baseType size dt smtClean smtId numFmt pitchFamily preserveAspectRatio def marB marT normSpc reduction fontScale lnSpcReduction spc a cstDsn csIdx minVer grow autofitToFirst lineEnd round1 round2 tile tx1 tx2 bg1 bg2 accent1 accent2 accent3 accent4 accent5 accent6 hlink folHlink scaleCrop snapToGrid snapToObjects showGuides showOutlineIcons showAnimation view showComments zoom useTimings loop showNarration animateBg displayRef by posX posY preferSingleView currentDateAndTime includeDateAndTime includeFooter includeSlideNumber includeHeader showSpecialPls spcFirstLastPara rtlCol spcCol ins grpLocks noGrp noUngrp noRot noChangeAspect noMove noResize noEditPoints noAdjustHandles noChangeArrowheads noChangeShapeType noSelect txBox noTextEdit noChangeAspect noCrop minSz maxSz autoSz numCol");
    private static readonly HashSet<string> CoreNames=Words("coreProperties title subject creator description language lastModifiedBy revision category contentStatus version keywords lastPrinted created modified identifier");
    private static readonly HashSet<string> AppNames=Words("Properties Application PresentationFormat Slides Notes HiddenSlides MMClips ScaleCrop HeadingPairs TitlesOfParts Manager Company LinksUpToDate SharedDoc HyperlinksChanged AppVersion DocSecurity TotalTime HLinks vector lpstr lpwstr i4 variant bool");
    private sealed record Part(string Role,string Mime,XName? Root);
    private sealed record Link(string Id,string Kind,string Target);

    public async Task<ValidatedOfficeSource> ValidateAsync(Stream input,long declaredLength,CancellationToken ct=default)
    {
        if(limits.MaximumPages is <1 or >200)throw new InvalidOperationException("Configure supported Office page limits.");
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(15));
        try
        {
            using var package=await BoundedOfficePackage.ReadAsync(input,declaredLength,limits,timeout.Token);
            var shape=Validate(package.Parts,timeout.Token);timeout.Token.ThrowIfCancellationRequested();return new(package.DetachOriginal(),OfficeSourceKind.Pptx,shape.Pages,shape.Width,shape.Height);
        }
        catch(OperationCanceledException) when(!ct.IsCancellationRequested){throw Rejected();}
        catch(Exception e) when(e is DocumentRejectedException or System.Xml.XmlException or InvalidDataException or IOException or ArgumentException or OverflowException or NotSupportedException){throw Rejected();}
    }

    private (int Pages,double Width,double Height) Validate(Dictionary<string,byte[]> parts,CancellationToken ct)
    {
        if(!parts.TryGetValue("[Content_Types].xml",out var typeBytes)||!parts.ContainsKey("ppt/presentation.xml")||!parts.ContainsKey("_rels/.rels"))throw Rejected();
        var elements=0;var types=BoundedOfficePackage.Xml(typeBytes,ct,ref elements,250_000);if(types.Root?.Name!=XName.Get("Types",C)||types.Root.Attributes().Any(x=>!x.IsNamespaceDeclaration))throw Rejected();
        var defaults=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);var overrides=new Dictionary<string,string>(StringComparer.Ordinal);
        foreach(var item in types.Root.Elements())
        {
            if(item.Name==XName.Get("Default",C)){Only(item,"Extension","ContentType");var ext=Attr(item,"Extension");if(ext is not ("xml" or "rels" or "png" or "jpg" or "jpeg")||!defaults.TryAdd(ext,Attr(item,"ContentType")))throw Rejected();}
            else if(item.Name==XName.Get("Override",C)){Only(item,"PartName","ContentType");var path=Attr(item,"PartName");if(!path.StartsWith('/')||!overrides.TryAdd(path[1..],Attr(item,"ContentType")))throw Rejected();}
            else throw Rejected();
        }
        if(overrides.Any(x=>!parts.ContainsKey(x.Key)))throw Rejected();
        var definitions=new Dictionary<string,Part>(StringComparer.Ordinal);var xmls=new Dictionary<string,XDocument>(StringComparer.Ordinal);long pixels=0;var text=0;var shapes=0;
        foreach(var (name,bytes) in parts)
        {
            ct.ThrowIfCancellationRequested();if(name=="[Content_Types].xml")continue;
            var definition=Definition(name);definitions.Add(name,definition);var actual=overrides.GetValueOrDefault(name)??defaults.GetValueOrDefault(name.Split('.').Last());if(actual!=definition.Mime)throw Rejected();
            if(definition.Role=="image")
            {
                var image=ImageHeaderValidation.Read(bytes,ct);if(image.Mime!=actual||(pixels+=(long)image.Width*image.Height)>48_000_000)throw Rejected();continue;
            }
            var xml=BoundedOfficePackage.Xml(bytes,ct,ref elements,250_000);if(xml.Root?.Name!=definition.Root)throw Rejected();xmls.Add(name,xml);
            if(definition.Role=="rels")continue;
            foreach(var node in xml.Descendants())
            {
                ct.ThrowIfCancellationRequested();if(elements>250_000)throw Rejected();var ns=node.Name.NamespaceName;var local=node.Name.LocalName;
                var allowed=definition.Role switch {"core"=>CoreNames.Contains(local)&&ns is Core or "http://purl.org/dc/elements/1.1/" or "http://purl.org/dc/terms/","app"=>AppNames.Contains(local)&&ns is App or Vt,_=>ns==P&&Presentation.Contains(local)||ns==A&&Drawing.Contains(local)};
                if(!allowed)throw Rejected();
                foreach(var attribute in node.Attributes().Where(x=>!x.IsNamespaceDeclaration))
                {
                    if(attribute.Value.Length>4096)throw Rejected();
                    if(definition.Role=="core"&&attribute.Name==XName.Get("type","http://www.w3.org/2001/XMLSchema-instance")) {if(attribute.Value!="dcterms:W3CDTF")throw Rejected();continue;}
                    if(attribute.Name.NamespaceName==R){if(attribute.Name.LocalName is not ("id" or "embed"))throw Rejected();continue;}
                    if(attribute.Name.NamespaceName.Length!=0||!Attributes.Contains(attribute.Name.LocalName))throw Rejected();
                    if(attribute.Name.LocalName=="hidden"&&attribute.Value is not ("false" or "0")||attribute.Name.LocalName=="show"&&attribute.Value is not ("true" or "1"))throw Rejected();
                    if(attribute.Name.LocalName is "x" or "y")Signed(attribute.Value,-50_800_000,50_800_000);
                    if(attribute.Name.LocalName is "cx" or "cy" or "w" or "h")Positive(attribute.Value,0,50_800_000);
                    if(attribute.Name.LocalName is "blurRad" or "rad")Positive(attribute.Value,0,1_270_000);
                    if(attribute.Name.LocalName=="dist")Positive(attribute.Value,0,12_700_000);
                    if(attribute.Name.LocalName=="rot")Signed(attribute.Value,-21_600_000,21_600_000);
                    if(attribute.Name.LocalName=="sz"&&node.Name.NamespaceName==A&&node.Name.LocalName is "rPr" or "defRPr" or "endParaRPr")Positive(attribute.Value,100,40000);
                    if(attribute.Name.LocalName=="typeface"&&(attribute.Value.Contains(':')||attribute.Value.Contains('/')||attribute.Value.Contains('\\')))throw Rejected();
                }
                if(ns==A&&local=="t"&&(text+=node.Value.Length)>1_000_000)throw Rejected();
                if(ns==P&&local is "sp" or "pic" or "grpSp"&&++shapes>20_000)throw Rejected();
                if(ns==A&&local is "objectDefaults" or "extraClrSchemeLst" or "custClrLst"&&node.HasElements)throw Rejected();
                if(ns==A&&local=="blip"&&node.HasElements)throw Rejected();
            }
        }
        var links=new Dictionary<string,List<Link>>(StringComparer.Ordinal);var count=0;
        foreach(var (name,xml) in xmls.Where(x=>definitions[x.Key].Role=="rels"))
        {
            if(xml.Root!.Attributes().Any(x=>!x.IsNamespaceDeclaration))throw Rejected();
            var owner=Owner(name);if(owner.Length!=0&&!definitions.ContainsKey(owner))throw Rejected();var ids=new HashSet<string>(StringComparer.Ordinal);var list=new List<Link>();
            foreach(var item in xml.Root!.Elements())
            {
                ct.ThrowIfCancellationRequested();if(++count>4096||item.Name!=XName.Get("Relationship",Rel))throw Rejected();Only(item,"Id","Type","Target","TargetMode");
                var id=Attr(item,"Id");var kind=Attr(item,"Type");var mode=(string?)item.Attribute("TargetMode");if(id.Length>128||!ids.Add(id)||mode is not (null or "Internal"))throw Rejected();
                var target=Resolve(owner,Attr(item,"Target"));if(!definitions.TryGetValue(target,out var to)||!AllowedLink(owner.Length==0?"root":definitions[owner].Role,to.Role,kind))throw Rejected();list.Add(new(id,kind,target));
            }
            links.Add(owner,list);
        }
        if(!links.TryGetValue("",out var roots)||roots.Count(x=>x.Kind==R+"/officeDocument"&&x.Target=="ppt/presentation.xml")!=1)throw Rejected();
        var reached=new HashSet<string>(StringComparer.Ordinal);var queue=new Queue<string>(roots.Select(x=>x.Target));while(queue.TryDequeue(out var next)){if(!reached.Add(next))continue;if(links.TryGetValue(next,out var edges))foreach(var edge in edges)queue.Enqueue(edge.Target);}
        if(definitions.Any(x=>x.Value.Role!="rels"&&!reached.Contains(x.Key)))throw Rejected();
        foreach(var (name,xml) in xmls.Where(x=>definitions[x.Key].Role!="rels"))foreach(var node in xml.Descendants())foreach(var reference in node.Attributes().Where(x=>x.Name.NamespaceName==R))
        {
            var expected=node.Name==XName.Get("sldId",P)?"slide":node.Name==XName.Get("sldMasterId",P)?"master":node.Name==XName.Get("sldLayoutId",P)?"layout":node.Name==XName.Get("blip",A)?"image":null;
            if(expected is null||reference.Name.LocalName!=(expected=="image"?"embed":"id")||!links.TryGetValue(name,out var owned)||owned.SingleOrDefault(x=>x.Id==reference.Value) is not Link link||definitions[link.Target].Role!=expected)throw Rejected();
        }
        var main=xmls["ppt/presentation.xml"].Root!;if(main.Elements(XName.Get("sldIdLst",P)).Count()!=1)throw Rejected();var slideIds=main.Element(XName.Get("sldIdLst",P))!.Elements(XName.Get("sldId",P)).ToArray();
        if(slideIds.Length<1||slideIds.Length>limits.MaximumPages||slideIds.Length!=definitions.Count(x=>x.Value.Role=="slide")||slideIds.Select(x=>(string?)x.Attribute(XName.Get("id",R))).Distinct().Count()!=slideIds.Length)throw Rejected();
        var size=main.Elements(XName.Get("sldSz",P)).ToArray();if(size.Length!=1)throw Rejected();Positive(Attr(size[0],"cx"),914400,25_400_000);Positive(Attr(size[0],"cy"),914400,25_400_000);
        var numericIds=new HashSet<long>();foreach(var slide in slideIds){var id=Attr(slide,"id");Positive(id,256,uint.MaxValue);if(!numericIds.Add(long.Parse(id,CultureInfo.InvariantCulture)))throw Rejected();}
        foreach(var (name,xml) in xmls.Where(x=>definitions[x.Key].Role is "slide" or "master" or "layout"))
        {var content=xml.Root!.Elements(XName.Get("cSld",P)).ToArray();if(content.Length!=1||content[0].Elements(XName.Get("spTree",P)).Count()!=1)throw Rejected();}
        return (slideIds.Length,long.Parse(Attr(size[0],"cx"),CultureInfo.InvariantCulture)/12700d,long.Parse(Attr(size[0],"cy"),CultureInfo.InvariantCulture)/12700d);
    }

    private static Part Definition(string name)
    {
        if(name=="_rels/.rels"||Regex.IsMatch(name,@"^ppt/(?:_rels/presentation\.xml|(?:slides|slideMasters|slideLayouts|theme)/_rels/[A-Za-z]+[1-9][0-9]{0,3}\.xml)\.rels$",RegexOptions.CultureInvariant))return new("rels","application/vnd.openxmlformats-package.relationships+xml",XName.Get("Relationships",Rel));
        if(name=="ppt/presentation.xml")return new("main",MainMime,XName.Get("presentation",P));
        if(Regex.IsMatch(name,@"^ppt/slides/slide[1-9][0-9]{0,3}\.xml$",RegexOptions.CultureInvariant))return new("slide","application/vnd.openxmlformats-officedocument.presentationml.slide+xml",XName.Get("sld",P));
        if(Regex.IsMatch(name,@"^ppt/slideMasters/slideMaster[1-9][0-9]{0,3}\.xml$",RegexOptions.CultureInvariant))return new("master","application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml",XName.Get("sldMaster",P));
        if(Regex.IsMatch(name,@"^ppt/slideLayouts/slideLayout[1-9][0-9]{0,3}\.xml$",RegexOptions.CultureInvariant))return new("layout","application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml",XName.Get("sldLayout",P));
        if(Regex.IsMatch(name,@"^ppt/theme/theme[1-9][0-9]{0,3}\.xml$",RegexOptions.CultureInvariant))return new("theme","application/vnd.openxmlformats-officedocument.theme+xml",XName.Get("theme",A));
        if(Regex.IsMatch(name,@"^(?:ppt/media/image[1-9][0-9]{0,3}|docProps/thumbnail)\.(png|jpe?g)$",RegexOptions.CultureInvariant))return new("image",name.EndsWith(".png",StringComparison.Ordinal)?"image/png":"image/jpeg",null);
        if(name=="docProps/core.xml")return new("core","application/vnd.openxmlformats-package.core-properties+xml",XName.Get("coreProperties",Core));
        if(name=="docProps/app.xml")return new("app","application/vnd.openxmlformats-officedocument.extended-properties+xml",XName.Get("Properties",App));
        if(name=="ppt/presProps.xml")return new("properties","application/vnd.openxmlformats-officedocument.presentationml.presProps+xml",XName.Get("presentationPr",P));
        if(name=="ppt/viewProps.xml")return new("properties","application/vnd.openxmlformats-officedocument.presentationml.viewProps+xml",XName.Get("viewPr",P));
        if(name=="ppt/tableStyles.xml")return new("properties","application/vnd.openxmlformats-officedocument.presentationml.tableStyles+xml",XName.Get("tblStyleLst",A));
        throw Rejected();
    }
    private static bool AllowedLink(string from,string to,string kind)
    {
        if(kind=="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties")return from=="root"&&to=="core";
        if(kind==R+"/extended-properties")return from=="root"&&to=="app";
        if(kind=="http://schemas.openxmlformats.org/package/2006/relationships/metadata/thumbnail")return from=="root"&&to=="image";
        if(!kind.StartsWith(R+"/",StringComparison.Ordinal))return false;
        return kind[(R.Length+1)..] switch {"officeDocument"=>from=="root"&&to=="main","slide"=>from=="main"&&to=="slide","slideMaster"=>from is "main" or "layout"&&to=="master","slideLayout"=>from is "slide" or "master"&&to=="layout","theme"=>from=="master"&&to=="theme","image"=>from is "slide" or "layout" or "master"&&to=="image","presProps" or "viewProps" or "tableStyles"=>from=="main"&&to=="properties",_=>false};
    }
    private static string Owner(string name){if(name=="_rels/.rels")return "";var at=name.LastIndexOf("/_rels/",StringComparison.Ordinal);if(at<0)throw Rejected();return name[..at]+"/"+name[(at+7)..^5];}
    private static string Resolve(string owner,string target)
    {
        if(target.Length>512||target.Contains(':')||target.Contains('%')||target.Contains('\\')||target.Contains('?')||target.Contains('#')||target.StartsWith('/'))throw Rejected();
        var path=owner.Split('/').SkipLast(1).ToList();foreach(var item in target.Split('/')){if(item==".."){if(path.Count==0)throw Rejected();path.RemoveAt(path.Count-1);}else {if(item.Length==0||item=="."||item!=item.Trim())throw Rejected();path.Add(item);}}return string.Join('/',path);
    }
    private static void Only(XElement node,params string[] allowed){if(node.HasElements||node.Attributes().Any(x=>!x.IsNamespaceDeclaration&&(x.Name.NamespaceName.Length!=0||!allowed.Contains(x.Name.LocalName))))throw Rejected();}
    private static string Attr(XElement node,string name)=>string.IsNullOrWhiteSpace((string?)node.Attribute(name))?throw Rejected():(string)node.Attribute(name)!;
    private static void Positive(string value,long min,long max){if(!long.TryParse(value,NumberStyles.None,CultureInfo.InvariantCulture,out var parsed)||parsed<min||parsed>max)throw Rejected();}
    private static void Signed(string value,long min,long max){if(!long.TryParse(value,NumberStyles.AllowLeadingSign,CultureInfo.InvariantCulture,out var parsed)||parsed<min||parsed>max)throw Rejected();}
    private static HashSet<string> Words(string value)=>new(value.Split(' ',StringSplitOptions.RemoveEmptyEntries),StringComparer.Ordinal);
    internal static bool IsStaticDrawingElement(string name)=>Drawing.Contains(name);
    internal static bool IsStaticDrawingAttribute(string name)=>Attributes.Contains(name);
    private static DocumentRejectedException Rejected()=>new("This PPTX contains unsupported or malformed content. Export a PDF and try again.");
}
