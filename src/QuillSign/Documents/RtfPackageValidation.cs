using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Xml;

namespace QuillSign.Documents;

// Explicit RTF grammar -> owned DOCX. Unknown destinations are never skipped into a converter.
public sealed class RtfPackageValidation(DocumentOptions limits,DocxPackageValidation docx)
{
    public async Task<ValidatedOfficeSource> ValidateAsync(Stream input,long declaredLength,CancellationToken ct=default)
    {
        ct.ThrowIfCancellationRequested();ArgumentNullException.ThrowIfNull(input);
        if(limits.MaximumBytes is <1024 or >64*1024*1024||limits.MaximumPages is <1 or >200)throw new InvalidOperationException("Configure supported document limits.");
        if(declaredLength is <7 or >1024*1024||declaredLength>limits.MaximumBytes)throw Rejected();
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(15));byte[]? original=null;byte[]? derived=null;var transferred=false;
        try
        {
            using var owned=new MemoryStream();var buffer=new byte[16384];int count;while((count=await input.ReadAsync(buffer,timeout.Token))!=0){if(owned.Length+count>declaredLength)throw Rejected();await owned.WriteAsync(buffer.AsMemory(0,count),timeout.Token);}if(owned.Length!=declaredLength)throw Rejected();original=owned.ToArray();
            var document=new Reader(original,limits.MaximumPages,timeout.Token).Parse();derived=Build(document,limits.MaximumBytes,timeout.Token);using var stream=new MemoryStream(derived,false);using var checkedDocx=await docx.ValidateAsync(stream,derived.Length,timeout.Token);timeout.Token.ThrowIfCancellationRequested();
            var result=new ValidatedOfficeSource(original,OfficeSourceKind.Rtf,0,612,792,derived);transferred=true;return result;
        }
        catch(OperationCanceledException) when(!ct.IsCancellationRequested){throw Rejected();}
        catch(Exception e) when(e is DocumentRejectedException or XmlException or IOException or ArgumentException or OverflowException or NotSupportedException){throw Rejected();}
        finally {if(!transferred){if(original is not null)Array.Clear(original);if(derived is not null)Array.Clear(derived);}}
    }
    private sealed record Format(bool Bold=false,bool Italic=false,bool Underline=false,int HalfPoints=24,int Font=0,int Color=0);
    private sealed record State(Format Format,int UnicodeFallback=1);
    private sealed record Run(Format Format,StringBuilder Text);
    private sealed class Paragraph {internal string Alignment="left";internal List<Run> Runs=[];}
    private sealed record Document(List<Paragraph> Paragraphs,Dictionary<int,string> Fonts,List<string?> Colors);
    private enum Kind {Open,Close,Text,Control,End}
    private readonly record struct Token(Kind Kind,string Word="",int? Parameter=null,char Character='\0');
    private sealed class Reader(byte[] bytes,int maximumPages,CancellationToken ct)
    {
        private int at,tokens,textWork,runs,groups,pages=1,defaultFont;private bool ansi,body,fontTable,colorTable,explicitCodePage;private readonly List<Paragraph> paragraphs=[new()];private readonly Dictionary<int,string> fonts=new(){[0]="Liberation Sans"};private readonly List<string?> colors=[null];
        private Paragraph Current=>paragraphs[^1];
        internal Document Parse()
        {
            if(Next().Kind!=Kind.Open||Next()!=new Token(Kind.Control,"rtf",1))throw Rejected();Group(new(new()),1,true);if(Next().Kind!=Kind.End||!ansi||!fonts.ContainsKey(defaultFont)||!paragraphs.SelectMany(x=>x.Runs).Any(x=>!string.IsNullOrWhiteSpace(x.Text.ToString())))throw Rejected();return new(paragraphs,fonts,colors);
        }
        private void Group(State state,int depth,bool root=false)
        {
            if(depth>32||++groups>10000)throw Rejected();var fallback=0;var first=true;
            while(true)
            {
                var token=Next();if(token.Kind==Kind.End)throw Rejected();
                if(fallback>0){if(token.Kind!=Kind.Text)throw Rejected();fallback--;first=false;continue;}
                if(token.Kind==Kind.Close)return;
                if(token.Kind==Kind.Open){if(!ansi)throw Rejected();Group(state,depth+1);first=false;continue;}
                if(token.Kind==Kind.Text){if(!ansi)throw Rejected();Append(state.Format,token.Character);first=false;continue;}
                var word=token.Word;var n=token.Parameter;
                if(first&&!root&&word is "fonttbl" or "colortbl")
                {if(depth!=2||body||n is not null)throw Rejected();if(word=="fonttbl")Fonts();else Colors();return;}
                first=false;
                switch(word)
                {
                    case "ansi":if(!root||body||n is not null||ansi)throw Rejected();ansi=true;break;
                    case "ansicpg":if(!root||body||n!=1252)throw Rejected();explicitCodePage=true;break;
                    case "deff":if(!root||body)throw Rejected();defaultFont=Required(n,0,31);state=state with {Format=state.Format with {Font=defaultFont}};break;
                    case "viewkind":if(!root||body||n!=4)throw Rejected();break;
                    case "deflang":if(!root||body)throw Rejected();Required(n,0,65535);break;
                    case "lang":Required(n,0,65535);break;
                    case "uc":state=state with {UnicodeFallback=Required(n,0,4)};break;
                    case "u":var unicode=unchecked((char)(ushort)(short)Required(n,-32768,32767));if(char.IsSurrogate(unicode)||char.IsControl(unicode))throw Rejected();Append(state.Format,unicode);fallback=state.UnicodeFallback;break;
                    case "b":state=state with {Format=state.Format with {Bold=Toggle(n)}};break;
                    case "i":state=state with {Format=state.Format with {Italic=Toggle(n)}};break;
                    case "ul":state=state with {Format=state.Format with {Underline=Toggle(n)}};break;
                    case "ulnone":NoParameter(n);state=state with {Format=state.Format with {Underline=false}};break;
                    case "fs":state=state with {Format=state.Format with {HalfPoints=Required(n,16,48)}};break;
                    case "f":var font=Required(n,0,31);if(!fonts.ContainsKey(font))throw Rejected();state=state with {Format=state.Format with {Font=font}};break;
                    case "cf":state=state with {Format=state.Format with {Color=Required(n,0,colors.Count-1)}};break;
                    case "plain":NoParameter(n);state=state with {Format=new(Font:defaultFont)};break;
                    case "pard":if(!root)throw Rejected();NoParameter(n);Current.Alignment="left";break;
                    case "ql":case "qc":case "qr":case "qj":if(!root)throw Rejected();NoParameter(n);Current.Alignment=word switch{"ql"=>"left","qc"=>"center","qr"=>"right",_=>"both"};break;
                    case "par":NoParameter(n);if(paragraphs.Count>=1000)throw Rejected();paragraphs.Add(new(){Alignment=Current.Alignment});body=true;break;
                    case "tab":NoParameter(n);Append(state.Format,'\t');break;
                    case "line":NoParameter(n);Append(state.Format,'\n');break;
                    case "page":NoParameter(n);if(++pages>maximumPages)throw Rejected();Append(state.Format,'\f');break;
                    case "paperw":case "paperh":case "margl":case "margr":case "margt":case "margb":if(!root||body||n!=(word=="paperw"?12240:word=="paperh"?15840:1440))throw Rejected();break;
                    default:throw Rejected();
                }
            }
        }
        private void Fonts()
        {
            if(fontTable)throw Rejected();fontTable=true;fonts.Clear();
            while(true)
            {
                var token=Next();if(token.Kind==Kind.Close){if(fonts.Count<1)throw Rejected();return;}if(token.Kind!=Kind.Open||Next() is not {Kind:Kind.Control,Word:"f",Parameter:int id}||id is <0 or >31||fonts.ContainsKey(id)||fonts.Count>=32)throw Rejected();var name=new StringBuilder();var finished=false;
                while(true)
                {
                    token=Next();if(token.Kind==Kind.Close){if(!finished||name.Length is <1 or >64)throw Rejected();var actual=name.ToString().Trim();if(actual.Length==0)throw Rejected();fonts.Add(id,actual);break;}
                    if(token.Kind==Kind.Text){if(finished)throw Rejected();if(token.Character==';'){finished=true;continue;}if(!char.IsLetterOrDigit(token.Character)&&token.Character is not (' ' or '-' or '_'))throw Rejected();name.Append(token.Character);if(name.Length>64)throw Rejected();continue;}
                    if(token.Kind!=Kind.Control||name.Length>0||finished)throw Rejected();switch(token.Word){case "fnil":case "froman":case "fswiss":case "fmodern":NoParameter(token.Parameter);break;case "fcharset":if(token.Parameter!=0)throw Rejected();break;case "fprq":Required(token.Parameter,0,2);break;default:throw Rejected();}
                }
            }
        }
        private void Colors()
        {
            if(colorTable)throw Rejected();colorTable=true;colors.Clear();var components=new int[3];var seen=new HashSet<int>();var first=true;
            while(true)
            {
                var token=Next();if(token.Kind==Kind.Close){if(seen.Count!=0||colors.Count<1)throw Rejected();return;}
                if(token is {Kind:Kind.Text,Character:';'}){if(colors.Count>=32||seen.Count==0&&!first)throw Rejected();colors.Add(seen.Count==0?null:$"{components[0]:X2}{components[1]:X2}{components[2]:X2}");first=false;Array.Clear(components);seen.Clear();continue;}
                if(token.Kind!=Kind.Control)throw Rejected();var channel=token.Word switch{"red"=>0,"green"=>1,"blue"=>2,_=>throw Rejected()};if(!seen.Add(channel))throw Rejected();components[channel]=Required(token.Parameter,0,255);
            }
        }
        private void Append(Format format,char value)
        {
            body=true;if(!fonts.ContainsKey(format.Font)||format.Color>=colors.Count||++textWork>50_000||char.IsControl(value)&&value is not ('\t' or '\n' or '\f'))throw Rejected();
            if(Current.Runs.Count==0||Current.Runs[^1].Format!=format){if(++runs>10000)throw Rejected();Current.Runs.Add(new(format,new()));}Current.Runs[^1].Text.Append(value);
        }
        private Token Next()
        {
            if(++tokens>150000)throw Rejected();ct.ThrowIfCancellationRequested();while(at<bytes.Length&&bytes[at] is 10 or 13)at++;if(at==bytes.Length)return new(Kind.End);var b=bytes[at++];if(b=='{')return new(Kind.Open);if(b=='}')return new(Kind.Close);if(b!='\\')return new(Kind.Text,Character:Character(b));if(at==bytes.Length)throw Rejected();b=bytes[at++];
            if(b is (byte)'\\' or (byte)'{' or (byte)'}')return new(Kind.Text,Character:(char)b);
            if(b=='\''){if(at+2>bytes.Length||!byte.TryParse(Encoding.ASCII.GetString(bytes,at,2),NumberStyles.HexNumber,CultureInfo.InvariantCulture,out var escaped))throw Rejected();at+=2;return new(Kind.Text,Character:Character(escaped));}
            if(b=='~')return new(Kind.Text,Character:'\u00a0');if(b=='_')return new(Kind.Text,Character:'\u2011');if(b=='-')return new(Kind.Text,Character:'\u00ad');
            if(!char.IsAsciiLetter((char)b))throw Rejected();var start=at-1;while(at<bytes.Length&&char.IsAsciiLetter((char)bytes[at]))at++;if(at-start>32)throw Rejected();var word=Encoding.ASCII.GetString(bytes,start,at-start);int? number=null;var numberStart=at;if(at<bytes.Length&&bytes[at]=='-')at++;var digits=at;while(at<bytes.Length&&char.IsAsciiDigit((char)bytes[at]))at++;if(at-digits>6||at!=numberStart&&at==digits)throw Rejected();if(at>numberStart){if(!int.TryParse(Encoding.ASCII.GetString(bytes,numberStart,at-numberStart),NumberStyles.AllowLeadingSign,CultureInfo.InvariantCulture,out var value))throw Rejected();number=value;}if(at<bytes.Length&&bytes[at]==' ')at++;return new(Kind.Control,word,number);
        }
        private char Character(byte value)
        {
            if(value is <32 and not 9||value==127||value>=128&&!explicitCodePage)throw Rejected();if(value<128||value>=160)return(char)value;
            const string map="\u20ac\0\u201a\u0192\u201e\u2026\u2020\u2021\u02c6\u2030\u0160\u2039\u0152\0\u017d\0\0\u2018\u2019\u201c\u201d\u2022\u2013\u2014\u02dc\u2122\u0161\u203a\u0153\0\u017e\u0178";var character=map[value-128];return character=='\0'?throw Rejected():character;
        }
        private static int Required(int? value,int min,int max)=>value is int n&&n>=min&&n<=max?n:throw Rejected();
        private static bool Toggle(int? value)=>value is null or 1?true:value==0?false:throw Rejected();
        private static void NoParameter(int? value){if(value is not null)throw Rejected();}
    }
    private static byte[] Build(Document source,long maximum,CancellationToken ct)
    {
        const string w="http://schemas.openxmlformats.org/wordprocessingml/2006/main";using var result=new MemoryStream();
        using(var zip=new ZipArchive(new BoundedDocumentStream(result,maximum),ZipArchiveMode.Create,true))
        {
            void Part(string name,string content){using var writer=new StreamWriter(zip.CreateEntry(name).Open(),new UTF8Encoding(false,true));writer.Write(content);}
            Part("[Content_Types].xml","<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/></Types>");
            Part("_rels/.rels","<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/></Relationships>");
            using var document=new MemoryStream();using(var xml=XmlWriter.Create(new BoundedDocumentStream(document,8*1024*1024),new(){Encoding=new UTF8Encoding(false,true),CloseOutput=false}))
            {
                void Start(string name)=>xml.WriteStartElement("w",name,w);void Value(string name,string value){Start(name);xml.WriteAttributeString("w","val",w,value);xml.WriteEndElement();}
                Start("document");Start("body");foreach(var paragraph in source.Paragraphs)
                {
                    ct.ThrowIfCancellationRequested();Start("p");Start("pPr");Value("jc",paragraph.Alignment);xml.WriteEndElement();foreach(var run in paragraph.Runs)
                    {
                        Start("r");Start("rPr");Start("rFonts");xml.WriteAttributeString("w","ascii",w,source.Fonts[run.Format.Font]);xml.WriteAttributeString("w","hAnsi",w,source.Fonts[run.Format.Font]);xml.WriteEndElement();Value("sz",run.Format.HalfPoints.ToString(CultureInfo.InvariantCulture));if(run.Format.Bold)Value("b","1");if(run.Format.Italic)Value("i","1");if(run.Format.Underline)Value("u","single");if(source.Colors[run.Format.Color] is string color)Value("color",color);xml.WriteEndElement();var text=run.Text.ToString();var start=0;
                        void Literal(int end){if(end==start)return;Start("t");xml.WriteAttributeString("xml","space",null,"preserve");xml.WriteString(text[start..end]);xml.WriteEndElement();}
                        for(var i=0;i<text.Length;i++){if(text[i] is not ('\t' or '\n' or '\f'))continue;Literal(i);Start(text[i]=='\t'?"tab":"br");if(text[i]=='\f')xml.WriteAttributeString("w","type",w,"page");xml.WriteEndElement();start=i+1;}Literal(text.Length);xml.WriteEndElement();
                    }
                    xml.WriteEndElement();
                }
                Start("sectPr");Start("pgSz");xml.WriteAttributeString("w","w",w,"12240");xml.WriteAttributeString("w","h",w,"15840");xml.WriteEndElement();Start("pgMar");foreach(var side in new[]{"top","right","bottom","left"})xml.WriteAttributeString("w",side,w,"1440");xml.WriteEndElement();xml.WriteEndElement();xml.WriteEndElement();xml.WriteEndElement();
            }
            ct.ThrowIfCancellationRequested();document.Position=0;using var output=zip.CreateEntry("word/document.xml").Open();document.CopyTo(output);
        }
        return result.ToArray();
    }
    private static DocumentRejectedException Rejected()=>new("This RTF is outside the bounded literal formatting profile. Export a PDF and try again.");
}
