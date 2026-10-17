using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using QuillSign.Data;
using QuillSign.Documents;

namespace QuillSign.Legal;

// Callers verify scheduling before building new disclosures from this authorized,
// verified immutable upload snapshot. Historical snapshots are never regenerated.
// It grants no document, signing or deletion authority.
internal sealed record DemoDisclosureContext(string PublicId,int Days,DateTimeOffset StartedAt,DateTimeOffset DeleteAfter,string RetentionSha256)
{
    internal static DemoDisclosureContext? From(bool isDemo,string publicId,DocumentRetentionSnapshot? verified)=>
        !isDemo || verified is null ? null : new(publicId,verified.Days,verified.StartedAt,verified.DeleteAfter,UploadRetention.Digest(verified));
}

internal static class SyntheticDemoDisclosure
{
    internal const string Profile="synthetic-demo-v1";
    internal const string Version="synthetic-demo-2026-10-17.2";
    private static readonly UTF8Encoding Utf8=new(false,true);
    private static readonly Lazy<string> Template=new(()=>{
        using var input=typeof(ElectronicRecordDisclosure).Assembly.GetManifestResourceStream("QuillSign.Legal.SyntheticDemoDisclosure.txt")
            ?? throw new InvalidOperationException("The synthetic disclosure template is missing.");
        using var reader=new StreamReader(input,Utf8,false);
        return reader.ReadToEnd().Replace("\r\n","\n").Replace('\r','\n').TrimEnd() + "\n";
    });

    internal static DisclosureSnapshot Build(string publicId,string title,string contact,DemoDisclosureContext? context)
    {
        if(context is null || context.PublicId!=publicId || context.Days is <1 or >36500 || context.StartedAt.Offset!=TimeSpan.Zero ||
            context.DeleteAfter.Offset!=TimeSpan.Zero || context.StartedAt==default ||
            context.StartedAt> DateTimeOffset.MaxValue.AddDays(-context.Days) || context.DeleteAfter!=context.StartedAt.AddDays(context.Days) ||
            context.RetentionSha256 is not {Length:64} || context.RetentionSha256.Any(c=>!char.IsAsciiHexDigit(c)))
            throw new DisclosureRejectedException("A verified fixed demo retention policy is required.");
        var values=new Dictionary<string,string>(StringComparer.Ordinal) {
            ["version"]=Version,["public_id"]=publicId,["title"]=title,["sender_contact"]=contact,
            ["days"]=context.Days.ToString(CultureInfo.InvariantCulture),
            ["started_at"]=context.StartedAt.ToString("yyyy-MM-dd HH:mm:ss 'UTC'",CultureInfo.InvariantCulture),
            ["delete_after"]=context.DeleteAfter.ToString("yyyy-MM-dd HH:mm:ss 'UTC'",CultureInfo.InvariantCulture),
            ["retention_digest"]=context.RetentionSha256
        };
        // Replace only template placeholders; inserted context is always literal text.
        var text=System.Text.RegularExpressions.Regex.Replace(Template.Value,@"\{\{([a-z_]+)\}\}",m=>
            values.TryGetValue(m.Groups[1].Value,out var value) ? value : throw new InvalidOperationException("Unknown synthetic disclosure placeholder."));
        if(text.Length>ElectronicRecordDisclosure.MaximumTextCharacters)throw new DisclosureRejectedException("The disclosure exceeds the supported length.");
        return new(Version,publicId,title,contact,text,SHA256.HashData(Utf8.GetBytes(text)));
    }
}
