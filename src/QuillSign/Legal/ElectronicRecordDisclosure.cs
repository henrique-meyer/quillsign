using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using QuillSign.Email;

namespace QuillSign.Legal;

public sealed class ElectronicRecordOptions
{
    public string PaperCopyInstructions { get; set; } = "";
    public string PaperCopyFees { get; set; } = "";
    public string WithdrawalInstructions { get; set; } = "";
    public string WithdrawalConsequences { get; set; } = "";
    public string ContactUpdateInstructions { get; set; } = "";
    public string AccessRequirements { get; set; } = "";
    public string RetentionNotice { get; set; } = "";
}
public sealed record DisclosureSnapshot(string Version, string PublicId, string Title, string SenderContact, string Text, byte[] Sha256);
public sealed class DisclosureRejectedException(string message) : Exception(message);

// A pure snapshot builder, never a consent action or legal-compliance certification.
public sealed partial class ElectronicRecordDisclosure(ElectronicRecordOptions options)
{
    public const string CurrentVersion = "2026-10-16.1";
    public const int MaximumTextCharacters = 32768;
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly Lazy<string> Template = new(() =>
    {
        using var input = typeof(ElectronicRecordDisclosure).Assembly.GetManifestResourceStream("QuillSign.Legal.ElectronicRecordDisclosure.txt")
            ?? throw new InvalidOperationException("The disclosure template is missing.");
        if (input.Length > MaximumTextCharacters) throw new InvalidOperationException("The disclosure template is oversized.");
        using var reader = new StreamReader(input, Utf8, detectEncodingFromByteOrderMarks: false);
        return Normalize(reader.ReadToEnd(), MaximumTextCharacters, "template", singleLine: false);
    });

    public DisclosureSnapshot Build(string? publicId, string? title, string? senderContact)
    {
        if (publicId is not { Length: 32 } || !publicId.All(char.IsAsciiHexDigit)) throw new DisclosureRejectedException("Use the current envelope identifier.");
        var normalizedTitle = Normalize(title,512,"document title",singleLine:true);
        string contact;
        try { contact = EmailAddress.Normalize(senderContact?.Trim() ?? ""); }
        catch (ArgumentException) { throw new DisclosureRejectedException("Use the verified sender's contact address."); }
        var values = new Dictionary<string,string>(StringComparer.Ordinal)
        {
            ["version"] = CurrentVersion, ["public_id"] = publicId, ["title"] = normalizedTitle, ["sender_contact"] = contact,
            ["paper_copy_instructions"] = Policy(options.PaperCopyInstructions,nameof(options.PaperCopyInstructions)),
            ["paper_copy_fees"] = Policy(options.PaperCopyFees,nameof(options.PaperCopyFees)),
            ["withdrawal_instructions"] = Policy(options.WithdrawalInstructions,nameof(options.WithdrawalInstructions)),
            ["withdrawal_consequences"] = Policy(options.WithdrawalConsequences,nameof(options.WithdrawalConsequences)),
            ["contact_update_instructions"] = Policy(options.ContactUpdateInstructions,nameof(options.ContactUpdateInstructions)),
            ["access_requirements"] = Policy(options.AccessRequirements,nameof(options.AccessRequirements)),
            ["retention_notice"] = Policy(options.RetentionNotice,nameof(options.RetentionNotice))
        };
        // One pass: literal policy/title text is never interpreted as another template.
        var text = Placeholder().Replace(Template.Value, match => values.TryGetValue(match.Groups[1].Value,out var value)
            ? value : throw new InvalidOperationException("An unknown disclosure placeholder was found.")) + "\n";
        if (text.Length > MaximumTextCharacters) throw new DisclosureRejectedException("The disclosure exceeds the supported length.");
        return new(CurrentVersion,publicId,normalizedTitle,contact,text,SHA256.HashData(Utf8.GetBytes(text)));
    }

    public static bool Verify(DisclosureSnapshot? snapshot)
    {
        if (snapshot is null || snapshot.Sha256 is not { Length: 32 } || string.IsNullOrEmpty(snapshot.Text) ||
            snapshot.Text.Length > MaximumTextCharacters || string.IsNullOrEmpty(snapshot.Version) || snapshot.Version.Length > 128 ||
            snapshot.Version.Any(char.IsControl) || snapshot.PublicId is not { Length: 32 } || !snapshot.PublicId.All(char.IsAsciiHexDigit) ||
            string.IsNullOrEmpty(snapshot.Title) || snapshot.Title.Length > 512 || snapshot.Title.Any(char.IsControl) ||
            string.IsNullOrEmpty(snapshot.SenderContact) || snapshot.SenderContact.Length > 320 || snapshot.SenderContact.Any(char.IsControl)) return false;
        var prefix = $"Electronic Record and Signature Disclosure\nVersion: {snapshot.Version}\nEnvelope: {snapshot.PublicId}\nDocument: {snapshot.Title}\nSender contact: {snapshot.SenderContact}\n";
        if (!snapshot.Text.StartsWith(prefix,StringComparison.Ordinal)) return false;
        try { return CryptographicOperations.FixedTimeEquals(SHA256.HashData(Utf8.GetBytes(snapshot.Text)),snapshot.Sha256); }
        catch (EncoderFallbackException) { return false; }
    }
    private static string Policy(string? value,string name) => Normalize(value,4000,"ElectronicRecords:" + name,singleLine:false);
    private static string Normalize(string? value,int maximum,string name,bool singleLine)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximum) throw new DisclosureRejectedException($"Provide a complete {name} within its length limit.");
        string text;
        try { text = value.Replace("\r\n","\n").Replace('\r','\n').Normalize(NormalizationForm.FormC); }
        catch (ArgumentException) { throw new DisclosureRejectedException($"Use valid Unicode in {name}."); }
        if (text.Length > maximum || text.Any(c => (char.IsControl(c) && (singleLine || c != '\n')) || char.GetUnicodeCategory(c) == System.Globalization.UnicodeCategory.Format))
            throw new DisclosureRejectedException($"Remove unsupported control characters from {name}.");
        return text.Trim();
    }
    [GeneratedRegex(@"\{\{([a-z_]+)\}\}",RegexOptions.CultureInvariant)]
    private static partial Regex Placeholder();
}
