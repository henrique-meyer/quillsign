using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.WebUtilities;

namespace QuillSign.Email;

public sealed record VerifiedSnsMessage(string Type, string Message, Uri? ConfirmationUrl);

public sealed class SnsMessageValidator(EmailOptions options, ISnsCertificateSource certificates)
{
    public async Task<VerifiedSnsMessage> ValidateAsync(byte[] body, CancellationToken cancellationToken)
    {
        using var json = ParseJson(body);
        var root = json.RootElement;
        var type = Required(root, "Type", 64);
        if (type is not ("Notification" or "SubscriptionConfirmation" or "UnsubscribeConfirmation")) throw new InvalidSnsMessageException();
        var topic = Required(root, "TopicArn", 512);
        if (!string.Equals(topic, options.Sns.TopicArn, StringComparison.Ordinal)) throw new InvalidSnsMessageException();
        var host = TopicHost(topic);
        if (!Guid.TryParseExact(Required(root, "MessageId", 36), "D", out _) ||
            !DateTimeOffset.TryParse(Required(root, "Timestamp", 64), CultureInfo.InvariantCulture, DateTimeStyles.None, out var timestamp) ||
            timestamp.Offset != TimeSpan.Zero) throw new InvalidSnsMessageException();
        var message = Required(root, "Message", 512 * 1024);
        var version = Required(root, "SignatureVersion", 1);
        if (version is not ("1" or "2")) throw new InvalidSnsMessageException();
        var certificateUrl = ValidAwsUrl(Required(root, "SigningCertURL", 2048), host);
        if (certificateUrl.Query.Length != 0 || !Regex.IsMatch(certificateUrl.AbsolutePath,
            "^/SimpleNotificationService-[A-Za-z0-9_-]+\\.pem$", RegexOptions.CultureInvariant)) throw new InvalidSnsMessageException();
        Uri? confirmation = null;
        if (type != "Notification")
        {
            confirmation = ValidAwsUrl(Required(root, "SubscribeURL", 8192), host);
            var query = QueryHelpers.ParseQuery(confirmation.Query);
            if (confirmation.AbsolutePath != "/" || query.Count != 3 ||
                !query.TryGetValue("Action", out var action) || action.Count != 1 || action[0] != "ConfirmSubscription" ||
                !query.TryGetValue("TopicArn", out var queryTopic) || queryTopic.Count != 1 || queryTopic[0] != topic ||
                !query.TryGetValue("Token", out var token) || token.Count != 1 || token[0] != Required(root, "Token", 4096))
                throw new InvalidSnsMessageException();
        }
        var canonical = Canonical(root, type);
        byte[] signature;
        try { signature = Convert.FromBase64String(Required(root, "Signature", 2048)); }
        catch (FormatException) { throw new InvalidSnsMessageException(); }
        var der = await certificates.GetAsync(certificateUrl, cancellationToken);
        using var certificate = X509CertificateLoader.LoadCertificate(der);
        using var rsa = certificate.GetRSAPublicKey();
        if (rsa is null || !rsa.VerifyData(Encoding.UTF8.GetBytes(canonical), signature,
            version == "2" ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1))
            throw new InvalidSnsMessageException();
        return new VerifiedSnsMessage(type, message, confirmation);
    }

    public static string TopicHost(string arn)
    {
        var match = Regex.Match(arn, "^arn:(aws|aws-us-gov|aws-cn):sns:([a-z]{2}(?:-[a-z]+)+-[0-9]):[0-9]{12}:[A-Za-z0-9_-]{1,256}$", RegexOptions.CultureInvariant);
        if (!match.Success) throw new InvalidOperationException("Configure a valid SNS topic ARN.");
        return "sns." + match.Groups[2].Value + (match.Groups[1].Value == "aws-cn" ? ".amazonaws.com.cn" : ".amazonaws.com");
    }

    private static Uri ValidAwsUrl(string value, string host)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.Port != 443 ||
            uri.Host != host || uri.UserInfo.Length != 0 || uri.Fragment.Length != 0 || value.Contains('%') && uri.Query.Length == 0 || value.Contains('\\'))
            throw new InvalidSnsMessageException();
        return uri;
    }

    private static string Canonical(JsonElement root, string type)
    {
        var fields = type == "Notification"
            ? new[] { "Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type" }
            : ["Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"];
        var output = new StringBuilder();
        foreach (var field in fields)
        {
            if (field == "Subject" && !root.TryGetProperty(field, out _)) continue;
            output.Append(field).Append('\n').Append(Required(root, field, 512 * 1024)).Append('\n');
        }
        return output.ToString();
    }

    internal static string Required(JsonElement root, string name, int maximum)
    {
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String ||
            value.GetString() is not { Length: > 0 } text || text.Length > maximum) throw new InvalidSnsMessageException();
        return text;
    }

    internal static JsonDocument ParseJson(byte[] bytes)
    {
        try
        {
            var json = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 32 });
            try { CheckDuplicates(json.RootElement); return json; }
            catch { json.Dispose(); throw; }
        }
        catch (JsonException) { throw new InvalidSnsMessageException(); }
    }

    private static void CheckDuplicates(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in value.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new InvalidSnsMessageException();
                CheckDuplicates(property.Value);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
            foreach (var item in value.EnumerateArray()) CheckDuplicates(item);
    }
}
