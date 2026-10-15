using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using QuillSign.Email;

namespace QuillSign.Tests;

// All identities, messages, certificates and recipients are generated/synthetic.
internal sealed class SnsFixtures : ISnsCertificateSource, IDisposable
{
    public const string Topic = "arn:aws:sns:us-east-1:000000000000:synthetic-feedback";
    public const string CertificateUrl = "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-synthetic.pem";
    private readonly RSA key = RSA.Create(2048);
    public X509Certificate2 Certificate { get; }
    public int Fetches { get; private set; }
    public Exception? Failure { get; set; }
    public EmailOptions Options { get; } = new()
    {
        FromEmail = "noreply@example.invalid", BaseUrl = "https://example.invalid/",
        Ses = new() { Region = "us-east-1", ConfigurationSet = "synthetic-config" },
        Sns = new() { Enabled = true, TopicArn = Topic }
    };

    public SnsFixtures()
    {
        var request = new CertificateRequest("CN=synthetic SNS test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    public Task<byte[]> GetAsync(Uri uri, CancellationToken cancellationToken)
    {
        Fetches++;
        if (Failure is not null) throw Failure;
        return Task.FromResult(Certificate.RawData);
    }

    public Dictionary<string, string> Message(string payload, string type = "Notification", string version = "2")
    {
        var value = new Dictionary<string, string>
        {
            ["Type"] = type, ["MessageId"] = Guid.NewGuid().ToString(), ["TopicArn"] = Topic,
            ["Timestamp"] = "2025-01-01T00:00:00.000Z", // Old valid retries must still authenticate.
            ["Message"] = payload, ["SignatureVersion"] = version, ["SigningCertURL"] = CertificateUrl
        };
        if (type != "Notification")
        {
            value["Token"] = "synthetic-confirmation-token";
            value["SubscribeURL"] = QueryHelpers.AddQueryString("https://sns.us-east-1.amazonaws.com/", new Dictionary<string, string?>
            { ["Action"] = "ConfirmSubscription", ["TopicArn"] = Topic, ["Token"] = value["Token"] });
        }
        return value;
    }

    public byte[] Sign(Dictionary<string, string> value)
    {
        // Independent fixture implementation follows the AWS SNS wire specification.
        var order = value["Type"] == "Notification"
            ? new[] { "Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type" }
            : ["Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"];
        var canonical = string.Concat(order.Where(value.ContainsKey).Select(name => name + "\n" + value[name] + "\n"));
        value["Signature"] = Convert.ToBase64String(key.SignData(Encoding.UTF8.GetBytes(canonical),
            value["SignatureVersion"] == "1" ? HashAlgorithmName.SHA1 : HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        return JsonSerializer.SerializeToUtf8Bytes(value);
    }

    public string Feedback(string recipient, string id, string type = "Bounce", string bounceType = "Permanent") => JsonSerializer.Serialize(new
    {
        eventType = type,
        mail = new
        {
            messageId = id, source = Options.FromEmail, destination = new[] { recipient },
            tags = new Dictionary<string, string[]> { ["ses:configuration-set"] = [Options.Ses.ConfigurationSet] }
        },
        bounce = new { bounceType, bouncedRecipients = new[] { new { emailAddress = recipient } } },
        complaint = new { complainedRecipients = new[] { new { emailAddress = recipient } } }
    });

    public void Dispose() { Certificate.Dispose(); key.Dispose(); }
}
