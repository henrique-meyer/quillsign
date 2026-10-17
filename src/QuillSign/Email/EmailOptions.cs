using MimeKit;

namespace QuillSign.Email;

public sealed class EmailOptions
{
    public bool Enabled { get; set; }
    public string Provider { get; set; } = "Ses";
    public string FromEmail { get; set; } = "";
    public string FromName { get; set; } = "QuillSign";
    public string BaseUrl { get; set; } = "";
    public SesOptions Ses { get; set; } = new();
    public SmtpOptions Smtp { get; set; } = new();
    public SnsOptions Sns { get; set; } = new();
    public EmailAttachmentOptions Attachments { get; set; } = new();
}

public sealed class SesOptions
{
    public string Region { get; set; } = "";
    public string ConfigurationSet { get; set; } = "";
}

public sealed class SmtpOptions
{
    public string Host { get; set; } = "";
    public int Port { get; set; } = 587;
    public bool UseStartTls { get; set; } = true;
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
}

public sealed class SnsOptions
{
    public bool Enabled { get; set; }
    public string TopicArn { get; set; } = "";
    public bool AutoConfirmSubscriptions { get; set; }
}

public static class EmailAddress
{
    public static string Normalize(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 320 || value.Any(c => c is '\r' or '\n') ||
            !MailboxAddress.TryParse(value, out var address) || address.Address.Any(c => c > 127))
            throw new ArgumentException("A single valid email address is required.");
        var separator = address.Address.LastIndexOf('@');
        if (separator <= 0 || separator == address.Address.Length - 1)
            throw new ArgumentException("An email address with a domain is required.");
        return address.Address.ToLowerInvariant();
    }
}
