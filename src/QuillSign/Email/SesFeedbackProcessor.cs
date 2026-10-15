using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;

namespace QuillSign.Email;

public sealed record SesFeedback(string MessageId, string[] Recipients, EmailStatus Status, SuppressionReason? Suppression)
{
    public static SesFeedback? Parse(string message, EmailOptions options)
    {
        using var json = SnsMessageValidator.ParseJson(Encoding.UTF8.GetBytes(message));
        var root = json.RootElement;
        var type = SnsMessageValidator.Required(root, "eventType", 64);
        if (type is not ("Bounce" or "Complaint" or "Send" or "Delivery" or "Reject" or "Rendering Failure")) return null;
        if (!root.TryGetProperty("mail", out var mail)) throw new InvalidSnsMessageException();
        var id = SnsMessageValidator.Required(mail, "messageId", 512);
        try
        {
            if (EmailAddress.Normalize(SnsMessageValidator.Required(mail, "source", 512)) != EmailAddress.Normalize(options.FromEmail))
                throw new InvalidSnsMessageException();
            if (!mail.TryGetProperty("tags", out var tags) || !tags.TryGetProperty("ses:configuration-set", out var configSets) ||
                configSets.ValueKind != JsonValueKind.Array || configSets.GetArrayLength() != 1 || configSets[0].GetString() != options.Ses.ConfigurationSet)
                throw new InvalidSnsMessageException();
            if (!mail.TryGetProperty("destination", out var destination) || destination.ValueKind != JsonValueKind.Array || destination.GetArrayLength() is < 1 or > 50)
                throw new InvalidSnsMessageException();
            var recipients = destination.EnumerateArray().Select(x => x.ValueKind == JsonValueKind.String
                ? EmailAddress.Normalize(x.GetString()!) : throw new InvalidSnsMessageException()).Distinct().Order().ToArray();
            SuppressionReason? suppression = null;
            var status = type is "Send" or "Delivery" ? EmailStatus.Sent : EmailStatus.Failed;
            if (type is "Bounce" or "Complaint")
            {
                var field = type == "Bounce" ? "bounce" : "complaint";
                if (!root.TryGetProperty(field, out var feedback) ||
                    !feedback.TryGetProperty(type == "Bounce" ? "bouncedRecipients" : "complainedRecipients", out var affected) ||
                    affected.ValueKind != JsonValueKind.Array || affected.GetArrayLength() is < 1 or > 50)
                    throw new InvalidSnsMessageException();
                var targets = affected.EnumerateArray().Select(x => EmailAddress.Normalize(SnsMessageValidator.Required(x, "emailAddress", 320)))
                    .Distinct().Order().ToArray();
                if (targets.Except(recipients).Any()) throw new InvalidSnsMessageException();
                recipients = targets;
                if (type == "Complaint") { suppression = SuppressionReason.Complaint; status = EmailStatus.Complained; }
                else
                {
                    var bounce = SnsMessageValidator.Required(feedback, "bounceType", 32);
                    if (bounce is not ("Permanent" or "Transient" or "Undetermined")) throw new InvalidSnsMessageException();
                    if (bounce == "Permanent") { suppression = SuppressionReason.Bounce; status = EmailStatus.Bounced; }
                }
            }
            return new SesFeedback(id, recipients, status, suppression);
        }
        catch (ArgumentException) { throw new InvalidSnsMessageException(); }
        catch (InvalidOperationException) { throw new InvalidSnsMessageException(); }
    }
}

public sealed class SesFeedbackProcessor(QuillSignDbContext db, TimeProvider time)
{
    public async Task ApplyAsync(SesFeedback feedback, CancellationToken cancellationToken)
    {
        // Conditional updates are the deduplication boundary. A duplicate notification
        // leaves rowversions/timestamps unchanged, even when replicas race to process it.
        await db.Database.CreateExecutionStrategy().ExecuteAsync(async () =>
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            foreach (var recipient in feedback.Recipients.Order(StringComparer.Ordinal))
            {
                if (feedback.Suppression is { } reason)
                {
                    var reasonName = reason.ToString();
                    var at = time.GetUtcNow();
                    await db.Database.ExecuteSqlInterpolatedAsync($"""
                        IF NOT EXISTS (SELECT 1 FROM [Suppressions] WITH (UPDLOCK, HOLDLOCK) WHERE [Email] = {recipient})
                            INSERT INTO [Suppressions] ([Email], [Reason], [CreatedAt]) VALUES ({recipient}, {reasonName}, {at});
                        ELSE IF {reasonName} = N'Complaint'
                            UPDATE [Suppressions] SET [Reason] = N'Complaint' WHERE [Email] = {recipient} AND [Reason] = N'Bounce';
                        """, cancellationToken);
                }
                var matches = db.EmailOutbox.Where(x => x.Provider == "Ses" && x.ProviderMessageId == feedback.MessageId && x.To == recipient);
                matches = feedback.Status switch
                {
                    EmailStatus.Sent => matches.Where(x => x.Status == EmailStatus.Queued),
                    EmailStatus.Failed => matches.Where(x => x.Status == EmailStatus.Queued || x.Status == EmailStatus.Sent),
                    EmailStatus.Bounced => matches.Where(x => x.Status != EmailStatus.Bounced && x.Status != EmailStatus.Complained),
                    EmailStatus.Complained => matches.Where(x => x.Status != EmailStatus.Complained),
                    _ => throw new InvalidOperationException("Unsupported feedback status.")
                };
                await matches.ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, feedback.Status), cancellationToken);
            }
            await transaction.CommitAsync(cancellationToken);
        });
    }
}
