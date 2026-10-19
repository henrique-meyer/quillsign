using Amazon.SimpleEmailV2;
using Amazon.SimpleEmailV2.Model;

namespace QuillSign.Email.Pilot;

// Constructed lazily by EmailPilotSender only after its committed reservation.
// No MIME regeneration, Simple content, CC/BCC, redirects or SDK send retries.
public sealed class SesPreparedEmailTransport(IAmazonSimpleEmailServiceV2 client, EmailPilotSesSettings settings) : IPreparedEmailTransport
{
    public async Task<EmailDelivery> SendAsync(PreparedRawMime message, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (client.Config.MaxErrorRetry != 0 || client.Config.AllowAutoRedirect || client.Config.UseHttp || client.Config.RegionEndpoint?.SystemName != settings.Region ||
            !string.IsNullOrEmpty(client.Config.ServiceURL) || message.Sender != settings.FromEmail ||
            message.ByteCount is < 1 or > PreparedRawMime.MaximumBytes) throw new EmailPilotTransportRefusedException();
        using var bytes = message.OpenRead();
        SendEmailResponse response;
        try
        {
            response = await client.SendEmailAsync(new SendEmailRequest
            {
                FromEmailAddress = message.Sender,
                Destination = new Destination { ToAddresses = [message.Recipient] },
                ConfigurationSetName = settings.ConfigurationSet,
                Content = new EmailContent { Raw = new RawMessage { Data = bytes } }
            }, cancellationToken);
        }
        catch (AmazonSimpleEmailServiceV2Exception e) when ((int)e.StatusCode is >= 400 and < 500)
        { throw new EmailNotSubmittedException((int)e.StatusCode == 429 || e is TooManyRequestsException or LimitExceededException); }
        if (string.IsNullOrWhiteSpace(response.MessageId)) throw new InvalidOperationException("SES returned no delivery identifier.");
        return new("Ses", response.MessageId);
    }
}
