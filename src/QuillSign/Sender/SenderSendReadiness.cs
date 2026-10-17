using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using QuillSign.Documents;
using QuillSign.Legal;

namespace QuillSign.Sender;

public static class SenderSendStatement
{
    public const string Version="sender-send-v1";
    public const string Text="I approve sending this reviewed document to the listed signers in this order.";
    public static string Sha256=>Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Text)));
}

public sealed record SendReadiness(bool Available,string? Error,DisclosureSnapshot? Disclosure);
public sealed class SenderSendReadiness(SenderAvailability availability,ElectronicRecordDisclosure disclosures,TimeProvider time)
{
    public bool CanDispatch=>availability.CanSend;
    public SendReadiness Read(ClaimsPrincipal user,DraftReviewSnapshot draft)
    {
        var identity=SendDraftWorkflow.Identity(user,draft.PublicId);
        if(identity is null)return new(false,"This verified sender session is unavailable.",null);
        if(draft.ExpiresAt<=time.GetUtcNow())return new(false,"This draft has expired. Start a new request.",null);
        DisclosureSnapshot snapshot;
        try { snapshot=disclosures.Build(draft.PublicId,draft.Title,identity.Value.Email,draft.DemoDisclosure); }
        catch(DisclosureRejectedException) { return new(false,"Electronic-record disclosure settings or document details are incomplete. Check the draft or contact this instance's operator.",null); }
        return availability.CanSend ? new(true,null,snapshot) : new(false,"Invitation sending is unavailable right now. Your document remains a draft.",snapshot);
    }
}
