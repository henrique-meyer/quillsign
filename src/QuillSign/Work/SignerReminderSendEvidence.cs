using System.Text.Json;
using QuillSign.Documents;

namespace QuillSign.Work;

// New Send evidence is the authority. The original mutable ReminderDaysJson
// array is never interpreted as an approved schedule for an old envelope.
public static class SignerReminderSendEvidence
{
    public static void DemandReview(SignerReminderPolicy policy,string? reviewedSha256,string? schedulingVersion=null)
    {
        // A pre-upgrade review may send only the same explicitly empty policy.
        // An enabled schedule always needs its exact new review hash.
        if(reviewedSha256 is null && policy.Days.IsEmpty)return;
        if(reviewedSha256!=policy.Sha256 || !policy.Days.IsEmpty && schedulingVersion!=SignerReminderEvidence.Version)throw new DocumentConflictException();
    }
    public static SignerReminderPolicy Read(JsonElement sent,bool isDemo)
    {
        if(sent.ValueKind!=JsonValueKind.Object || sent.EnumerateObject().Count(x=>x.Name=="reminderPolicy")>1 ||
            sent.EnumerateObject().Count(x=>x.Name=="reminderPolicySha256")>1)throw Invalid();
        var hasPolicy=sent.TryGetProperty("reminderPolicy",out var policy);
        var hasHash=sent.TryGetProperty("reminderPolicySha256",out var hash);
        if(!hasPolicy && !hasHash)return new SignerReminderOptions().Freeze(isDemo);
        if(!hasPolicy || !hasHash || policy.ValueKind!=JsonValueKind.String || hash.ValueKind!=JsonValueKind.String)
            throw Invalid();
        var saved=SignerReminderPolicy.Read(policy.GetString()!,hash.GetString()!);
        if(isDemo && !saved.Days.IsEmpty)throw Invalid();
        return saved;
    }
    public static string? SchedulingVersion(JsonElement sent,bool isDemo)
    {
        var policy=Read(sent,isDemo);
        var members=sent.EnumerateObject().Where(x=>x.Name=="reminderSchedulingVersion").ToArray();
        if(members.Length==0)return null; // Old policy-only evidence never authorizes work.
        if(members.Length!=1 || members[0].Value.ValueKind!=JsonValueKind.String || members[0].Value.GetString()!=SignerReminderEvidence.Version ||
            !sent.TryGetProperty("reminderPolicy",out _) || !sent.TryGetProperty("reminderPolicySha256",out _))throw Invalid();
        return SignerReminderEvidence.Version;
    }
    private static InvalidDataException Invalid()=>new("The reviewed reminder policy could not be verified.");
}
