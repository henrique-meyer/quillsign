using System.Collections.Immutable;
using System.Text.Json.Serialization;

namespace QuillSign.Email.Pilot;

// A separately configured, closed finishing purpose. Enabling this never makes
// an expired EmailPilotManifest, token, enrollment or operator session live.
public sealed class EmailPilotCloseoutOptions
{
    public bool Enabled { get; set; }
    public EmailPilotCloseoutHostRole HostRole { get; set; }
    public string PrivateConfigurationSet { get; set; } = "";
    public string AuthorizationId { get; set; } = "";
    public string CapabilitySha256 { get; set; } = "";
    public DateTimeOffset StartsAt { get; set; }
    public DateTimeOffset Until { get; set; }
    public string[] AccountingParentRunIds { get; set; } = [];
    public string CompletionParentRunId { get; set; } = "";
    public string VoidParentRunId { get; set; } = "";
    public string CompletionRecordId { get; set; } = "";
    public string VoidRecordId { get; set; } = "";
    public string DeclineRecordId { get; set; } = "";
    public string[] CompletionWorkIds { get; set; } = [];
    public string[] VoidWorkIds { get; set; } = [];

    public void Validate()
    {
        if (!Enum.IsDefined(HostRole) || HostRole==EmailPilotCloseoutHostRole.Handoff && Enabled) throw Invalid();
        if (HostRole!=EmailPilotCloseoutHostRole.Legacy && !PrivateSet(PrivateConfigurationSet)) throw Invalid();
        if (HostRole==EmailPilotCloseoutHostRole.Legacy && PrivateConfigurationSet.Length!=0) throw Invalid();
        if (Enabled) _ = Capture();
    }
    internal static bool PrivateSet(string value)=>value is {Length:>=1 and <=64} && value.All(c=>char.IsAsciiLetterOrDigit(c)||c is '-' or '_');
    internal bool PrivateSetBinding(EmailOptions email)=>email.Provider=="Ses"&&email.Ses is not null&&PrivateSet(PrivateConfigurationSet)&&PrivateSet(email.Ses.ConfigurationSet)&&PrivateConfigurationSet!=email.Ses.ConfigurationSet;
    internal bool Host(EmailOptions email,Work.WorkOptions work,bool browser=false)
    {
        if(!work.Enabled)return false;
        if(HostRole==EmailPilotCloseoutHostRole.Legacy)return !email.Enabled;
        return email.Enabled && email.Provider=="Ses" && email.Ses is not null && PrivateSet(PrivateConfigurationSet) && PrivateSet(email.Ses.ConfigurationSet) &&
            !string.Equals(PrivateConfigurationSet,email.Ses.ConfigurationSet,StringComparison.Ordinal) &&
            (browser ? HostRole==EmailPilotCloseoutHostRole.Web : HostRole is EmailPilotCloseoutHostRole.Web or EmailPilotCloseoutHostRole.Pass);
    }

    internal EmailPilotCloseoutConfiguration Capture()
    {
        if (!Enabled) throw Invalid();
        return CaptureReceiptConfiguration();
    }

    // Structural facts only. Callers must independently authenticate an already
    // issued live receipt session; this never enables a mutating action.
    internal EmailPilotCloseoutConfiguration CaptureReceiptConfiguration()
    {
        if (!EmailPilotCanonical.Hash(CapabilitySha256) || StartsAt.Offset != TimeSpan.Zero || Until.Offset != TimeSpan.Zero ||
            StartsAt == default || Until <= StartsAt || Until > StartsAt.AddMinutes(30) ||
            AccountingParentRunIds is not { Length: >= 2 and <= 8 } || CompletionWorkIds is not { Length: 4 } || VoidWorkIds is not { Length: 2 }) throw Invalid();
        var id = Id(AuthorizationId); var completeParent = Id(CompletionParentRunId); var voidParent = Id(VoidParentRunId);
        var parents = AccountingParentRunIds.Select(Id).ToImmutableArray();
        var complete = Id(CompletionRecordId); var terminal = Id(VoidRecordId); var decline = Id(DeclineRecordId);
        var completeWork = CompletionWorkIds.Select(Id).ToImmutableArray(); var terminalWork = VoidWorkIds.Select(Id).ToImmutableArray();
        if (parents.Distinct().Count() != parents.Length || parents.Contains(id) || completeParent == voidParent ||
            !parents.Contains(completeParent) || !parents.Contains(voidParent) || new[] { complete, terminal, decline }.Distinct().Count() != 3 ||
            completeWork.Concat(terminalWork).Distinct().Count() != 6) throw Invalid();
        ValidateRole();
        return new(id, CapabilitySha256, StartsAt, Until, parents, completeParent, voidParent, complete, terminal, decline, completeWork, terminalWork,
            HostRole==EmailPilotCloseoutHostRole.Legacy?null:new("filtered-closeout-coexistence-v1",PrivateConfigurationSet));
    }
    private void ValidateRole()
    {if(!Enum.IsDefined(HostRole)||HostRole==EmailPilotCloseoutHostRole.Legacy&&PrivateConfigurationSet.Length!=0||HostRole!=EmailPilotCloseoutHostRole.Legacy&&!PrivateSet(PrivateConfigurationSet))throw Invalid();}

    private static Guid Id(string raw) => Guid.TryParseExact(raw, "N", out var id) && id != Guid.Empty ? id : throw Invalid();
    private static InvalidOperationException Invalid() => new("Configure one exact, bounded private closeout purpose and its existing records.");
}
public enum EmailPilotCloseoutHostRole { Legacy, Web, Pass, Handoff }
internal sealed record EmailPilotCloseoutCoexistence(string Version,string PrivateConfigurationSet);

internal sealed record EmailPilotCloseoutConfiguration(Guid AuthorizationId, string CapabilitySha256, DateTimeOffset StartsAt,
    DateTimeOffset Until, ImmutableArray<Guid> AccountingParents, Guid CompletionParent, Guid VoidParent, Guid CompletionRecord,
    Guid VoidRecord, Guid DeclineRecord, ImmutableArray<Guid> CompletionWork, ImmutableArray<Guid> VoidWork,
    [property:JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)] EmailPilotCloseoutCoexistence? Coexistence=null);

internal enum EmailPilotCloseoutStep
{
    CompletionSender, CompletionFirstSigner, CompletionSecondSigner, CompletionRecipient,
    VoidSender, VoidSigner, DeclineVerification, DeclineInvitation, DeclineNotice, Lookup
}

internal static class EmailPilotCloseoutLimits
{
    internal const string Version = "restricted-failed-notice-closeout-v1";
    internal const int ApplicationAttempts = 10;
    internal const int PriorApplicationAttempts = 12, PriorSimulatorAttempts = 4, PriorTimestampAttempts = 4;
    internal const long PriorEncodedBytes = 27918, EncodedBytes = 31429362;
}
