using QuillSign.Data;

namespace QuillSign.Completion;

public sealed class CompletionPublicationOptions
{
    public int? CompletedDays {get;set;}
    public int? DemoPurgeAfterDays {get;set;}
    public bool AllowDevelopmentWriteOnce {get;set;}
    internal FinalRetention Select(Envelope envelope,IHostEnvironment environment)
    {
        var days=envelope.IsDemo ? DemoPurgeAfterDays : CompletedDays;
        if(days is null || days<0 || days>36500 || envelope.IsDemo && days==0)
            throw new CompletionPublicationUnavailableException("Configure an explicit supported server retention interval before publication.");
        return new(days.Value,AllowDevelopmentWriteOnce && environment.IsDevelopment() && envelope.IsDemo);
    }
}
public sealed record FinalRetention(int Days,bool DevelopmentWriteOnce)
{
    public DateTimeOffset? RequiredUntil(DateTimeOffset decision)=>Days==0 ? null : decision.ToUniversalTime().AddDays(Days);
}
public sealed class CompletionPublicationUnavailableException(string message) : Exception(message);
