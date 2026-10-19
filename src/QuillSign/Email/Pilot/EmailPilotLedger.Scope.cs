using QuillSign.Data;

namespace QuillSign.Email.Pilot;

public sealed partial class EmailPilotLedger
{
    internal async Task<T?> ReadScopeAsync<T>(Guid envelopeId,
        Func<QuillSignDbContext,EmailPilotManifest,EmailPilotEnrollment,Task<T?>> read,CancellationToken ct) where T:class
    {
        if(!Enabled || envelopeId==Guid.Empty)return null;
        var id=RunId;var db=database();await Open(db,ct);
        var run=await Manifest(db,id,true,ct);if(run is null)return null;
        var saved=(await Enrollments(db,run,ct)).SingleOrDefault(x=>x.SubjectEnvelopeId==envelopeId);
        if(saved?.Verification is null)return null;
        var value=await read(db,run,saved);EnsureLive(run);return value;
    }
}
