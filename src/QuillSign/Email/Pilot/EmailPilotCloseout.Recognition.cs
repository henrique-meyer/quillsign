using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

public sealed partial class EmailPilotCloseout
{
    // Denial only: this neither opens the protected manifest nor authenticates a
    // delivery. Initial aliases have no operation row; their immutable header ID
    // and preserved original pair identify them even after secret erasure.
    internal static async Task<bool> RecognizesWorkAsync(QuillSignDbContext db, Guid id, CancellationToken ct = default)
    {
        if (await db.EmailPilotCloseoutOperations.AsNoTracking().AnyAsync(x => x.WorkId == id, ct)) return true;
        var headers = await db.EmailPilotCloseouts.AsNoTracking().Select(x => x.Id).Take(2).ToArrayAsync(ct);
        if (headers.Length == 0) return false;
        if (headers.Length != 1 || headers[0] == Guid.Empty) throw Invalid();
        var work = await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, ct);
        var mail = await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, ct);
        var workRecord = work?.EnvelopeId; var mailRecord = mail?.EnvelopeId;
        // Neither mutable candidate association nor Kind excludes the original
        // enrolled cohort. UNION also retains a single surviving original row.
        var originals = await db.WorkItems.AsNoTracking().Where(x => x.EnvelopeId != null &&
                (x.EnvelopeId == workRecord || x.EnvelopeId == mailRecord || db.EmailPilotEnrollments.Any(e => e.SubjectEnvelopeId == x.EnvelopeId)))
            .Select(x => x.Id).Union(db.EmailOutbox.AsNoTracking().Where(x => x.EnvelopeId != null &&
                (x.EnvelopeId == workRecord || x.EnvelopeId == mailRecord || db.EmailPilotEnrollments.Any(e => e.SubjectEnvelopeId == x.EnvelopeId)))
                .Select(x => x.Id)).Take(4097).ToArrayAsync(ct);
        if (originals.Length > 4096) throw Invalid();
        var matched = originals.Where(original => AliasId(headers[0], original) == id).ToArray();
        if (matched.Length == 0) return false;
        if (matched.Length != 1) throw Invalid();
        var originalId = matched[0];
        var originalWorkRecord = await db.WorkItems.AsNoTracking().Where(x => x.Id == originalId).Select(x => x.EnvelopeId).SingleOrDefaultAsync(ct);
        var originalMailRecord = await db.EmailOutbox.AsNoTracking().Where(x => x.Id == originalId).Select(x => x.EnvelopeId).SingleOrDefaultAsync(ct);
        var originalRecord = originalWorkRecord ?? originalMailRecord;
        if (work is null || mail is null || work.Kind != WorkKind.Email || work.EnvelopeId is null || work.EnvelopeId != mail.EnvelopeId) throw Invalid();
        if (originalRecord is null || originalWorkRecord is not null && originalWorkRecord != originalRecord ||
            originalMailRecord is not null && originalMailRecord != originalRecord || work.EnvelopeId != originalRecord) throw Invalid();
        return true;
    }
}
