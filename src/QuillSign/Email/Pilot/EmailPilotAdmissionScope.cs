using QuillSign.Data;

namespace QuillSign.Email.Pilot;

// Internal single-use authority for preparing one normal verification outbox in
// the transaction which creates its exact live enrollment. It cannot send mail.
internal sealed class EmailPilotAdmissionScope(QuillSignDbContext database, Guid envelopeId, string sender, Action ensureLive)
{
    private readonly Guid transactionId = database.Database.CurrentTransaction?.TransactionId
        ?? throw new InvalidOperationException("Pilot admission requires its owning transaction.");
    private bool consumed;
    internal void Demand(QuillSignDbContext db, Guid id, string address)
    {
        ensureLive();
        if (consumed || !ReferenceEquals(db,database) || id != envelopeId || address != sender ||
            db.Database.CurrentTransaction?.TransactionId != transactionId) throw EmailPilotProtection.Invalid();
        consumed = true;
    }
}
