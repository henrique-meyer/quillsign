namespace QuillSign.Lifecycle;

internal enum ProductionRecordStage { Draft, Signing, Completing, Completed, Expired, Declined, Voided }
internal enum ProductionRetentionDisposition { AwaitingTerminalState, RequiresDisposition, Finite, Indefinite }
internal enum ProductionRetentionClock { Creation, Completion, Expiry, Decline, Void }

// Eligibility is only a policy clock. Holds, storage protection, evidence and destructive
// authority must still be checked by the separately implemented lifecycle services.
internal sealed record ProductionRetentionDecision(ProductionRetentionDisposition Disposition,
    ProductionRetentionClock? Clock, DateTimeOffset? StartedAt, DateTimeOffset? EligibleAt)
{
    internal static ProductionRetentionDecision Evaluate(ProductionRetentionSnapshot snapshot,
        ProductionRecordStage stage, DateTimeOffset now, DateTimeOffset? terminalAt = null)
    {
        ProductionRetentionPolicyContract.Validate(snapshot);
        if (!Enum.IsDefined(stage) || now.Offset != TimeSpan.Zero || now < snapshot.CreatedAt)
            throw Invalid();
        if (stage is ProductionRecordStage.Signing or ProductionRecordStage.Completing)
        {
            if (terminalAt is not null) throw Invalid();
            return new(stage == ProductionRecordStage.Signing ? ProductionRetentionDisposition.AwaitingTerminalState :
                ProductionRetentionDisposition.RequiresDisposition, null, null, null);
        }
        var anchor = snapshot.CreatedAt;
        if (stage == ProductionRecordStage.Draft)
        { if (terminalAt is not null) throw Invalid(); }
        else
        {
            if (terminalAt is not DateTimeOffset at || !ProductionRetentionPolicyContract.WholeUtc(at) ||
                at < snapshot.CreatedAt || at > now) throw Invalid();
            anchor = at;
        }
        var (clock, days) = stage switch
        {
            ProductionRecordStage.Draft => (ProductionRetentionClock.Creation, snapshot.Policy.AbandonedDraftDays),
            ProductionRecordStage.Completed => (ProductionRetentionClock.Completion, snapshot.Policy.CompletedDays),
            ProductionRecordStage.Expired => (ProductionRetentionClock.Expiry, snapshot.Policy.ExpiredDays),
            ProductionRecordStage.Declined => (ProductionRetentionClock.Decline, snapshot.Policy.DeclinedDays),
            ProductionRecordStage.Voided => (ProductionRetentionClock.Void, snapshot.Policy.VoidedDays),
            _ => throw Invalid()
        };
        return days == 0 ? new(ProductionRetentionDisposition.Indefinite, clock, anchor, null) :
            new(ProductionRetentionDisposition.Finite, clock, anchor, ProductionRetentionPolicyContract.AddDays(anchor, days));
    }

    private static InvalidDataException Invalid() => new("The production lifecycle state or its retention clock could not be verified.");
}
