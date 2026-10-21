using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Signing;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

// Connected private backend, deliberately unregistered until trusted operator
// middleware supplies its configuration/authority. Raw provider DTOs never
// establish complete preservation or authorize release/deletion.
internal sealed partial class ProductionHoldCoordinator(Func<QuillSignDbContext> open, IDataProtectionProvider keys,
    TimeProvider time, ProductionHoldWitnessJournal witness, IProductionHoldObjectSource objects,
    AzureProductionHoldArchiveWriter archive, AzureProductionHoldArchiveReleaseStore releases,
    IProductionReviewInputSource? reviewInputs=null, IProductionCompletionInputSource? completionInputs=null) : IProductionHoldReleaseFence
{
    private static readonly JsonSerializerOptions PreviewRows=new(){Converters={new JsonStringEnumConverter()}};
    internal async Task<HoldWitnessState> SubmitAsync(ProductionOperatorAuthority authority, ProductionOperatorPolicy operators,
        ProductionHoldCommand command, CancellationToken ct = default)
    {
        var before = await witness.ReadAsync(command.RecordId, ct);
        if (before.Unacknowledged is null && before.OutstandingOperation is null) before = await ReadVerifiedAsync(command.RecordId, ct);
        else if (before.Unacknowledged is not null && before.Unacknowledged != command) throw Invalid();
        // Publish before SQL: failed/unknown commits leave a durable closed gate.
        // A replay recovers the existing command rather than reusing its budget
        // or assuming a missing acknowledgement means the commit rolled back.
        var state = await witness.IntentAsync(authority, operators, command, Id(command.CommandId, "intent"), ct);
        // An admitted business operation must settle provider dispatch, its SQL
        // commit AND worker Finish before we acquire the preservation cut. The
        // external intent already blocks later admissions; do not deadlock the
        // drain by holding its SQL parent lock or invent settlement from expiry.
        if (state.OutstandingOperation is not null) return state;
        if (state.Unacknowledged is null) return await ReadVerifiedAsync(command.RecordId, ct);
        await using var db = open(); await using var tx = await db.Database.BeginTransactionAsync(ct);
        var receipt = await new ProductionHoldRequests(db, keys, time).PrepareLockedAsync(authority, operators, command, ct);
        var sql = await Sql(db, receipt.Current, command.RecordId, ct);
        var content = ContentDigest(sql);
        if (before.OutstandingOperation is null && before.BusinessStateSha256 is not null && before.BusinessStateSha256 != content) throw Invalid();
        authority.Demand(operators, command.Permission, time);
        await tx.CommitAsync(ct);
        return await witness.AcceptSqlAsync(command, receipt, content, Id(command.CommandId, "sql"), ct, sql.StateSha256);
    }

    internal async Task<HoldWitnessState> ReadVerifiedAsync(Guid recordId, CancellationToken ct = default)
    {
        var state = await witness.ReadAsync(recordId, ct);
        await using var db = open(); await using var tx = await db.Database.BeginTransactionAsync(ct);
        await Verify(db, recordId, state, ct);
        await tx.RollbackAsync(ct);
        var after = await witness.ReadAsync(recordId, ct);
        if (after.HeadHash != state.HeadHash) throw Invalid();
        return after;
    }

    internal async Task<HoldWitnessState> PreserveAsync(Guid recordId, Guid holdId, Guid planId, CancellationToken ct = default)
    {
        var state = await ReadVerifiedAsync(recordId, ct);
        if (!state.Holds.TryGetValue(holdId, out var hold) || hold.Release is not null) throw Invalid();
        if (hold.Effective) return state;
        if (hold.PlanId is not null && hold.PlanId != planId) throw Invalid();
        var work = Id(hold.Placement.CommandId, "preserve-operation");
        state = await witness.ReservePreservationAsync(hold.Placement, planId, work, Id(work, "reserve"), ct);
        ProductionHoldProtectedPlan plan;
        ProductionHoldControlPrefix frozenPrefix;
        await using (var db = open())
        {
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            var requests = await Verify(db, recordId, state, ct);
            var controls = new ProductionHoldControls(db, keys, time);
            var saved = await controls.ReadLockedAsync(recordId, ct);
            if (saved.Plans.TryGetValue(planId, out var prior))
            { if (prior.HoldId != holdId) throw Invalid(); plan = prior; }
            else
            {
                var snapshot = await new ProductionHoldObjectInventory(db, keys, time, objects)
                    .CaptureLockedAsync(recordId, requests.Revision, requests.FenceHash!, ct: ct);
                await DemandCompleteSchemas(db,snapshot,state,ct);
                plan = await ProductionHoldBundlePlan.FreezeLockedAsync(db, keys, time, holdId, planId, snapshot, ct);
                plan = await controls.SavePlanLockedAsync(plan, ct);
            }
            await DemandCompleteSchemas(db,ProductionHoldBundlePlan.OpenVerified(plan, keys, time).Snapshot,state,ct);
            frozenPrefix = hold.PlanSha256 is not null ? hold.Control! : (await controls.ReadLockedAsync(recordId, ct)).Prefix;
            await tx.CommitAsync(ct);
        }
        await witness.FreezePlanAsync(hold.Placement, planId, plan.Sha256, frozenPrefix, work, Id(work, "plan"), ct);
        var body = ProductionHoldBundlePlan.OpenVerified(plan, keys, time);
        foreach (var item in body.Items)
        {
            await DemandPreservation(recordId, hold.Placement, work, ct);
            await using var db = open(); await using var tx = await db.Database.BeginTransactionAsync(ct);
            await Verify(db, recordId, await witness.ReadAsync(recordId, ct), ct);
            await new ProductionHoldControls(db, keys, time).PreserveItemLockedAsync(recordId, planId, item.Path,
                Id(planId, item.Path), archive, ct);
            await DemandPreservation(recordId, hold.Placement, work, ct);
            await tx.CommitAsync(ct);
        }
        // Every item has just undergone exact provider bytes/protection readback.
        // Authenticate the complete saved set and control prefix, not just a PDF.
        await using (var db = open())
        {
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            await Verify(db, recordId, await witness.ReadAsync(recordId, ct), ct);
            var controls = await new ProductionHoldControls(db, keys, time).ReadLockedAsync(recordId, ct);
            var digest = BundleDigest(plan, body, controls);
            await DemandPreservation(recordId, hold.Placement, work, ct);
            var result = await witness.PreserveAsync(hold.Placement, planId, plan.Sha256, digest, controls.Prefix,
                work, Id(work, "complete"), ct);
            await tx.RollbackAsync(ct); return result;
        }
    }

    internal async Task<HoldWitnessState> ReleaseAsync(Guid recordId, Guid holdId, CancellationToken ct = default)
    {
        var state = await ReadVerifiedAsync(recordId, ct);
        if (!state.Holds.TryGetValue(holdId, out var hold) || hold.Release is not { } release || !hold.Effective) throw Invalid();
        if (hold.Released) return state;
        var work = Id(release.CommandId, "release-operation");
        await witness.ReserveReleaseAsync(release, work, Id(work, "reserve"), ct);
        // Every plan for this hold must be complete; no missing receipt or a
        // temporarily absent blob is accepted as proof of a cancelled write.
        await using var db = open(); await using var tx = await db.Database.BeginTransactionAsync(ct);
        await Verify(db, recordId, await witness.ReadAsync(recordId, ct), ct);
        var controls = await new ProductionHoldControls(db, keys, time).ReadLockedAsync(recordId, ct);
        var owned = controls.Plans.Values.Where(x => x.HoldId == holdId).OrderBy(x => x.PlanId).ToArray();
        if (owned.Length == 0) throw Invalid();
        var receipts = new List<ProductionHoldArchiveStoredObject>();
        foreach (var plan in owned)
        {
            var body = ProductionHoldBundlePlan.OpenVerified(plan, keys, time); _ = BundleDigest(plan, body, controls);
            foreach (var item in body.Items)
            {
                var scope = await ProductionHoldArchiveReleaseCapability.AuthorizeLockedAsync(db, keys, time, this,
                    holdId, release.CommandId, plan.PlanId, item.Path, ct);
                receipts.Add(await releases.ReleaseAsync(scope, ct));
            }
        }
        await DemandReleaseAsync(recordId, holdId, release.CommandId, state.RequestRevision, state.RequestFenceHash!, ct);
        var releaseHash = Digest(new { Version = "production-hold-release-receipt-v1", recordId, holdId,
            release.CommandId, RequestRevision = release.ExpectedRevision + 1, RequestFenceHash = hold.ReleaseFenceHash, controls.Prefix,
            Objects = receipts.OrderBy(x => x.Path, StringComparer.Ordinal).ToArray() });
        var result = await witness.ReleaseAsync(release, releaseHash, controls.Prefix, work, Id(work, "complete"), ct);
        await tx.RollbackAsync(ct); return result;
    }

    public async Task DemandReleaseAsync(Guid recordId, Guid holdId, Guid releaseCommandId, long requestRevision,
        string requestFenceHash, CancellationToken ct = default)
    {
        var state = await witness.ReadAsync(recordId, ct);
        if (state.Unacknowledged is not null || state.RequestRevision != requestRevision || state.RequestFenceHash != requestFenceHash ||
            !state.Holds.TryGetValue(holdId, out var hold) || !hold.Effective || hold.Released || hold.Release?.CommandId != releaseCommandId ||
            state.OutstandingOperation != Id(releaseCommandId, "release-operation")) throw Invalid();
    }

    private async Task DemandPreservation(Guid id, ProductionHoldCommand placement, Guid operation, CancellationToken ct)
    {
        var state = await witness.ReadAsync(id, ct);
        if (state.Unacknowledged is not null || state.OutstandingOperation != operation ||
            !state.Holds.TryGetValue(placement.HoldId, out var hold) || hold.Placement != placement || hold.Release is not null || hold.Effective) throw Invalid();
    }

    private async Task<ProductionHoldRequestSnapshot> Verify(QuillSignDbContext db, Guid id, HoldWitnessState state, CancellationToken ct)
    {
        var requests = await new ProductionHoldRequests(db, keys, time).ReadLockedAsync(id, ct);
        ProductionHoldWitnessJournal.DemandSql(state, requests);
        if (requests.Revision == 0)
        {
            if (!state.Initialized) { if (state.Sequence != 0) throw Invalid(); return requests; }
            var acknowledged = await new ProductionHoldSqlInventory(db, keys, time)
                .CaptureAcknowledgementLockedAsync(id, requests.Revision, requests.FenceHash, ct: ct);
            if (ContentDigest(acknowledged) != state.BusinessStateSha256 || acknowledged.StateSha256 != state.SqlStateSha256) throw Invalid();
            return requests;
        }
        var sql = await Sql(db, requests, id, ct);
        if (ContentDigest(sql) != state.BusinessStateSha256 || state.SqlStateSha256 is not null && sql.StateSha256 != state.SqlStateSha256) throw Invalid();
        var controls = new ProductionHoldControls(db, keys, time);
        var saved = await controls.ReadLockedAsync(id, ct);
        foreach (var hold in state.Holds.Values.Where(x => x.PlanSha256 is not null))
        {
            if (hold.PlanId is not { } planId || hold.PlanSha256 is null || hold.Control is null ||
                !saved.Plans.TryGetValue(planId, out var plan) || plan.HoldId != hold.Placement.HoldId || plan.Sha256 != hold.PlanSha256) throw Invalid();
            await controls.DemandExtendsLockedAsync(id, hold.Control, ct);
            if (!hold.Effective) continue;
            // Check the original complete item set even after later controls were
            // appended for an independent hold. A restored shorter journal fails.
            var body = ProductionHoldBundlePlan.OpenVerified(plan, keys, time);
            if (BundleDigest(plan, body, saved) != hold.PreservationSha256) throw Invalid();
            if (hold.Released)
            {
                var released = saved.Plans.Values.Where(x => x.HoldId == hold.Placement.HoldId).OrderBy(x => x.PlanId)
                    .SelectMany(x => saved.Items.Where(i => i.PlanId == x.PlanId).OrderBy(i => i.Stored.Path, StringComparer.Ordinal))
                    .Select(x => x.Stored).OrderBy(x => x.Path, StringComparer.Ordinal).ToArray();
                var release = hold.Release ?? throw Invalid();
                if (hold.ReleaseSha256 != Digest(new { Version = "production-hold-release-receipt-v1", recordId = id, holdId = hold.Placement.HoldId,
                    release.CommandId, RequestRevision = release.ExpectedRevision + 1, RequestFenceHash = hold.ReleaseFenceHash,
                    Prefix = hold.Control, Objects = released })) throw Invalid();
            }
        }
        return requests;
    }

    private Task<ProductionHoldSqlSnapshot> Sql(QuillSignDbContext db, ProductionHoldRequestSnapshot requests, Guid id, CancellationToken ct)
        => new ProductionHoldSqlInventory(db, keys, time).CaptureLockedAsync(id, requests.Revision, requests.FenceHash!, ct: ct);

    private string ContentDigest(ProductionHoldSqlSnapshot snapshot)
        => ProductionRecordOperationAdmission.ContentDigest(snapshot, keys);

    private static string BundleDigest(ProductionHoldProtectedPlan plan, ProductionHoldFrozenPlan body, ProductionHoldControlState controls)
    {
        var receipts = controls.Items.Where(x => x.PlanId == plan.PlanId).OrderBy(x => x.Stored.Path, StringComparer.Ordinal).ToArray();
        var items = body.Items.OrderBy(x => x.Path, StringComparer.Ordinal).ToArray();
        if (receipts.Length != items.Length || receipts.Where((x, i) => x.PlanSha256 != plan.Sha256 ||
            x.Stored.Path != items[i].Path || x.Stored.Length != items[i].Length || x.Stored.Sha256 != items[i].Sha256).Any()) throw Invalid();
        return Digest(new { Version = "production-hold-complete-bundle-v1", plan.RecordId, plan.HoldId, plan.PlanId, plan.Sha256,
            body.Snapshot.SqlStateSha256, body.Snapshot.ManifestSha256, Items = receipts });
    }

    private async Task DemandCompleteSchemas(QuillSignDbContext db,ProductionHoldObjectSnapshot snapshot,HoldWitnessState state,CancellationToken ct)
    {
        // Per-schema readers run during capture/replay; this final closed graph
        // also binds the runtime plans, exact worker outcomes and owned tails.
        // Unknown or partial history remains pending.
        using var sql = ProductionHoldSqlInventory.OpenVerified(snapshot.Sql, keys);
        ProductionHoldAdmissionAuditReferences.Demand(sql.RootElement);
        var tables = sql.RootElement.GetProperty("Tables").EnumerateArray().ToDictionary(x => x.GetProperty("Table").GetString()!, x => x.GetProperty("Rows"));
        var status = tables["Envelopes"].EnumerateArray().Single().GetProperty("Status").GetString();
        var terminal=status is "Voided" or "Declined" or "Expired";
        HoldInvitationHistory? invitationHistory=null;
        if (status is "Sent" or "Completed"||terminal)
        {
            var inventory=ProductionHoldObjectInventory.OpenVerified(snapshot,keys,time);
            // Keep the already verified simple signing/publication path intact.
            // Advanced lineage is admitted only through the complete typed
            // historical reader, never by a broad event-name exemption.
            if(NeedsInvitationHistory(tables))invitationHistory=await ProductionHoldInvitationHistoryReferences.ReadVerifiedLockedAsync(
                db,sql.RootElement,inventory,keys,state,time,ct);
            var inputs=await ReadReviewInputs(db,snapshot.RecordId,tables["SignerReviewCandidates"],state,inventory,ct);
            var history=terminal
                ?await ProductionHoldTerminalReferences.ReadVerifiedLockedAsync(db,sql.RootElement,inventory,keys,inputs,state,time,ct,invitationHistory)
                :status=="Completed"
                ?ProductionHoldCompletionStageReferences.ReadVerified(sql.RootElement,inventory,keys,inputs,
                    await ReadCompletionInputs(db,snapshot.RecordId,state,inventory,ct),state,invitationHistory)
                :ProductionHoldReviewCheckpointReferences.ReadVerified(sql.RootElement,inventory,keys,inputs,invitationHistory);
            DemandPreviewPlans(tables["SignaturePreviews"],history.Previews,state,inventory);
        }
        else if (status != "Draft"||(state.ReviewWrites?.Count??0)!=0) throw Invalid();
        var invitationAudits=invitationHistory?.AuditSequences;
        foreach (var audit in tables["AuditEvents"].EnumerateArray())
        {
            if(invitationAudits?.Contains(audit.GetProperty("Sequence").GetInt64())==true)continue;
            if ((status is "Sent" or "Completed"||terminal) && audit.GetProperty("Event").GetString() is "fields_finalized" or "sent" or "invitation_submitted" or "link_opened" or "consent_given" or
                "signature_adopted" or "field_filled" or "field_cleared" or "signer_review_prepared" or "signer_finish_accepted" or "signer_completed") continue;
            if (status=="Completed"&&audit.GetProperty("Event").GetString() is "completion_prepared" or "completion_executed_sealed" or "completion_certificate_sealed" or
                "completion_publication_prepared" or "completed" or ProductionRetentionLedger.TerminalEvent or "completion_notification_queued" or
                "completion_access_issued" or "completion_notification_attempt" or "completion_notification_submitted" or
                "completion_access_redeemed" or "completion_lookup_opened" or "final_download_prepared") continue;
            if(terminal&&audit.GetProperty("Event").GetString() is "voided" or "declined" or "expired" or ProductionRetentionLedger.TerminalEvent or
                "void_notification_queued" or "void_notification_attempt" or "void_notification_submitted")continue;
            if (audit.GetProperty("Event").GetString() is not (ProductionRetentionLedger.EnrollmentEvent or
                "draft_created" or "sender_verification_requested" or "sender_email_verified" or
                "document_uploaded" or "document_replaced" or "preview_confirmed" or "signer_added" or "signer_updated" or "signer_removed" or
                "signers_reordered" or "recipient_added" or "recipient_updated" or "recipient_removed" or "envelope_details_updated" or "fields_saved")) throw Invalid();
        }
    }

    private static bool NeedsInvitationHistory(IReadOnlyDictionary<string,JsonElement> tables)
    {
        if(tables["SignerContactRevisions"].GetArrayLength()!=0||tables["EmailOutbox"].EnumerateArray().Any(x=>
            x.GetProperty("Template").GetString() is InvitationResendProtection.Template or InvitationSuccessorProtection.Template))return true;
        foreach(var audit in tables["AuditEvents"].EnumerateArray())
        {
            var name=audit.GetProperty("Event").GetString();
            if(name is SignerContactHistory.Event or InvitationResendProtection.Event or InvitationSuccessorProtection.Event or
                SignerReminderEvidence.ScheduleEvent or SignerReminderEvidence.AdmissionEvent)return true;
            if(name!="sent")continue;
            using var sent=JsonDocument.Parse(audit.GetProperty("DataJson").GetString()!);
            var p=sent.RootElement;
            if(p.TryGetProperty("reminderPolicy",out var policy)&&p.TryGetProperty("reminderPolicySha256",out var hash)&&
                !SignerReminderPolicy.Read(policy.GetString()!,hash.GetString()!).Days.IsEmpty)return true;
        }
        return false;
    }

    private async Task<IReadOnlyList<VerifiedCompletionInput>> ReadCompletionInputs(QuillSignDbContext db,Guid recordId,
        HoldWitnessState state,IReadOnlyList<HoldObjectEvidence> inventory,CancellationToken ct)
    {
        _=ProductionHoldCompletionStageReferences.DemandSettled(recordId,state);
        var references=ProductionHoldCompletionInputReferences.References(recordId,state);
        ProductionCompletionInputCodec.DemandAggregate(references.Select(x=>x.Item.Length));
        ProductionHoldCompletionInputReferences.DemandCensus(recordId,references,inventory);
        if(references.Length!=Enum.GetValues<CompletionInputKind>().Length)throw Invalid();
        var source=completionInputs??objects as IProductionCompletionInputSource??throw Invalid();
        // Reopened plans keep their ORIGINAL bytes and clocks but need a fresh
        // CURRENT same-parent hold scope; never resurrect the worker's lease.
        var current=await new ProductionHoldSqlInventory(db,keys,time).CaptureLockedAsync(recordId,state.RequestRevision,state.RequestFenceHash!,ct:ct);
        var scope=ProductionHoldObjectScope.FromVerified(current,keys,time);
        var result=new List<VerifiedCompletionInput>();
        foreach(var reference in references)
        {
            var evidence=inventory.Single(x=>x.Address.Area=="normalized"&&x.Address.Name==$"{recordId:N}/completion-inputs/{reference.Item.Blob.ObjectId:N}"&&
                x.Address.VersionId==reference.Receipt.VersionId&&x.Address.Snapshot.Length==0&&x.Address.ETag==reference.Receipt.ETag&&
                x.Address.Length==reference.Item.Length&&x.Sha256==reference.Item.Sha256);
            var read=ProductionCompletionInputReadScope.FromHold(scope,reference.Context,reference.Kind,reference.Item,reference.Receipt,evidence);
            try
            {
                var bytes=await source.ReadAsync(read,ct);read.Demand(ct);
                result.Add(ProductionCompletionInputCodec.OpenVerified(keys,recordId,reference.Context,reference.Kind,reference.Item,bytes));
            }
            finally {read.Close();}
        }
        return result;
    }

    // The old frozen capture is evidence, not a fresh IO capability. Reopened
    // plans get a new bounded read scope from CURRENT authenticated hold SQL
    // under this same parent lock; original sidecar bytes and clocks stay fixed.
    private async Task<IReadOnlyList<VerifiedReviewInput>> ReadReviewInputs(QuillSignDbContext db,Guid recordId,JsonElement rows,
        HoldWitnessState state,IReadOnlyList<HoldObjectEvidence> inventory,CancellationToken ct)
    {
        var plans=state.ReviewWrites;
        if(rows.GetArrayLength()>4096||rows.GetArrayLength()!=(plans?.Count??0)||rows.EnumerateArray().GroupBy(x=>x.GetProperty("SignerId").GetGuid()).Any(x=>x.Count()>SignerReviewCandidates.MaximumCandidatesPerSigner))throw Invalid();
        DemandReviewInputBudget(plans?.Values.Select(x=>x.Plan.Input.Length)??Enumerable.Empty<long>());
        if(rows.GetArrayLength()==0)return [];
        var source=reviewInputs??objects as IProductionReviewInputSource??throw Invalid();
        var current=await new ProductionHoldSqlInventory(db,keys,time).CaptureLockedAsync(recordId,state.RequestRevision,state.RequestFenceHash!,ct:ct);
        var scope=ProductionHoldObjectScope.FromVerified(current,keys,time);
        var result=new List<VerifiedReviewInput>();
        foreach(var raw in rows.EnumerateArray())
        {
            var candidateId=raw.GetProperty("Id").GetGuid();
            var matches=plans!.Where(x=>ProductionRecordReviewWriteContract.ReadRow(x.Value.Plan.CandidateRowJson).Id==candidateId).ToArray();
            if(matches.Length!=1)throw Invalid();
            var (operationId,writes)=matches.Single();var plan=writes.Plan;
            ProductionRecordReviewWriteContract.Validate(plan);
            if(operationId!=plan.OperationId||plan.Identity.EnvelopeId!=recordId||
                !ProductionRecordReviewWriteContract.Complete(writes)||!state.SettledOperations.ContainsKey(operationId)||
                state.Outcomes?.ContainsKey(operationId)!=true||state.Operations?.GetValueOrDefault(operationId) is not {} operation||
                operation.Kind!=ProductionRecordReviewWriteContract.Kind||operation.Reference!=candidateId.ToString("N"))throw Invalid();
            foreach(var receipt in writes.Receipts.Values)
            {
                var item=receipt.Item;var name=item.Blob.Kind==DocumentBlobKind.ReviewInput
                    ?$"{recordId:N}/review-inputs/{item.Blob.ObjectId:N}":$"{recordId:N}/{item.Blob.ObjectId:N}";
                if(!inventory.Any(x=>x.Address.Area=="normalized"&&x.Address.Name==name&&x.Address.VersionId==receipt.VersionId&&
                    x.Address.Snapshot.Length==0&&x.Address.ETag==receipt.ETag&&x.Address.Length==item.Length&&x.Sha256==item.Sha256))throw Invalid();
            }
            var inputReceipt=writes.Receipts[plan.Input.Blob];
            var input=inventory.Single(x=>x.Address.Area=="normalized"&&x.Address.Name==$"{recordId:N}/review-inputs/{plan.Input.Blob.ObjectId:N}"&&
                x.Address.VersionId==inputReceipt.VersionId&&x.Address.Snapshot.Length==0&&x.Address.ETag==inputReceipt.ETag&&
                x.Address.Length==plan.Input.Length&&x.Sha256==plan.Input.Sha256);
            var read=ProductionReviewInputReadScope.FromHold(scope,plan,inputReceipt,input);
            var bytes=await source.ReadAsync(read,ct);read.Demand(ct);
            result.Add(ProductionReviewInputCodec.OpenVerified(keys,plan,bytes));
        }
        return result;
    }

    // Preserve the ORIGINAL record-wide worst-case owned ciphertext budget,
    // while allowing many smaller per-party candidates. Metadata is checked
    // before resolving a sidecar reader, provider IO or sidecar decryption.
    internal static void DemandReviewInputBudget(IEnumerable<long> lengths)
    {
        var maximum=(long)SignerReviewCandidates.MaximumCandidatesPerSigner*ProductionReviewInputCodec.MaximumCipherBytes;
        long total=0;
        foreach(var length in lengths)
        {
            if(length<1||length>ProductionReviewInputCodec.MaximumCipherBytes||length>maximum-total)throw Invalid();
            total=checked(total+length);
        }
    }

    // Historical SQL and hashes alone cannot attest to normalized mark output.
    // Bind every saved preview to its complete externally retained original pair,
    // committed outcome and exact inventoried provider versions. UsedAt may only
    // advance through the separately verified adoption history above.
    private static void DemandPreviewPlans(JsonElement rows,IReadOnlyList<HoldVerifiedSignaturePreview> verified,
        HoldWitnessState state,IReadOnlyList<HoldObjectEvidence> inventory)
    {
        var plans=state.PreviewWrites;
        if(rows.GetArrayLength()!=verified.Count||(plans?.Count??0)!=verified.Count)throw Invalid();
        foreach(var raw in rows.EnumerateArray())
        {
            var row=raw.Deserialize<SignaturePreview>(PreviewRows)??throw Invalid();
            if(!verified.Any(x=>x.Id==row.Id))throw Invalid();
            var matches=plans!.Where(x=>ProductionRecordPreviewWriteContract.ReadRow(x.Value.Plan.PreviewRowJson).Id==row.Id).ToArray();
            if(matches.Length!=1)throw Invalid();
            var (operationId,writes)=matches.Single();var plan=writes.Plan;
            ProductionRecordPreviewWriteContract.Validate(plan);
            if(!ProductionRecordPreviewWriteContract.Complete(writes)||!state.SettledOperations.ContainsKey(operationId)||
                state.Outcomes?.ContainsKey(operationId)!=true||state.Operations?.GetValueOrDefault(operationId) is not { } operation||
                operation.Kind!=ProductionRecordPreviewWriteContract.Kind||operation.Reference!=row.Id.ToString("N")||
                plan.Identity.EnvelopeId!=row.EnvelopeId||plan.Identity.SignerId!=row.SignerId)throw Invalid();
            row.UsedAt=null;
            if(ProductionRecordPreviewWriteContract.Row(row)!=plan.PreviewRowJson)throw Invalid();
            foreach(var receipt in writes.Receipts.Values)
            {
                var item=receipt.Item;
                if(!inventory.Any(x=>x.Address.Area=="normalized"&&x.Address.Name==$"{item.Blob.EnvelopeId:N}/{item.Blob.ObjectId:N}"&&
                    x.Address.VersionId==receipt.VersionId&&x.Address.Snapshot.Length==0&&x.Address.ETag==receipt.ETag&&
                    x.Address.Length==item.Length&&x.Sha256==item.Sha256))throw Invalid();
            }
        }
    }

    internal static Guid Id(Guid owner, string phase)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes($"production-hold-coordinator-v1/{owner:N}/{phase}"));
        return new Guid(hash.AsSpan(0, 16));
    }
    private static string Digest<T>(T value) => ProductionHoldWitnessJournal.Digest(JsonSerializer.SerializeToUtf8Bytes(value));
    private static InvalidDataException Invalid() => new("The production hold lifecycle requires reconciliation.");
}
