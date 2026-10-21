using System.Security.Cryptography.Pkcs;
using System.Text.Json;
using QuillSign.Storage;

namespace QuillSign.Lifecycle;

internal sealed record CompletionInputReference(HoldWitnessCompletionContext Context, CompletionInputKind Kind, ProductionRecordWriteReceipt Receipt)
{
    internal ProductionRecordWriteDescriptor Item => Receipt.Item;
}

// Explicit closed references from the authenticated external completion journal.
// Normalized-prefix census/archive already retains every version/snapshot; this
// guard additionally authenticates the exact typed original inputs and receipts.
internal static class ProductionHoldCompletionInputReferences
{
    internal static CompletionInputReference[] References(Guid recordId, HoldWitnessState state)
    {
        var result = new List<CompletionInputReference>();
        if (state.Completions is null) return [];
        if (state.Completions.Count > 1) throw ProductionCompletionInputCodec.Invalid();
        foreach (var operation in state.Completions)
        {
            if (state.Operations is null || !state.Operations.TryGetValue(operation.Key, out var owner) || !ProductionCompletionProtocol.Sealing(owner.Kind)) throw ProductionCompletionInputCodec.Invalid();
            foreach (var slot in operation.Value.Slots?.Values ?? Enumerable.Empty<HoldWitnessCompletionSlot>())
            {
                ProductionCompletionProtocol.Context(slot.Context);
                foreach (var kind in Enum.GetValues<CompletionInputKind>())
                {
                    var effect = ProductionCompletionInputCodec.Effect(kind);
                    if (!slot.Started.ContainsKey(effect)) continue;
                    if (!slot.Receipts.TryGetValue(effect, out var receipt) || receipt.Stored is not { } stored || receipt.Final is not null) throw ProductionCompletionInputCodec.Invalid();
                    ProductionCompletionProtocol.Receipt(receipt);
                    ProductionCompletionInputCodec.DemandDescriptor(recordId, slot.Context, kind, stored.Item);
                    result.Add(new(slot.Context, kind, stored));
                }
            }
        }
        ProductionCompletionInputCodec.DemandAggregate(result.Select(x => x.Item.Length));
        if (result.Select(x => x.Item.Blob.ObjectId).Distinct().Count() != result.Count) throw ProductionCompletionInputCodec.Invalid();
        return result.ToArray();
    }
    internal static void DemandCensus(Guid recordId, IReadOnlyList<CompletionInputReference> references, IReadOnlyList<HoldObjectEvidence> objects)
    {
        ProductionCompletionInputCodec.DemandAggregate(references.Select(x => x.Item.Length));
        var prefix = $"{recordId:N}/completion-inputs/";
        var names = references.Select(x => prefix + x.Item.Blob.ObjectId.ToString("N")).ToHashSet(StringComparer.Ordinal);
        if (objects.Any(x => x.Address.Name.StartsWith(prefix, StringComparison.Ordinal) && (x.Address.Area != "normalized" || !names.Contains(x.Address.Name)))) throw ProductionCompletionInputCodec.Invalid();
        foreach (var reference in references)
        {
            var item = reference.Item; var receipt = reference.Receipt;
            ProductionCompletionInputCodec.DemandDescriptor(recordId, reference.Context, reference.Kind, item);
            if (!objects.Any(x => x.Address.Area == "normalized" && x.Address.Name == prefix + item.Blob.ObjectId.ToString("N") &&
                x.Address.VersionId == receipt.VersionId && string.IsNullOrEmpty(x.Address.Snapshot) && x.Address.ETag == receipt.ETag &&
                x.Address.Length == item.Length && x.Sha256 == item.Sha256)) throw ProductionCompletionInputCodec.Invalid();
        }
    }
    internal static void Demand(JsonElement sql, HoldWitnessState state, IReadOnlyList<HoldObjectEvidence> objects,
        IReadOnlyList<VerifiedCompletionInput> inputs, Microsoft.AspNetCore.DataProtection.IDataProtectionProvider keys)
    {
        var recordId = sql.GetProperty("RecordId").GetGuid(); var references = References(recordId, state); DemandCensus(recordId, references, objects);
        if (inputs.Count != references.Length || inputs.Select(x => x.Descriptor.Blob.ObjectId).Distinct().Count() != inputs.Count) throw ProductionCompletionInputCodec.Invalid();
        foreach (var reference in references)
        {
            var input = inputs.SingleOrDefault(x => x.Descriptor == reference.Item) ?? throw ProductionCompletionInputCodec.Invalid();
            if (input.RecordId != recordId || input.Kind != reference.Kind ||
                ProductionCompletionInputCodec.ContextSha256(input.Context) != ProductionCompletionInputCodec.ContextSha256(reference.Context)) throw ProductionCompletionInputCodec.Invalid();
            var body = input.Body;
            if (input.Kind is CompletionInputKind.CandidatePlan or CompletionInputKind.ExecutedResult or CompletionInputKind.CertificateResult or
                CompletionInputKind.PublicationIntentPlan or CompletionInputKind.PublicationResultPlan)
                _ = ProductionCompletionInputRows.Bind(input, keys, sql);
            if (body.TimestampRequest is { } request)
            {
                var original = inputs.SingleOrDefault(x => x.Context.OperationId == input.Context.OperationId && x.Context.Slot == input.Context.Slot &&
                    x.Kind == (input.Kind == CompletionInputKind.ExecutedTimestampRequest ? CompletionInputKind.ExecutedContext : CompletionInputKind.CertificateContext)) ?? throw ProductionCompletionInputCodec.Invalid();
                if (request.ContextPlainSha256 != original.PlainSha256 || request.StartedAt != original.Body.SealContext!.SigningAt) throw ProductionCompletionInputCodec.Invalid();
                var completion = state.Completions![input.Context.OperationId].Slots![input.Context.Slot];
                var effect = input.Context.Slot == CompletionSlot.ExecutedSeal ? CompletionEffect.ExecutedTsa : CompletionEffect.CertificateTsa;
                if (!completion.Started.TryGetValue(effect, out var started) || started.Sha256 != ProductionCompletionInputCodec.Hash(request.Encoded)) throw ProductionCompletionInputCodec.Invalid();
            }
            if (body.TimestampResponse is { } response)
            {
                var savedRequest = inputs.SingleOrDefault(x => x.PlainSha256 == response.RequestPlainSha256 && x.Context.OperationId == input.Context.OperationId &&
                    x.Kind == (input.Kind == CompletionInputKind.ExecutedTimestampResponse ? CompletionInputKind.ExecutedTimestampRequest : CompletionInputKind.CertificateTimestampRequest)) ?? throw ProductionCompletionInputCodec.Invalid();
                if (!Rfc3161TimestampRequest.TryDecode(savedRequest.Body.TimestampRequest!.Encoded, out var original, out var read) || read != savedRequest.Body.TimestampRequest.Encoded.Length) throw ProductionCompletionInputCodec.Invalid();
                var returned = original.ProcessResponse(response.EncodedResponse, out var consumed);
                if (consumed != response.EncodedResponse.Length || !returned.AsSignedCms().Encode().AsSpan().SequenceEqual(response.VerifiedToken)) throw ProductionCompletionInputCodec.Invalid();
            }
            if (body.SealResult is not null)
            {
                var original = inputs.SingleOrDefault(x => x.Context.OperationId == input.Context.OperationId && x.Context.Slot == input.Context.Slot &&
                    x.Kind == (input.Kind == CompletionInputKind.ExecutedResult ? CompletionInputKind.ExecutedContext : CompletionInputKind.CertificateContext)) ?? throw ProductionCompletionInputCodec.Invalid();
                if (JsonSerializer.Serialize(original.Body.SealContext) != JsonSerializer.Serialize(body.SealContext)) throw ProductionCompletionInputCodec.Invalid();
                var savedResponse = inputs.SingleOrDefault(x => x.Context.OperationId == input.Context.OperationId && x.Context.Slot == input.Context.Slot &&
                    x.Kind == (input.Kind == CompletionInputKind.ExecutedResult ? CompletionInputKind.ExecutedTimestampResponse : CompletionInputKind.CertificateTimestampResponse)) ?? throw ProductionCompletionInputCodec.Invalid();
                var metadata = JsonSerializer.Deserialize<CompletionSealMetadataInput>(body.SealResult.MetadataJson) ?? throw ProductionCompletionInputCodec.Invalid();
                if (metadata.TimestampAt != savedResponse.Body.TimestampResponse!.TimestampAt || metadata.TimestampCertificateSha256 != savedResponse.Body.TimestampResponse.CertificateSha256 ||
                    metadata.TimestampPolicy != savedResponse.Body.TimestampResponse.Policy) throw ProductionCompletionInputCodec.Invalid();
            }
        }
    }
}
