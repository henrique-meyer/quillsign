using System.Security.Cryptography;
using System.Text.Json;
using QuillSign.Data;

namespace QuillSign.Completion;

// Internal read context, never a user/session capability. Publication verifies the immutable
// rows and canonical completion proof before creating it. Only the exact owned transition
// can project back to the frozen all-signed source; unrelated mutations remain conflicts.
internal sealed class PublishedCompletionSource(string beforeJson,byte[] afterHash,long auditSequence)
{
    internal long AuditSequence {get;}=auditSequence;
    internal Envelope Project(Envelope current)
    {
        if(current.Status!=EnvelopeStatus.Completed || !CompletionEvidenceValidation.Same(Digest(current),afterHash))
            throw new InvalidDataException("The completed source transition could not be verified.");
        return JsonSerializer.Deserialize<Envelope>(beforeJson) ?? throw new InvalidDataException("Missing frozen completion source.");
    }
    internal static byte[] Digest(Envelope value)=>SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value));
}
