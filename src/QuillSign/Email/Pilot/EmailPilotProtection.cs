using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;

namespace QuillSign.Email.Pilot;

public sealed class EmailPilotProtection(IDataProtectionProvider keys)
{
    private static readonly JsonSerializerOptions Json = new() { MaxDepth = 8, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    public string Protect<T>(Guid runId, string purpose, T value) => keys.CreateProtector("QuillSign.EmailPilot.v1", runId.ToString("N"), purpose)
        .Protect(JsonSerializer.Serialize(value, Json));
    public T Read<T>(Guid runId, string purpose, string value, int maximum)
    {
        if (value is not { Length: > 0 } || value.Length > maximum) throw Invalid();
        try { return JsonSerializer.Deserialize<T>(keys.CreateProtector("QuillSign.EmailPilot.v1", runId.ToString("N"), purpose).Unprotect(value), Json) ?? throw Invalid(); }
        catch (Exception e) when (e is CryptographicException or JsonException or ArgumentException or FormatException) { throw Invalid(); }
    }
    internal static InvalidDataException Invalid() => new("Pilot authority or budget evidence could not be verified.");
}
