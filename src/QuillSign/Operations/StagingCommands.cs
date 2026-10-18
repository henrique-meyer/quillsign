using System.Security.Cryptography;
using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using PdfSharp.Pdf;
using PdfSharp.Pdf.IO;
using QuillSign.Sealing;
using QuillSign.Storage;

namespace QuillSign.Operations;

// Explicit operator invocation only. No SQL, email, public route or scheduled producer.
public static class StagingCommands
{
    public static async Task<int> RunAsync(string[] args)
    {
        var cleanup = args.Length == 4 && args[0] == "cleanup" && Guid.TryParseExact(args[1], "N", out _) &&
            Guid.TryParseExact(args[2], "N", out _) && args[3].Length == 64 && args[3].All(char.IsAsciiHexDigit);
        if (!cleanup && (args.Length != 1 || args[0] is not ("storage" or "seal")))
        { Console.Error.WriteLine("Usage: staging storage|seal OR staging cleanup <envelope-N> <object-N> <expected-SHA256>"); return 2; }
        try
        {
            var builder = WebApplication.CreateBuilder();
            builder.Logging.ClearProviders();
            DemandConfiguration(builder.Configuration);
            builder.Services.AddSingleton(TimeProvider.System);
            builder.Services.AddQuillSignStorage(builder.Configuration, builder.Environment);
            builder.Services.AddPlatformPdfSeals(builder.Configuration);
            using var app = builder.Build();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(180));
            if (cleanup) await CleanupSyntheticAsync(app.Services, Guid.ParseExact(args[1], "N"), Guid.ParseExact(args[2], "N"), Convert.FromHexString(args[3]), timeout.Token);
            else if (args[0] == "storage") await VerifyStorageAsync(app.Services, timeout.Token);
            else await VerifySealsAsync(app.Services, timeout.Token);
            Console.WriteLine($"{{\"operation\":\"staging-{args[0]}\",\"status\":\"ok\"}}");
            return 0;
        }
        catch (Exception error)
        {
            // Deliberately omit endpoint, object ID, certificate, body and token data.
            var details = new List<string>();
            for (Exception? current = error; current is not null; current = current.InnerException)
                details.Add(current is RequestFailedException azure ? $"{current.GetType().Name}:{azure.Status}:{azure.ErrorCode}" : current.GetType().Name);
            Console.Error.WriteLine($"Staging check failed ({string.Join(" -> ", details)}).");
            return 1;
        }
    }

    public static void DemandConfiguration(IConfiguration configuration)
    {
        if (configuration["Storage:Provider"] != "Azure" || configuration["ElectronicRecords:Profile"] != "synthetic-demo-v1" ||
            configuration.GetValue<bool?>("Email:Enabled") != false || configuration.GetValue<bool>("Completion:AllowDevelopmentWriteOnce"))
            throw new InvalidOperationException("Staging checks require Azure, synthetic demo mode and disabled email/development publication.");
    }

    private static byte[] SyntheticPdf()
    {
        // A new blank, explicitly titled non-agreement: no user input or document data.
        using var document = new PdfDocument();
        document.Info.Title = "SYNTHETIC STORAGE AND SEAL CHECK - NO AGREEMENT";
        document.AddPage();
        using var output = new MemoryStream();
        document.Save(output, false);
        return output.ToArray();
    }

    private static async Task VerifyStorageAsync(IServiceProvider services, CancellationToken ct)
    {
        var time = services.GetRequiredService<TimeProvider>();
        var target = new FinalDocument(Guid.NewGuid(), FinalDocumentKind.Executed, Guid.NewGuid());
        var source = SyntheticPdf(); var hash = SHA256.HashData(source);
        var until = DateTimeOffset.FromUnixTimeSeconds(time.GetUtcNow().AddSeconds(65).ToUnixTimeSeconds());
        var store = services.GetRequiredService<ICompletionFinalStore>();
        var capability = CompletionFinalCapability.WriteFixed(target, source.LongLength, hash, until, false, time);
        var stored = await store.WriteAsync(capability, target, new MemoryStream(source, false), source.LongLength, hash, until, ct);
        if (stored.Protection != FinalProtection.LockedTime || stored.ProtectedUntil != until || string.IsNullOrEmpty(stored.VersionId))
            throw new InvalidDataException("Exact version protection was not confirmed.");
        using var downloaded = new MemoryStream();
        await store.ReadAsync(CompletionFinalCapability.ReadFixed(stored, until, time), stored, downloaded, ct);
        if (!downloaded.ToArray().AsSpan().SequenceEqual(source)) throw new InvalidDataException("Readback differs.");
        var root = services.GetRequiredService<BlobServiceClient>().GetBlobContainerClient("final")
            .GetBlobClient($"{target.EnvelopeId:N}/executed/{target.ObjectId:N}");
        var version = root.WithVersion(stored.VersionId);
        var condition = new BlobRequestConditions { IfMatch = new ETag(stored.ETag) };
        // A new current version does not modify the exact retained original. Use
        // an unlocked, exact short policy to exercise production lock recovery.
        var next = (await root.UploadAsync(new BinaryData(source), new BlobUploadOptions {
            Conditions = condition, HttpHeaders = new() { ContentType = "application/pdf" },
            ImmutabilityPolicy = new() { ExpiresOn = until, PolicyMode = BlobImmutabilityPolicyMode.Unlocked }
        }, ct)).Value;
        if (string.IsNullOrEmpty(next.VersionId) || next.VersionId == stored.VersionId) throw new InvalidDataException("Synthetic version was not created.");
        try
        {
            _ = await store.WriteAsync(CompletionFinalCapability.WriteFixed(target, source.LongLength, hash, until, false, time),
                target, new MemoryStream(source, false), source.LongLength, hash, until, ct);
            using var unchanged = new MemoryStream();
            await store.ReadAsync(CompletionFinalCapability.ReadFixed(stored, until, time), stored, unchanged, ct);
            if (!unchanged.ToArray().AsSpan().SequenceEqual(source)) throw new InvalidDataException("Retained version changed.");
            await DemandProtectedAsync(() => version.DeleteAsync(conditions: condition, cancellationToken: ct));
        }
        finally
        {
            var delay = until.AddSeconds(3) - time.GetUtcNow();
            if (delay > TimeSpan.Zero) await Task.Delay(delay, ct);
            // Only the two generated versions; never weaken policies or enumerate/delete a container.
            var current = (await root.GetPropertiesAsync(cancellationToken: ct)).Value;
            if (current.VersionId != next.VersionId || current.HasLegalHold || current.ImmutabilityPolicy?.ExpiresOn > time.GetUtcNow())
                throw new InvalidDataException("Synthetic root version changed or remains protected.");
            var currentCondition = new BlobRequestConditions { IfMatch = current.ETag };
            await root.DeleteAsync(conditions: currentCondition, cancellationToken: ct);
            await root.WithVersion(next.VersionId).DeleteAsync(conditions: currentCondition, cancellationToken: ct);
            await version.DeleteAsync(conditions: condition, cancellationToken: ct);
        }
        if (await root.ExistsAsync(ct) || await root.WithVersion(next.VersionId).ExistsAsync(ct) || await version.ExistsAsync(ct))
            throw new InvalidDataException("Expired synthetic versions were not deleted.");
    }

    private static async Task DemandProtectedAsync(Func<Task> attempt)
    {
        try { await attempt(); }
        catch (RequestFailedException error) when (error.Status == 409 && error.ErrorCode == "BlobImmutableDueToPolicy") { return; }
        throw new InvalidDataException("Azure did not reject an early mutation/deletion with its immutability policy.");
    }

    // Explicitly nominated operator test data only, independent of enrolled purge.
    // No discovery, SQL mutation, authority issuance or policy changes.
    private static async Task CleanupSyntheticAsync(IServiceProvider services, Guid envelope, Guid objectId, byte[] expected, CancellationToken ct)
    {
        if (envelope == Guid.Empty || objectId == Guid.Empty) throw new InvalidDataException("Invalid synthetic object.");
        var root = services.GetRequiredService<BlobServiceClient>().GetBlobContainerClient("final").GetBlobClient($"{envelope:N}/executed/{objectId:N}");
        var properties = (await root.GetPropertiesAsync(cancellationToken: ct)).Value;
        if (properties.ContentLength is <16 or >4096 || string.IsNullOrEmpty(properties.VersionId) || properties.HasLegalHold ||
            properties.ImmutabilityPolicy is not { ExpiresOn: DateTimeOffset until, PolicyMode: BlobImmutabilityPolicyMode.Locked } ||
            until > services.GetRequiredService<TimeProvider>().GetUtcNow()) throw new InvalidDataException("Synthetic probe protection is not expired.");
        var condition = new BlobRequestConditions { IfMatch = properties.ETag };
        var version = root.WithVersion(properties.VersionId);
        var downloaded = (await version.DownloadContentAsync(new BlobDownloadOptions { Conditions = condition }, ct)).Value.Content.ToArray();
        DemandSyntheticDocument(downloaded, expected);
        await root.DeleteAsync(conditions: condition, cancellationToken: ct);
        await version.DeleteAsync(conditions: condition, cancellationToken: ct);
        if (await root.ExistsAsync(ct) || await version.ExistsAsync(ct)) throw new InvalidDataException("Synthetic cleanup did not complete.");
    }

    public static void DemandSyntheticDocument(byte[] bytes, byte[] expected)
    {
        if (bytes.Length is <16 or >4096 || expected.Length != 32 || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(bytes), expected))
            throw new InvalidDataException("Synthetic probe hash differs.");
        using var input = new MemoryStream(bytes, false);
        using var pdf = PdfReader.Open(input, PdfDocumentOpenMode.Import);
        if (pdf.PageCount != 1 || pdf.Info.Title != "SYNTHETIC STORAGE AND SEAL CHECK - NO AGREEMENT" || pdf.Internals.Catalog.Elements.GetDictionary("/AcroForm") is not null)
            throw new InvalidDataException("Only a nominated unsigned synthetic probe may be removed.");
    }

    private static async Task VerifySealsAsync(IServiceProvider services, CancellationToken ct)
    {
        var engine = services.GetRequiredService<PlatformPdfSeal>();
        var source = SyntheticPdf(); var hash = SHA256.HashData(source);
        var first = await engine.SealAsync(source, hash, ct);
        // A new provider read must retain the same persisted identity. Each successful
        // engine operation sends one coordinated TSA request; no retry here.
        var second = await engine.SealBoundAsync(source, hash, Convert.FromHexString(first.CertificateSha256), ct);
        if (first.CertificateSha256 != second.CertificateSha256 || !first.SourceSha256.AsSpan().SequenceEqual(hash) ||
            !second.SourceSha256.AsSpan().SequenceEqual(hash) || first.Bytes.AsSpan().SequenceEqual(source) || second.Bytes.AsSpan().SequenceEqual(source))
            throw new InvalidDataException("Persistent seal verification failed.");
    }
}
