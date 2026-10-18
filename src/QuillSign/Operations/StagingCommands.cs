using System.Security.Cryptography;
using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using PdfSharp.Pdf;
using QuillSign.Sealing;
using QuillSign.Storage;

namespace QuillSign.Operations;

// Explicit operator invocation only. No SQL, email, public route or scheduled producer.
public static class StagingCommands
{
    public static async Task<int> RunAsync(string[] args)
    {
        if (args.Length != 1 || args[0] is not ("storage" or "seal"))
        { Console.Error.WriteLine("Usage: staging storage|seal"); return 2; }
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
            if (args[0] == "storage") await VerifyStorageAsync(app.Services, timeout.Token);
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
        var version = services.GetRequiredService<BlobServiceClient>().GetBlobContainerClient("final")
            .GetBlobClient($"{target.EnvelopeId:N}/executed/{target.ObjectId:N}").WithVersion(stored.VersionId);
        try
        {
            await DemandProtectedAsync(() => version.SetMetadataAsync(new Dictionary<string, string> { ["synthetic"] = "mutation-must-fail" },
                new BlobRequestConditions { IfMatch = new ETag(stored.ETag) }, ct), versionMutation: true);
            await DemandProtectedAsync(() => version.DeleteAsync(cancellationToken: ct));
        }
        finally
        {
            var delay = until.AddSeconds(3) - time.GetUtcNow();
            if (delay > TimeSpan.Zero) await Task.Delay(delay, ct);
            // Exact generated version only; never clear a policy, enumerate or delete a container.
            await version.DeleteAsync(cancellationToken: ct);
        }
        if (await version.ExistsAsync(ct)) throw new InvalidDataException("Expired synthetic version was not deleted.");
    }

    private static async Task DemandProtectedAsync(Func<Task> attempt, bool versionMutation = false)
    {
        try { await attempt(); }
        catch (RequestFailedException error) when (error.Status == 409 && error.ErrorCode == "BlobImmutableDueToPolicy" ||
            versionMutation && error.Status == 400 && error.ErrorCode == "OperationNotAllowedOnVersion") { return; }
        throw new InvalidDataException("Azure did not reject an early mutation/deletion with its immutability policy.");
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
