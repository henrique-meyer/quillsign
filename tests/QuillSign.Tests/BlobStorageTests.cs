using System.Security.Claims;
using Azure;
using Azure.Storage.Blobs;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class BlobStorageTests
{
    private static BlobServiceClient Service() => new(
        Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE") ??
            throw new InvalidOperationException("Run scripts/dev/Use-LocalDatabase.ps1 -Action Test with Azurite running."),
        new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03));

    internal static ClaimsPrincipal Sender(Guid envelope, string? scheme = EnvelopeStorageAuthorization.SenderScheme) =>
        new(new ClaimsIdentity([new Claim(EnvelopeStorageAuthorization.EnvelopeClaim, envelope.ToString())], scheme));

    private static DocumentBlob Reference() => new(Guid.NewGuid(), DocumentBlobKind.Original, Guid.NewGuid());
    private static BlobClient Raw(BlobServiceClient service, DocumentBlob reference) => service
        .GetBlobContainerClient(reference.Kind switch
        {
            DocumentBlobKind.Original => "originals", DocumentBlobKind.Normalized => "normalized", _ => "previews"
        }).GetBlobClient($"{reference.EnvelopeId:N}/{reference.ObjectId:N}");

    [Theory]
    [InlineData(DocumentBlobKind.Original)]
    [InlineData(DocumentBlobKind.Normalized)]
    [InlineData(DocumentBlobKind.Preview)]
    public async Task Nonseekable_multiblock_document_roundtrips_without_buffering_the_whole_document(DocumentBlobKind kind)
    {
        var service = Service();
        var store = new AzureBlobStore(service, 2 * 1024 * 1024, true);
        var reference = Reference() with { Kind = kind };
        var payload = new byte[1024 * 1024 + 17];
        Random.Shared.NextBytes(payload);
        using var input = new NonseekableInput(payload);
        try
        {
            await store.WriteAsync(Sender(reference.EnvelopeId), reference, input, payload.Length);
            using var output = new MemoryStream();
            Assert.Equal(payload.Length, await store.CopyToAsync(Sender(reference.EnvelopeId), reference, output));
            Assert.Equal(payload, output.ToArray());
            Assert.InRange(input.LargestRequest, 1, 256 * 1024);
            var container = service.GetBlobContainerClient(kind switch
            {
                DocumentBlobKind.Original => "originals", DocumentBlobKind.Normalized => "normalized", _ => "previews"
            });
            var properties = await container.GetAccessPolicyAsync();
            Assert.Equal(Azure.Storage.Blobs.Models.PublicAccessType.None, properties.Value.BlobPublicAccess);
            // No anonymous access even when the object path is known.
            var anonymous = new BlobClient(Raw(service, reference).Uri,
                new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03));
            var denied = await Assert.ThrowsAsync<RequestFailedException>(() => anonymous.DownloadContentAsync());
            Assert.Contains(denied.Status, new[] { 403, 404 });
        }
        finally { await store.DeleteAsync(Sender(reference.EnvelopeId), reference); }
    }

    [Theory]
    [InlineData(0)] // Other envelope.
    [InlineData(1)] // Anonymous identity carrying the claim.
    [InlineData(2)] // Unrelated authentication scheme.
    [InlineData(3)] // Ambiguous envelope scope.
    public async Task Unauthorized_requests_are_rejected_before_any_storage_request(int mode)
    {
        var reference = Reference();
        var identity = mode switch
        {
            0 => Sender(Guid.NewGuid()),
            1 => Sender(reference.EnvelopeId, null),
            2 => Sender(reference.EnvelopeId, "Unrelated"),
            _ => new ClaimsPrincipal(new ClaimsIdentity([
                new Claim(EnvelopeStorageAuthorization.EnvelopeClaim, reference.EnvelopeId.ToString()),
                new Claim(EnvelopeStorageAuthorization.EnvelopeClaim, Guid.NewGuid().ToString())
            ], EnvelopeStorageAuthorization.SenderScheme))
        };
        var store = new AzureBlobStore(new BlobServiceClient(new Uri("http://127.0.0.1:1")), 1024);
        using var data = new MemoryStream([1]);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => store.WriteAsync(identity, reference, data, 1));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => store.CopyToAsync(identity, reference, data));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => store.DeleteAsync(identity, reference));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(1025)]
    public async Task Invalid_declared_size_is_rejected_without_storage_access(long length)
    {
        var reference = Reference();
        var store = new AzureBlobStore(new BlobServiceClient(new Uri("http://127.0.0.1:1")), 1024);
        using var source = new MemoryStream([1]);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => store.WriteAsync(Sender(reference.EnvelopeId), reference, source, length));
    }

    [Theory]
    [InlineData(9, 10)]
    [InlineData(11, 10)]
    public async Task Declared_length_mismatch_never_commits_a_readable_object(int actual, int declared)
    {
        var service = Service();
        var store = new AzureBlobStore(service, 1024, true);
        var reference = Reference();
        using var source = new NonseekableInput(new byte[actual]);
        await Assert.ThrowsAsync<InvalidDataException>(() => store.WriteAsync(Sender(reference.EnvelopeId), reference, source, declared));
        Assert.False((await Raw(service, reference).ExistsAsync()).Value);
    }

    [Fact]
    public async Task Source_failure_after_a_staged_block_never_commits()
    {
        var service = Service();
        var store = new AzureBlobStore(service, 1024 * 1024, true);
        var reference = Reference();
        using var source = new NonseekableInput(new byte[512 * 1024], failAfter: 256 * 1024);
        await Assert.ThrowsAsync<IOException>(() => store.WriteAsync(Sender(reference.EnvelopeId), reference, source, 512 * 1024));
        Assert.False((await Raw(service, reference).ExistsAsync()).Value);
    }

    [Fact]
    public async Task Reusing_a_reference_cannot_overwrite_a_committed_object()
    {
        var service = Service();
        var store = new AzureBlobStore(service, 1024, true);
        var reference = Reference();
        var sender = Sender(reference.EnvelopeId);
        try
        {
            using var first = new MemoryStream([1, 2, 3]);
            await store.WriteAsync(sender, reference, first, 3);
            using var second = new MemoryStream([4, 5, 6]);
            var failure = await Assert.ThrowsAsync<RequestFailedException>(() => store.WriteAsync(sender, reference, second, 3));
            Assert.Contains(failure.Status, new[] { 409, 412 });
            using var result = new MemoryStream();
            await store.CopyToAsync(sender, reference, result);
            Assert.Equal(new byte[] { 1, 2, 3 }, result.ToArray());
        }
        finally { await store.DeleteAsync(sender, reference); }
    }

    [Fact]
    public async Task Oversized_stored_data_is_rejected_before_writing_to_the_destination()
    {
        var service = Service();
        var reference = Reference();
        var raw = Raw(service, reference);
        await service.GetBlobContainerClient("originals").CreateIfNotExistsAsync();
        await raw.UploadAsync(BinaryData.FromBytes(new byte[101]));
        try
        {
            using var result = new MemoryStream();
            var store = new AzureBlobStore(service, 100);
            await Assert.ThrowsAsync<InvalidDataException>(() => store.CopyToAsync(Sender(reference.EnvelopeId), reference, result));
            Assert.Equal(0, result.Length);
        }
        finally { await raw.DeleteIfExistsAsync(); }
    }

    [Fact]
    public async Task Missing_and_cancelled_operations_do_not_report_success()
    {
        var service = Service();
        var store = new AzureBlobStore(service, 1024, true);
        var reference = Reference();
        await service.GetBlobContainerClient("originals").CreateIfNotExistsAsync();
        using var result = new MemoryStream();
        var missing = await Assert.ThrowsAsync<RequestFailedException>(() => store.CopyToAsync(Sender(reference.EnvelopeId), reference, result));
        Assert.Equal(404, missing.Status);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        using var source = new MemoryStream([1]);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.WriteAsync(Sender(reference.EnvelopeId), reference, source, 1, cancellation.Token));
        Assert.False((await Raw(service, reference).ExistsAsync()).Value);
    }

    private sealed class NonseekableInput(byte[] payload, int? failAfter = null) : Stream
    {
        private int position;
        public int LargestRequest { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (failAfter.HasValue && position >= failAfter) throw new IOException("Synthetic source failure.");
            LargestRequest = Math.Max(LargestRequest, buffer.Length);
            var count = Math.Min(buffer.Length, payload.Length - position);
            payload.AsMemory(position, count).CopyTo(buffer);
            position += count;
            return ValueTask.FromResult(count);
        }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
