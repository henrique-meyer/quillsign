using System.Diagnostics;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using QuillSign.Completion;
using QuillSign.Verification;

namespace QuillSign.Tests;

public sealed class VerificationUploadCancellationTests
{
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Body_timeout_and_caller_cancellation_stop_before_framework_form_reads_or_backend_and_restore_request_lifetime(bool caller)
    {
        using var source=new CancellationTokenSource();var original=source.Token;using var body=new Stalled();using var response=new MemoryStream();
        var http=new DefaultHttpContext();http.Request.Path="/verify";http.Request.Method="POST";http.Request.ContentType="multipart/form-data; boundary=synthetic";http.Request.Body=body;http.RequestAborted=original;http.Response.Body=response;
        var calls=0;var boundary=new VerificationUploadBoundary(_=> {calls++;return Task.CompletedTask;},new UploadedPdfVerificationOptions {TimeoutSeconds=1},new VerificationBrowserOptions {BodyTimeoutSeconds=1},Options.Create(new AntiforgeryOptions()));
        var timer=Stopwatch.StartNew();var running=boundary.InvokeAsync(http);await body.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        if(caller) {source.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>running);}
        else {await running;Assert.Equal(503,http.Response.StatusCode);Assert.Contains("No integrity result is confirmed",System.Text.Encoding.UTF8.GetString(response.ToArray()));}
        Assert.Equal(original,http.RequestAborted);Assert.Equal(0,calls);Assert.True(timer.Elapsed<TimeSpan.FromSeconds(10));
    }
    private sealed class Stalled : Stream
    {
        public readonly TaskCompletionSource Entered=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override bool CanRead=>true;public override bool CanSeek=>false;public override bool CanWrite=>false;
        public override long Length=>throw new NotSupportedException();public override long Position {get=>throw new NotSupportedException();set=>throw new NotSupportedException();}
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken ct=default) {Entered.TrySetResult();await Task.Delay(Timeout.InfiniteTimeSpan,ct);return 0;}
        public override Task<int> ReadAsync(byte[] buffer,int offset,int count,CancellationToken ct)=>ReadAsync(buffer.AsMemory(offset,count),ct).AsTask();
        public override int Read(byte[] buffer,int offset,int count)=>throw new NotSupportedException();public override void Flush()=>throw new NotSupportedException();public override long Seek(long offset,SeekOrigin origin)=>throw new NotSupportedException();public override void SetLength(long value)=>throw new NotSupportedException();public override void Write(byte[] buffer,int offset,int count)=>throw new NotSupportedException();
    }
}
