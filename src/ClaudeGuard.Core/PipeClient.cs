using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;

namespace ClaudeGuard;

public sealed class ServiceUnavailableException : IOException
{
    public ServiceUnavailableException() : base("守护服务未运行或暂时无法连接") { }
}

public static class PipeClient
{
    public static async Task<Response> SendAsync(Request request, CancellationToken ct)
    {
        // An absent service must not consume the much longer audit timeout.
        if (Native.ServicePid() == 0) throw new ServiceUnavailableException();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(request.Command is "check" or "repair" ? 55 : 4));
        using var pipe = new NamedPipeClientStream(".", Product.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
        await ConnectAsync(pipe, timeout.Token, TimeSpan.FromSeconds(2));
        // Reject a pipe squatter before disclosing the controller secret.
        if (!Native.GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var pid)) throw new IOException("服务身份验证失败");
        if (pid == 0 || pid != Native.ServicePid())
            throw new IOException("服务身份验证失败");
        await PipeWire.WriteAsync(pipe, request, timeout.Token);
        return await PipeWire.ReadAsync<Response>(pipe, timeout.Token);
    }

    internal static async Task ConnectAsync(NamedPipeClientStream pipe, CancellationToken ct, TimeSpan connectionTimeout)
    {
        using var connection = CancellationTokenSource.CreateLinkedTokenSource(ct);
        connection.CancelAfter(connectionTimeout);
        try { await pipe.ConnectAsync(connection.Token); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw new ServiceUnavailableException(); }
    }
}

public static class PipeWire
{
    public const int MaxBytes = 32768;
    public static async Task<T> ReadAsync<T>(Stream pipe, CancellationToken ct)
    {
        byte[] header = new byte[4];
        await pipe.ReadExactlyAsync(header, ct);
        int length = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length is <= 0 or > MaxBytes) throw new IOException("消息长度无效");
        byte[] bytes = new byte[length]; await pipe.ReadExactlyAsync(bytes, ct);
        return JsonSerializer.Deserialize<T>(bytes, new JsonSerializerOptions { MaxDepth = 12 }) ?? throw new IOException("消息无效");
    }
    public static async Task WriteAsync<T>(Stream pipe, T value, CancellationToken ct)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        if (bytes.Length > MaxBytes) throw new IOException("消息过长");
        byte[] header = new byte[4]; System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(header, bytes.Length);
        await pipe.WriteAsync(header, ct); await pipe.WriteAsync(bytes, ct); await pipe.FlushAsync(ct);
    }
}
