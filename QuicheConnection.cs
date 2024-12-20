using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using static Quiche.NativeMethods;

#if !WINDOWS
using size_t = int;
#else
using size_t = uint;
#endif

namespace Quiche.NET;

public class QuicheConnection : IDisposable
{
    private static (MemoryHandle, int) GetSocketAddress(EndPoint? endPoint)
    {
        Memory<byte>? buf = endPoint?.Serialize().Buffer;
        return buf is null ? default : (buf.Value.Pin(), buf.Value.Length);
    }

    internal unsafe static QuicheConnection Accept(Socket socket,
        EndPoint remoteEndPoint, ReadOnlyMemory<byte> initialData,
        QuicheConfig config, byte[]? cid = null)
    {
        EndPoint localEndPoint = socket.LocalEndPoint ?? throw new ArgumentException(
            "Given socket was not bound to a valid local endpoint!", nameof(socket));

        var (local, local_len) = GetSocketAddress(localEndPoint);
        var (remote, remote_len) = GetSocketAddress(remoteEndPoint);

        using (local)
        using (remote)
        {
            byte[] scidBuf = (byte[]?)cid?.Clone() ?? RandomNumberGenerator
                .GetBytes((int)QuicheLibrary.MAX_CONN_ID_LEN);
            fixed (byte* scidPtr = scidBuf)
            {
                return new(quiche_accept(
                    scidPtr, (nuint)scidBuf.Length, null, 0,
                    (sockaddr*)local.Pointer, local_len,
                    (sockaddr*)remote.Pointer, remote_len,
                    config.NativePtr),
                    socket, remoteEndPoint,
                    initialData, scidBuf);
            }
        }
    }

    public unsafe static QuicheConnection Connect(Socket socket, EndPoint remoteEndPoint,
        QuicheConfig config, string? hostname = null, byte[]? cid = null)
    {
        EndPoint localEndPoint = socket.LocalEndPoint ?? throw new ArgumentException(
            "Given socket was not bound to a valid local endpoint!", nameof(socket));

        var (local, local_len) = GetSocketAddress(localEndPoint);
        var (remote, remote_len) = GetSocketAddress(remoteEndPoint);

        using (local)
        using (remote)
        {
            byte[] hostnameBuf = Encoding.UTF8.GetBytes([.. hostname?.ToCharArray(), '\u0000']);
            byte[] scidBuf = (byte[]?)cid?.Clone() ?? RandomNumberGenerator
                .GetBytes((int)QuicheLibrary.MAX_CONN_ID_LEN);

            fixed (byte* hostnamePtr = hostnameBuf)
            fixed (byte* scidPtr = scidBuf)
            {
                return new(quiche_connect(hostnamePtr,
                    scidPtr, (nuint)scidBuf.Length,
                    (sockaddr*)local.Pointer, local_len,
                    (sockaddr*)remote.Pointer, remote_len,
                    config.NativePtr),
                    socket, remoteEndPoint,
                    ReadOnlyMemory<byte>.Empty, scidBuf);
            }
        }
    }

    internal unsafe nint SendOnPath(Socket socket, EndPoint remoteEndPoint,
        QuicheConfig config, byte* outBuffer, nuint outBufferLength, SendInfo* sendInfo)
    {
        EndPoint localEndPoint = socket.LocalEndPoint ?? throw new ArgumentException(
            "Given socket was not bound to a valid local endpoint!", nameof(socket));

        var (local, local_len) = GetSocketAddress(localEndPoint);
        var (remote, remote_len) = GetSocketAddress(remoteEndPoint);

        using (local)
        using (remote)
        {
            return NativePtr->SendOnPath(outBuffer, outBufferLength, (sockaddr*)local.Pointer, local_len, (sockaddr*)remote.Pointer, remote_len, sendInfo);
        }
    }

    private const int MAX_STREAM_SEND_RETRIES = 10;

    private readonly Task? listenTask;
    private readonly Task recvTask, recvStreamTask, sendTask, sendStreamTask;
    private readonly CancellationTokenSource cts;

    private readonly TaskCompletionSource establishedTcs;
    private readonly ConcurrentDictionary<ulong, QuicheStream> streamMap;
    private readonly ConcurrentBag<TaskCompletionSource<QuicheStream>> streamBag;

    private readonly Socket socket;
    private readonly EndPoint remoteEndPoint;

    internal readonly ConcurrentDictionary<ulong, byte[]> sendQueue;
    internal readonly ConcurrentQueue<ReadOnlyMemory<byte>> recvQueue;

    private readonly byte[] connectionId;
    internal ReadOnlySpan<byte> ConnectionId => connectionId;

    internal unsafe Conn* NativePtr { get; private set; }

    public Task ConnectionEstablished => establishedTcs.Task;

    public unsafe bool IsClosed
    {
        get
        {
            lock (this)
            {
                return NativePtr is not null && NativePtr->IsClosed();
            }
        }
    }

    public unsafe bool IsServer
    {
        get
        {
            lock (this)
            {
                return NativePtr is not null && NativePtr->IsServer();
            }
        }
    }

    private unsafe QuicheConnection(Conn* nativePtr, Socket socket, EndPoint remoteEndPoint, ReadOnlyMemory<byte> initialData, ReadOnlyMemory<byte> connectionId)
    {
        NativePtr = nativePtr;

        this.socket = socket;
        this.remoteEndPoint = remoteEndPoint;

        this.connectionId = new byte[QuicheLibrary.MAX_CONN_ID_LEN];
        connectionId.CopyTo(this.connectionId);

        sendQueue = new();
        recvQueue = new();

        streamMap = new();
        streamBag = new();

        establishedTcs = new();

        cts = new();

        recvTask = Task.Run(() => ReceiveAsync(cts.Token));
        sendTask = Task.Run(() => SendAsync(cts.Token));

        recvStreamTask = Task.Run(() => ReceiveStreamAsync(cts.Token));
        sendStreamTask = Task.Run(() => SendStreamAsync(cts.Token));

        if (initialData.IsEmpty)
        {
            listenTask = Task.Run(() => ListenAsync(cts.Token));
        }
        else
        {
            recvQueue.Enqueue(initialData);
        }
    }

    private class SendScheduleInfo
    {
        public int SendCount { get; set; }
        public byte[]? SendBuffer { get; set; }
    }

    private void SendPacket(object? state)
    {
        SendScheduleInfo? info = state as SendScheduleInfo;
        if (info is not null)
        {
            lock (info)
            {
                if (info.SendBuffer is not null)
                {
                    int bytesSent = 0;
                    while (bytesSent < info.SendCount)
                    {
                        var packetSpan = info.SendBuffer.AsSpan(bytesSent, info.SendCount - bytesSent);
                        bytesSent += socket.SendTo(packetSpan, remoteEndPoint);
                    }
                }
            }
        }
    }

    private async Task SendAsync(CancellationToken cancellationToken)
    {
        byte[] packetBuf = new byte[QuicheLibrary.MAX_DATAGRAM_LEN];

        SendScheduleInfo info = new() { SendBuffer = packetBuf };
        Timer timer = new Timer(SendPacket, info, Timeout.Infinite, Timeout.Infinite);

        while (!cancellationToken.IsCancellationRequested)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                long resultOrError;
                SendInfo sendInfo = default;
                unsafe
                {
                    lock (this)
                    {
                        fixed (byte* pktPtr = info.SendBuffer)
                        {
                            resultOrError = (long)NativePtr->Send(
                                pktPtr, (nuint)info.SendBuffer.Length,
                                (SendInfo*)Unsafe.AsPointer(ref sendInfo)
                                );
                        }
                    }
                }

                QuicheException.ThrowIfError((QuicheError)resultOrError);

                lock (info)
                {
                    info.SendCount = (int)resultOrError;
                }

                timer.Change(
                    TimeSpan.FromSeconds(Unsafe.As<timespec, CLong>
                        (ref sendInfo.at).Value) +
                    TimeSpan.FromTicks(sendInfo.at.tv_nsec / 100),
                    Timeout.InfiniteTimeSpan
                    );
            }
            catch (QuicheException ex)
            when (ex.ErrorCode == QuicheError.QUICHE_ERR_DONE)
            {
                if (IsClosed) { throw; }
                await Task.Delay(75, cancellationToken);
                continue;
            }
            catch (QuicheException ex)
            {
                establishedTcs.TrySetException(ex);
                while (streamBag.TryTake(out TaskCompletionSource<QuicheStream>? tcs))
                {
                    tcs.TrySetException(ex);
                }
                throw;
            }
            catch (OperationCanceledException)
            {
                establishedTcs.TrySetCanceled(cts.Token);
                while (streamBag.TryTake(out TaskCompletionSource<QuicheStream>? tcs))
                {
                    tcs.TrySetCanceled(cts.Token);
                }
                throw;
            }
        }
    }

    private async Task SendStreamAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();

                ulong streamId;
                QuicheStream? stream;
                if (sendQueue.Any())
                {
                    streamId = sendQueue.Keys.First();
                    stream = GetStream(streamId);
                }
                else
                {
                    ulong? streamIdOrNull =
                        streamMap.Keys.Cast<ulong?>()
                        .FirstOrDefault(x => x.HasValue ?
                            IsStreamFinished(x.Value) : false
                            );

                    streamId = streamIdOrNull.GetValueOrDefault();
                    stream = streamIdOrNull is null ?
                        null : GetStream(streamId);
                }

                bool isConnectionEstablished, isInEarlyData;
                unsafe
                {
                    lock (this)
                    {
                        isConnectionEstablished = NativePtr->IsEstablished();
                        isInEarlyData = NativePtr->IsInEarlyData();
                    }
                }

                if (stream is null || (!isConnectionEstablished && !isInEarlyData))
                {
                    foreach (var str in streamMap.Values)
                    {
                        str.Flush();
                    }

                    await Task.Delay(75, cancellationToken);
                    continue;
                }

                if (!sendQueue.TryRemove(streamId, out byte[]? streamBuf) || streamBuf.Length == 0)
                {
                    stream.Flush();

                    await Task.Delay(75, cancellationToken);
                    continue;
                }

                long resultOrError, errorCode, bytesSent = 0;
                Lazy<bool> hasNotSentAllBytes;
                do
                {
                    unsafe
                    {
                        lock (this)
                        {
                            fixed (byte* bufPtr = streamBuf)
                            {
                                errorCode = (long)QuicheError.QUICHE_ERR_NONE;
                                resultOrError = (long)NativePtr->StreamSend(streamId,
                                    bufPtr + bytesSent, (nuint)(streamBuf.Length - bytesSent),
                                    false, (ulong*)Unsafe.AsPointer(ref errorCode)
                                    );
                            }
                        }
                    }

                    hasNotSentAllBytes = new(() => (bytesSent += resultOrError) < streamBuf.Length);
                } while (resultOrError >= 0 && hasNotSentAllBytes.Value);

                sendQueue.AddOrUpdate(streamId,
                    key => streamBuf[(int)bytesSent..],
                    (key, buf) => [.. streamBuf[(int)bytesSent..], .. buf]
                    );

                QuicheException.ThrowIfError((QuicheError)resultOrError);

                stream.SetFirstWrite();
            }
            catch (QuicheException ex)
            when (ex.ErrorCode == QuicheError.QUICHE_ERR_DONE)
            {
                if (IsClosed) { throw; }
                await Task.Delay(75, cancellationToken);
                continue;
            }
            catch (QuicheException ex)
            {
                establishedTcs.TrySetException(ex);
                while (streamBag.TryTake(out TaskCompletionSource<QuicheStream>? tcs))
                {
                    tcs.TrySetException(ex);
                }
                throw;
            }
            catch (OperationCanceledException)
            {
                establishedTcs.TrySetCanceled(cts.Token);
                while (streamBag.TryTake(out TaskCompletionSource<QuicheStream>? tcs))
                {
                    tcs.TrySetCanceled(cts.Token);
                }
                throw;
            }
        }
    }

    private async Task ReceiveAsync(CancellationToken cancellationToken)
    {
        byte[] packetBuf = new byte[QuicheLibrary.MAX_DATAGRAM_LEN];
        while (!cancellationToken.IsCancellationRequested)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                bool isConnEstablished, isInEarlyData;
                unsafe
                {
                    lock (this)
                    {
                        NativePtr->OnTimeout();

                        isConnEstablished = NativePtr->IsEstablished();
                        isInEarlyData = NativePtr->IsInEarlyData();
                    }
                }

                if (isConnEstablished)
                {
                    establishedTcs.TrySetResult();
                }

                ReadOnlyMemory<byte> nextPacket;
                if (!recvQueue.TryDequeue(out nextPacket) && !IsClosed)
                {
                    await Task.Delay(75, cancellationToken);
                    continue;
                }
                else if (IsClosed)
                {
                    throw new QuicheException(QuicheError.QUICHE_ERR_DONE, "Connection timed out from inactivity.");
                }
                else
                {
                    nextPacket.CopyTo(packetBuf);
                }

                long resultOrError;
                unsafe
                {
                    lock (this)
                    {
                        var (to, to_len) = GetSocketAddress(socket.LocalEndPoint);
                        var (from, from_len) = GetSocketAddress(remoteEndPoint);

                        RecvInfo recvInfo = new RecvInfo
                        {
                            to = (sockaddr*)to.Pointer,
                            to_len = to_len,

                            from = (sockaddr*)from.Pointer,
                            from_len = from_len,
                        };

                        using (to)
                        using (from)
                        {
                            fixed (byte* bufPtr = packetBuf)
                            {
                                resultOrError = (long)NativePtr->Recv(
                                    bufPtr, (nuint)nextPacket.Length,
                                    (RecvInfo*)Unsafe.AsPointer(ref recvInfo)
                                    );
                            }
                        }
                    }
                }

                QuicheException.ThrowIfError((QuicheError)resultOrError);
            }
            catch (QuicheException ex)
            {
                establishedTcs.TrySetException(ex);
                while (streamBag.TryTake(out TaskCompletionSource<QuicheStream>? tcs))
                {
                    tcs.TrySetException(ex);
                }
                throw;
            }
            catch (OperationCanceledException)
            {
                establishedTcs.TrySetCanceled(cts.Token);
                while (streamBag.TryTake(out TaskCompletionSource<QuicheStream>? tcs))
                {
                    tcs.TrySetCanceled(cts.Token);
                }
                throw;
            }
        }
    }

    private async Task ReceiveStreamAsync(CancellationToken cancellationToken)
    {
        byte[] streamBuf = new byte[QuicheLibrary.MAX_BUFFER_LEN];
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();

                long streamIdOrNone;
                bool isConnEstablished, isInEarlyData;
                unsafe
                {
                    lock (this)
                    {
                        streamIdOrNone = NativePtr->StreamReadableNext();

                        isConnEstablished = NativePtr->IsEstablished();
                        isInEarlyData = NativePtr->IsInEarlyData();
                    }
                }

                ulong streamId;
                QuicheStream stream;
                if (streamIdOrNone >= 0 && (isConnEstablished || isInEarlyData))
                {
                    streamId = (ulong)streamIdOrNone;
                    stream = GetStream(streamId);
                }
                else
                {
                    await Task.Delay(75, cancellationToken);
                    continue;
                }

                if (!streamBag.TryTake(out TaskCompletionSource<QuicheStream>? tcs))
                {
                    streamBag.Add(tcs = new());
                }
                tcs.TrySetResult(stream);

                bool streamFinished = false;
                long recvCount = long.MaxValue;
                while (!streamFinished && recvCount > 0)
                {
                    long errorCode;
                    unsafe
                    {
                        lock (this)
                        {
                            fixed (byte* bufPtr = streamBuf)
                            {
                                errorCode = (long)QuicheError.QUICHE_ERR_NONE;
                                recvCount = (long)NativePtr->StreamRecv(streamId, bufPtr, (nuint)streamBuf.Length,
                                    (bool*)Unsafe.AsPointer(ref streamFinished), (ulong*)Unsafe.AsPointer(ref errorCode));
                            }
                        }
                    }

                    if (recvCount > 0)
                    {
                        await stream.ReceiveDataAsync(
                            streamBuf.AsMemory(0, (int)recvCount),
                            streamFinished, cancellationToken
                            );

                        stream.SetFirstRead();
                    }
                    else
                    {
                        QuicheException.ThrowIfError((QuicheError)recvCount);
                    }
                }
            }
            catch (QuicheException ex)
                when (ex.ErrorCode == QuicheError.QUICHE_ERR_DONE)
            {
                if (IsClosed) { throw; }
                await Task.Delay(75, cancellationToken);
                continue;
            }
            catch (QuicheException ex)
            {
                while (streamBag.TryTake(out TaskCompletionSource<QuicheStream>? tcs))
                {
                    tcs.TrySetException(ex);
                }
                throw;
            }
            catch (OperationCanceledException)
            {
                while (streamBag.TryTake(out TaskCompletionSource<QuicheStream>? tcs))
                {
                    tcs.TrySetCanceled(cts.Token);
                }
                throw;
            }
        }
    }

    private async Task ListenAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            cancellationToken.ThrowIfCancellationRequested();

            byte[] packetBuf = new byte[QuicheLibrary.MAX_DATAGRAM_LEN];
            SocketReceiveFromResult result = await socket.ReceiveFromAsync(
                packetBuf, remoteEndPoint, cancellationToken);
            recvQueue.Enqueue(packetBuf.AsMemory(0, result.ReceivedBytes));
        }
    }

    private QuicheStream GetStream(ulong streamId) =>
        streamMap.GetOrAdd(streamId, id => new(this, id));

    internal unsafe bool IsStreamFinished(ulong streamId)
    {
        lock (this)
        {
            return NativePtr is not null && NativePtr->StreamFinished(streamId);
        }
    }

    public async Task<QuicheStream> CreateOutboundStreamAsync(QuicheStream.Direction direction, CancellationToken cancellationToken = default)
    {
        ulong streamId, streamIdx = 0;
        do
        {
            cancellationToken.ThrowIfCancellationRequested();
            streamId = (streamIdx++ << 2) | (ulong)direction | Convert.ToUInt64(IsServer);
            if (streamMap.ContainsKey(streamId))
            {
                await Task.Yield();
            }
            else
            {
                break;
            }
        } while (!cancellationToken.IsCancellationRequested);
        return GetStream(streamId);
    }

    public async Task<QuicheStream> AcceptInboundStreamAsync(CancellationToken cancellationToken = default)
    {
        if (!streamBag.TryTake(out TaskCompletionSource<QuicheStream>? tcs))
        {
            streamBag.Add(tcs = new());
        }
        return await tcs.Task.WaitAsync(cancellationToken);
    }

    private bool disposedValue;

    protected unsafe virtual void Dispose(bool disposing)
    {
        bool isNativeHandleValid;
        lock (this)
        {
            isNativeHandleValid = NativePtr is not null;
        }

        if (!disposedValue && isNativeHandleValid)
        {
            if (disposing)
            {
                try
                {
                    cts.Cancel();
                    Task.WhenAll(recvTask, sendTask,
                        recvStreamTask, sendStreamTask,
                        listenTask ?? Task.CompletedTask
                        ).Wait();
                }
                catch (AggregateException ex)
                when (ex.InnerExceptions.All(
                    x => x is OperationCanceledException ||
                    x is QuicheException q && q.ErrorCode == QuicheError.QUICHE_ERR_DONE
                    ))
                { }

                foreach (var (_, stream) in streamMap)
                {
                    stream.Dispose();
                }

                try
                {
                    lock (this)
                    {
                        int errorResult;
                        byte[] reasonBuf = Encoding.UTF8.GetBytes("Connection was implicitly closed for user initiated disposal.");
                        fixed (byte* reasonPtr = reasonBuf)
                        {
                            errorResult = NativePtr->Close(true, 0x00, reasonPtr, (nuint)reasonBuf.Length);
                            QuicheException.ThrowIfError((QuicheError)errorResult, "Failed to close connection!");
                        }
                    }
                }
                catch (QuicheException ex)
                when (ex.ErrorCode == QuicheError.QUICHE_ERR_DONE)
                { }
                finally
                {
                    cts.Dispose();

                    recvQueue.Clear();
                    sendQueue.Clear();

                    streamMap.Clear();
                    streamBag.Clear();

                    if (!IsServer)
                    {
                        socket.Dispose();
                    }
                }
            }

            lock (this)
            {
                if (NativePtr is not null)
                {
                    NativePtr->Free();
                    NativePtr = null;
                }
            }
        }

        disposedValue = true;
    }

    ~QuicheConnection()
    {
        Dispose(disposing: false);
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
}
