using Quiche;
using Quiche.NET;
using System.Buffers;
using System.Collections;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using static Quiche.NativeMethodsGroupingExtensions;

namespace QuichePlaygroundLibrary
{
    internal unsafe class Program
    {
        private const string QUICHE_H3_APPLICATION_PROTOCOL = "h3";
        private const int MAX_DATAGRAM_SIZE = 1350;

        private static Conn* _connection;
        private static H3Conn* _h3Connection;
        private static H3Config* _h3ConfigPtr;
        private static H3Config _h3Config;
        private static QuicheConfig _config;

        private static byte[] buffer;
        private static byte* bufferPtr;

        private static byte[] outBuffer;
        private static byte* outBufferPtr;

        private static Socket _client;
        private static IPEndPoint _remoteEndPoint;
        private const string Hostname = "google.com";
        private static H3Header[] Headers;
        private static long _streamId;

        private static bool _enableDebugLogging = false;

        static void Main(string[] args)
        {
            if (_enableDebugLogging)
                EnableDebugLogging();

            ConstructBuffer();
            CreateConfig();
            ConstructPeers();

            _connection = Connect(_client, _remoteEndPoint, _config, Hostname);
            _client.Blocking = false;

            Debug($"Initial - Connecting to: {_remoteEndPoint} from: {_client.LocalEndPoint}");

            SendInfo sendInfo = new SendInfo();
            Debug($"isClosed: {_connection->IsInEarlyData()}");

            nint write = _connection->Send(outBufferPtr, (nuint)outBuffer.Length, &sendInfo);
            int r = _client.SendTo(outBuffer, (int)write, SocketFlags.None, _remoteEndPoint);

            Debug($"Initial - Write: {write}");
            Debug($"isClosed: {_connection->IsInEarlyData()}");

            bool reqSent = false;
            _h3ConfigPtr = NativeMethods.quiche_h3_config_new();

            while (true)
            {
                ReadLoop();
                EstablishH3(ref reqSent);
                H3ReadLoop();
                WriteLoop();
            }
        }

        private static void EstablishH3(ref bool reqSent)
        {
            if (reqSent) return;

            if (_connection->IsEstablished() && _h3Connection == null)
            {
                Debug($"H3 - Creating Connection...");
                _h3Connection = NativeMethods.quiche_h3_conn_new_with_transport(_connection, _h3ConfigPtr);
                Debug($"H3 - Connection Created");
            }

            if (_h3Connection != null)
            {
                H3Header* headerPtr = (H3Header*)Marshal.UnsafeAddrOfPinnedArrayElement(Headers, 0);

                NativeMethods.quiche_h3_send_request(_h3Connection, _connection, headerPtr, HEADER_LENGTH, true);
                Debug($"H3 - Sending Request");
            }
        }

        private static void CreateConfig()
        {
            _config = new QuicheConfig();
            _config.ShouldVerifyPeer = false;
            _config.SetApplicationProtocols(QUICHE_H3_APPLICATION_PROTOCOL);
            _config.MaxIdleTimeout = 5000;
            _config.MaxReceiveUdpPayloadSize = MAX_DATAGRAM_SIZE;
            _config.MaxSendUdpPayloadSize = MAX_DATAGRAM_SIZE;

            _config.MaxInitialDataSize = 10_000_000;

            _config.MaxInitialLocalBidiStreamDataSize = 1_000_000;
            _config.MaxInitialRemoteBidiStreamDataSize = 1_000_000;
            _config.MaxInitialUniStreamDataSize = 1_000_000;
            _config.MaxInitialBidiStreams = 1_000_000;

            _config.MaxInitialBidiStreams = 100;
            _config.MaxInitialUniStreams = 100;
            _config.IsActiveMigrationDisabled = true;
        }

        private static void ConstructBuffer()
        {
            buffer = new byte[65535];
            outBuffer = new byte[MAX_DATAGRAM_SIZE];
            bufferPtr = (byte*)Marshal.UnsafeAddrOfPinnedArrayElement(buffer, 0);
            outBufferPtr = (byte*)Marshal.UnsafeAddrOfPinnedArrayElement(outBuffer, 0);
            Headers = ConstructHeaders();
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int OnForEachHeaderCallback(byte* name, nuint name_len, byte* value, nuint value_len, void* argp);
        private static int ForEachHeaderCallback(byte* name, nuint name_len, byte* value, nuint value_len, void* argp)
        {
            string n = System.Text.Encoding.UTF8.GetString(name, (int)name_len);
            string v = System.Text.Encoding.UTF8.GetString(value, (int)value_len);

            Debug($"H3 - Got HTTP Header: name: {n} value: {v}");
            return 0;
        }

        private static void ConstructPeers()
        {
            _client = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            _client.Bind(new IPEndPoint(IPAddress.Any, 0));

            // Remote
            IPHostEntry remoteHost = Dns.GetHostEntry(Hostname);
            IPAddress remoteIpAddress = remoteHost.AddressList[0];
            _remoteEndPoint = new IPEndPoint(remoteIpAddress, 443);
        }

        private static void ReadLoop()
        {
            while (true)
            {
                Thread.Sleep(1);

                Debug($"ReadLoop - Socket Receiving... isEstablished: {_connection->IsEstablished()}");

                bool noMorePacketsToRead = _client.Available <= 0;

                if (noMorePacketsToRead)
                {
                    Debug("ReadLoop - No more packets to read");
                    break;
                }

                int resultOrError = _client.Receive(buffer);

                Debug($"ReadLoop Received: {resultOrError}");

                if (resultOrError < 0)
                    continue;

                var (to, to_len) = GetSocketAddress(_client.LocalEndPoint);
                var (from, from_len) = GetSocketAddress(_remoteEndPoint);

                RecvInfo recvInfo = new RecvInfo
                {
                    to = (sockaddr*)to.Pointer,
                    to_len = to_len,

                    from = (sockaddr*)from.Pointer,
                    from_len = from_len,
                };

                Debug($"ReadLoop QUIC Receiving...");
                nint read = NativeMethods.quiche_conn_recv(_connection, bufferPtr, (nuint)resultOrError, &recvInfo);
                Debug($"ReadLoop QUIC Received... len: {read}");
            }
        }
        private static void H3ReadLoop()
        {
            if (_h3Connection == null) return;

            H3Event* h3Event;

            _streamId = _h3Connection->Poll(_connection, &h3Event);

            Debug($"H3 Polled streamId: {_streamId} h3Event: {(IntPtr)h3Event}");

            if (_streamId <= -1) return;

            quiche_h3_event_type eventType = (quiche_h3_event_type)NativeMethods.quiche_h3_event_type(h3Event);

            Debug($"H3 EventType: {eventType}");

            switch (eventType)
            {
                case quiche_h3_event_type.QUICHE_H3_EVENT_HEADERS:
                    {
                        var callback = new OnForEachHeaderCallback(ForEachHeaderCallback);
                        _forEachHeaderCallbackHandle = GCHandle.Alloc(callback);
                        var pCallback = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, void*, int>)(void*)Marshal.GetFunctionPointerForDelegate(callback);
                        int r = NativeMethods.quiche_h3_event_for_each_header(h3Event, pCallback, null);

                        if (r != 0)
                        {
                            Debug("H3 - Error on Header");
                            break;
                        }

                        break;
                    }
                case quiche_h3_event_type.QUICHE_H3_EVENT_DATA:
                    {
                        while (true)
                        {
                            nint len = NativeMethods.quiche_h3_recv_body(_h3Connection, _connection, (ulong)_streamId, bufferPtr, (nuint)buffer.Length);

                            if (len <= 0)
                                break;

                            string body = System.Text.Encoding.UTF8.GetString(buffer, 0, (int)len);
                            Debug($"H3 - Receive Body len: {len} body: {body}");
                        }

                        break;
                    }

                case quiche_h3_event_type.QUICHE_H3_EVENT_FINISHED:

                    Debug($"H3 - Closing Connection");

                    string reason = "kthxbye";
                    byte* reasonPtr = (byte*)Marshal.StringToHGlobalAnsi(reason);

                    int result = NativeMethods.quiche_conn_close(_connection, true, 0, reasonPtr, (nuint)reason.Length);

                    Debug($"H3 - Connection Closed, Result: {result}");
                    Environment.Exit(0);

                    break;
            }
        }

        private static void WriteLoop()
        {
            while (true)
            {
                SendInfo sendInfo = new SendInfo();
                nint write = _connection->Send(outBufferPtr, (nuint)outBuffer.Length, &sendInfo);

                Debug($"WriteLoop - QUIC Send: {write}");

                bool noMorePacketsToRead = write <= 0;

                if (noMorePacketsToRead)
                {
                    Debug("WriteLoop - No more packets to send");
                    break;
                }

                Debug($"WriteLoop - Socket Send: {write}");

                _client.SendTo(outBuffer, 0, (int)write, SocketFlags.None, _remoteEndPoint);

                Thread.Sleep(1);
            }
        }

        private static GCHandle _logCallbackHandle = default;
        private static GCHandle _forEachHeaderCallbackHandle = default;

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void OnQuicheLogCallback(byte* handle, void* context);
        private static unsafe void OnQuicheLog(byte* message, void* argp)
        {
            string msg = Marshal.PtrToStringAnsi((IntPtr)message) ?? string.Empty;
            Debug($"OnQuicheLog: {msg}");
        }

        private static (MemoryHandle, int) GetSocketAddress(EndPoint? endPoint)
        {
            Memory<byte>? buf = endPoint?.Serialize().Buffer;
            return buf is null ? default : (buf.Value.Pin(), buf.Value.Length);
        }

        public unsafe static Conn* Connect(Socket socket, EndPoint remoteEndPoint,
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
                    return NativeMethods.quiche_connect(hostnamePtr,
                        scidPtr, (nuint)scidBuf.Length,
                        (sockaddr*)local.Pointer, local_len,
                        (sockaddr*)remote.Pointer, remote_len,
                        config.NativePtr);
                }
            }
        }

        private const int HEADER_LENGTH = 5;

        private static H3Header[] ConstructHeaders()
        {
            string urlScheme = "https"; // Replace with your URL scheme
            string urlPath = "/"; // Replace with your URL path

            H3Header[] headers =
            [
                Create(":method", "GET"),
                Create(":scheme", urlScheme),
                Create(":authority", Hostname),
                Create(":path", urlPath),
                Create("user-agent", "quiche"),
            ];

            return headers;
        }

        public static H3Header Create(string name, string value)
        {
            H3Header header = new();

            byte[] nameBytes = Encoding.UTF8.GetBytes(name);
            byte[] valueBytes = Encoding.UTF8.GetBytes(value);

            fixed (byte* namePtr = nameBytes, valuePtr = valueBytes)
            {
                header.name = namePtr;
                header.name_len = (nuint)nameBytes.Length;
                header.value = valuePtr;
                header.value_len = (nuint)valueBytes.Length;
            }

            return header;
        }

        private static void EnableDebugLogging()
        {
            var callback = new OnQuicheLogCallback(OnQuicheLog);
            _logCallbackHandle = GCHandle.Alloc(callback);
            var pCallback = (delegate* unmanaged[Cdecl]<byte*, void*, void>)(void*)Marshal.GetFunctionPointerForDelegate(callback);
            int debugLog = NativeMethods.quiche_enable_debug_logging(pCallback, null);

            Debug($"Enable Debug Logging isSucess: {debugLog == 0}");
        }

        private static void Debug(string message)
        {
            Console.WriteLine(message);
        }
    }
}
