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

namespace QuichePlaygroundLibrary
{
    internal unsafe class Program
    {
        private const string QUICHE_H3_APPLICATION_PROTOCOL = "h3";
        private const int MAX_DATAGRAM_SIZE = 1350;

        private static void EnableDebugLogging()
        {
            var callback = new OnQuicheLogCallback(OnQuicheLog);
            callbackHandle = GCHandle.Alloc(callback);
            var pCallback = (delegate* unmanaged[Cdecl]<byte*, void*, void>)(void*)Marshal.GetFunctionPointerForDelegate(callback);
            int debugLog = NativeMethods.quiche_enable_debug_logging(pCallback, null);

            Console.WriteLine($"isDebugLogEnabled {debugLog == 0}");
        }

        private static Conn* _connection;
        private static QuicheConfig _config;

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

        private static byte[] buffer;
        private static byte* bufferPtr;

        private static byte[] outBuffer;
        private static byte* outBufferPtr;

        private static Socket _client;
        private static IPEndPoint _remoteEndPoint;
        private const string Hostname = "google.com";

        private static void ConstructBuffer()
        {
            buffer = new byte[65535];
            outBuffer = new byte[MAX_DATAGRAM_SIZE];
            bufferPtr = (byte*)Marshal.UnsafeAddrOfPinnedArrayElement(buffer, 0);
            outBufferPtr = (byte*)Marshal.UnsafeAddrOfPinnedArrayElement(outBuffer, 0);
        }

        static void Main(string[] args)
        {
            //EnableDebugLogging();

            ConstructBuffer();
            CreateConfig();
            ConstructPeers();

            _connection = Connect(_client, _remoteEndPoint, _config, Hostname);

            Debug($"Initial - Connecting to: {_remoteEndPoint} from: {_client.LocalEndPoint}");

            SendInfo sendInfo = new SendInfo();
            //nint result = SendOnPath(_connection, _client, _remoteEndPoint, outBufferPtr, (nuint)outBuffer.Length, &sendInfo);

            nint write = _connection->Send(outBufferPtr, (nuint)outBuffer.Length, &sendInfo);
            int r = _client.SendTo(outBuffer, (int)write, SocketFlags.None, _remoteEndPoint);

            Debug($"Initial - Write: {write}");

            //Thread outgoingPackets = new Thread(new ThreadStart(WriteLoop));
            //outgoingPackets.Start();

            //Console.ReadKey();

            Thread readLoop = new Thread(new ThreadStart(ReadLoop));
            readLoop.Start();

            Console.ReadKey();
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
            var (local, local_len) = GetSocketAddress(_client.LocalEndPoint);
            RecvInfo recvInfo = new RecvInfo();
            recvInfo.to_len = local_len;
            recvInfo.to = (sockaddr*)local.Pointer;

            while (true)
            {
                Thread.Sleep(1000);
                Console.WriteLine($"ReadLoop isClosed: {_connection->IsClosed()}");
                EndPoint ep = _remoteEndPoint;

                Console.WriteLine($"ReadLoop - Socket Receiving...");
                int resultOrError = _client.Receive(buffer);
                Console.WriteLine($"ReadLoop Received: {resultOrError}");

                //if (resultOrError < 0)
                //    continue;

                Console.WriteLine($"ReadLoop QUIC Receiving...");
                _connection->Recv(bufferPtr, (nuint)resultOrError, &recvInfo);
                Console.WriteLine($"ReadLoop QUIC Received...");
            }
        }

        private static void WriteLoop()
        {
            while (true)
            {
                SendInfo s = new SendInfo();
                nint write = _connection->Send(outBufferPtr, (nuint)outBuffer.Length, &s);

                Console.WriteLine($"write: {write}");

                if (write < 0)
                {
                    _client.SendTo(outBuffer, 0, (int)write, SocketFlags.None, _remoteEndPoint);
                }

                Thread.Sleep(100);
            }
        }

        private static GCHandle callbackHandle = default;

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void OnQuicheLogCallback(byte* handle, void* context);
        private static unsafe void OnQuicheLog(byte* message, void* argp)
        {
            string msg = Marshal.PtrToStringAnsi((IntPtr)message) ?? string.Empty;
            Console.WriteLine($"OnQuicheLog: {msg}");
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

        internal unsafe static nint SendOnPath(Conn* connection, Socket socket, EndPoint remoteEndPoint, byte* outBuffer, nuint outBufferLength, SendInfo* sendInfo)
        {
            EndPoint localEndPoint = socket.LocalEndPoint ?? throw new ArgumentException(
                "Given socket was not bound to a valid local endpoint!", nameof(socket));

            var (local, local_len) = GetSocketAddress(localEndPoint);
            var (remote, remote_len) = GetSocketAddress(remoteEndPoint);

            using (local)
            using (remote)
            {
                return connection->SendOnPath(outBuffer, outBufferLength, (sockaddr*)local.Pointer, local_len, (sockaddr*)remote.Pointer, remote_len, sendInfo);
            }
        }

        private H3Header[] ConstructHeaders()
        {
            Dictionary<string, string> managedHeaders = new Dictionary<string, string>()
            {
                ["GET"] = "method",
                ["scheme"] = "",
                ["authority"] = "",
                ["path"] = "",
                ["user-agent"] = "quiche",
            };

            H3Header[] headers = new H3Header[managedHeaders.Count];
            int index = 0;

            foreach (var h in managedHeaders)
            {
                H3Header header = new H3Header();
                header.name = (byte*)Marshal.StringToHGlobalAnsi(h.Key);
                header.name_len = (nuint)h.Key.Length;

                header.value = (byte*)Marshal.StringToHGlobalAnsi(h.Value);
                header.value_len = (nuint)h.Value.Length;

                headers[index] = header;
                index++;
            }

            return headers;
        }

        private static void Debug(string message)
        {
            Console.WriteLine(message);
        }
    }
}
