using Quiche;
using Quiche.NET;
using System.Buffers;
using System.Collections;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace QuichePlaygroundLibrary
{
    internal unsafe class Program
    {
        private const string QUICHE_H3_APPLICATION_PROTOCOL = "\x02h3";
        private const int MAX_DATAGRAM_SIZE = 1350;

        private static void EnableDebugLogging()
        {
            var callback = new OnQuicheLogCallback(OnQuicheLog);
            callbackHandle = GCHandle.Alloc(callback);
            var pCallback = (delegate* unmanaged[Cdecl]<byte*, void*, void>)(void*)Marshal.GetFunctionPointerForDelegate(callback);
            int debugLog = NativeMethods.quiche_enable_debug_logging(pCallback, null);

            Console.WriteLine($"isDebugLogEnabled {debugLog == 0}");
        }

        static void Main(string[] args)
        {
            //EnableDebugLogging();

            QuicheConfig config = new QuicheConfig();
            config.ShouldVerifyPeer = false;
            config.SetApplicationProtocols(QUICHE_H3_APPLICATION_PROTOCOL);
            config.MaxIdleTimeout = 5000;
            config.MaxReceiveUdpPayloadSize = MAX_DATAGRAM_SIZE;
            config.MaxSendUdpPayloadSize = MAX_DATAGRAM_SIZE;

            config.MaxInitialDataSize = 10_000_000;

            config.MaxInitialLocalBidiStreamDataSize = 1_000_000;
            config.MaxInitialRemoteBidiStreamDataSize = 1_000_000;
            config.MaxInitialUniStreamDataSize = 1_000_000;

            config.MaxInitialBidiStreams = 100;
            config.MaxInitialUniStreams = 100;
            config.IsActiveMigrationDisabled = true;

            string hostname = "google.com";

            // Local

            UdpClient udpClient = new UdpClient(0, AddressFamily.InterNetwork);

            Socket client = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            client.Bind(new IPEndPoint(IPAddress.Any, 0));

            // Remote
            IPHostEntry remoteHost = Dns.GetHostEntry(hostname);
            IPAddress remoteIpAddress = remoteHost.AddressList[0];
            IPEndPoint remoteEndPoint = new IPEndPoint(remoteIpAddress, 443);

            byte[] buffer = new byte[65535];
            byte* bufferPtr = (byte*)Marshal.UnsafeAddrOfPinnedArrayElement(buffer, 0);

            byte[] outBuffer = new byte[MAX_DATAGRAM_SIZE];
            byte* outBufferPtr = (byte*)Marshal.UnsafeAddrOfPinnedArrayElement(outBuffer, 0);

            Conn* connection = Connect(client, remoteEndPoint, config, hostname);

            SendInfo sendInfo = new SendInfo();

            Debug($"bufferPtr: {(IntPtr)bufferPtr} outBufferPtr: {(IntPtr)outBufferPtr}");
            Debug($"Connecting to: {remoteEndPoint} from: {client.LocalEndPoint}");

            nint result = SendOnPath(connection, client, remoteEndPoint, outBufferPtr, (nuint)outBuffer.Length, &sendInfo);

            Debug($"Send on Path result: {result} sendInfoFromLen: {sendInfo.to.ss_family}");

            client.SendTo(outBuffer, 0, (int)result, SocketFlags.None, remoteEndPoint);

            while (true)
            {
                Console.WriteLine($"Is Established: {connection->IsEstablished()}");
                Thread.Sleep(500);
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
