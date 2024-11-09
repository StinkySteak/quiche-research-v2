using Quiche.NET;
using Quiche;
using System.Buffers;
using System.Net.Sockets;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using static Quiche.NativeMethodsGroupingExtensions;

namespace QuichePlaygroundLibrary
{
    internal unsafe class Http3Server
    {
        private const string QUICHE_H3_APPLICATION_PROTOCOL = "h3";
        private const int MAX_DATAGRAM_SIZE = 1350;
        private const int LOCAL_CONN_ID_LEN = 16;

        private static byte[] buffer;
        private static byte* bufferPtr;

        private static byte[] outBuffer;
        private static byte* outBufferPtr;
        private static bool _enableDebugLogging = false;
        private static QuicheConfig _config;
        private static Socket _socket;

        public static void Run()
        {
            ConstructBuffer();

            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            _socket.Bind(new IPEndPoint(IPAddress.Loopback, 4433));

            _config = new QuicheConfig();
            _config.LoadCertificateChainFromPemFile("./cert.crt");
            _config.LoadPrivateKeyFromPemFile("./cert.key");
            _config.SetApplicationProtocols(QUICHE_H3_APPLICATION_PROTOCOL);

            _config.MaxIdleTimeout = 5000;
            _config.MaxReceiveUdpPayloadSize = MAX_DATAGRAM_SIZE;
            _config.MaxSendUdpPayloadSize = MAX_DATAGRAM_SIZE;

            _config.MaxInitialDataSize = 10_000_000;

            _config.MaxInitialLocalBidiStreamDataSize = 1_000_000;
            _config.MaxInitialRemoteBidiStreamDataSize = 1_000_000;
            _config.MaxInitialUniStreamDataSize = 1_000_000;
            // _config.MaxInitialBidiStreams = 1_000_000;

            _config.MaxInitialBidiStreams = 100;
            _config.MaxInitialUniStreams = 100;
            _config.NativePtr->EnableEarlyData();

            H3Config _h3Config = new H3Config();

            Debug($"Polling...");

            while (true)
            {
                bool hasPacket = _socket.Available > 0;

                if (hasPacket)
                    break;
            }

            Debug($"Polled");

            while (true)
            {
                ReadLoop();
            }


        }

        private static void ReadLoop()
        {
            byte type = 0;
            uint version = 0;

            nuint maxIdLength = QuicheLibrary.MAX_CONN_ID_LEN;
            byte* scid = stackalloc byte[QuicheLibrary.MAX_CONN_ID_LEN];
            byte* dcid = stackalloc byte[QuicheLibrary.MAX_CONN_ID_LEN];
            byte* odcid = stackalloc byte[QuicheLibrary.MAX_CONN_ID_LEN];

            nuint tokenLength = (nuint)("quiche").Length;
            byte* token = stackalloc byte[(int)tokenLength];

            while (true)
            {
                Debug($"ReadLoop - Enter");

                int resultOrError = _socket.Receive(buffer);

                Debug($"ReadLoop Received: {resultOrError}");

                bool noMorePacketsToRead = _socket.Available <= 0;

                if (noMorePacketsToRead)
                {
                    Debug("ReadLoop - No more packets to read");
                    break;
                }

                int rc = NativeMethods.quiche_header_info(bufferPtr, (nuint)resultOrError, LOCAL_CONN_ID_LEN, &version, &type, scid, &maxIdLength, dcid, &maxIdLength, token, &tokenLength);

                if (rc < 0)
                {
                    Debug("ReadLoop ");
                }
            }
        }

        private static void ConstructBuffer()
        {
            buffer = new byte[65535];
            outBuffer = new byte[MAX_DATAGRAM_SIZE];
            bufferPtr = (byte*)Marshal.UnsafeAddrOfPinnedArrayElement(buffer, 0);
            outBufferPtr = (byte*)Marshal.UnsafeAddrOfPinnedArrayElement(outBuffer, 0);
        }

        private static void Debug(string message)
        {
            Console.WriteLine(message);
        }
    }

}
