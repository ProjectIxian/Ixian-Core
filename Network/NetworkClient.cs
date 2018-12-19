using DLT.Meta;
using DLT.Network;
using System;
using System.Net.Sockets;

namespace DLT
{
    public class NetworkClient : RemoteEndpoint
    {
        public TcpClient tcpClient = null;

        public long timeDifference = 0;


        private string tcpHostname = "";
        private int tcpPort = 0;
        private int totalReconnects = 0;

        private object reconnectLock = new object();

        public NetworkClient()
        {
            prepareClient();
        }

        // Prepare the client socket
        private void prepareClient()
        {
            tcpClient = new TcpClient();


            Socket tmpSocket = tcpClient.Client;

            // Don't allow another socket to bind to this port.
            tmpSocket.ExclusiveAddressUse = true;

            prepareSocket(tmpSocket);
        }

        public bool connectToServer(string hostname, int port)
        {
            if (fullyStopped)
            {
                Logging.error("Can't start a fully stopped RemoteEndpoint");
                return false;
            }

            helloReceived = false;
            blockHeight = 0;

            tcpHostname = hostname;
            tcpPort = port;
            address = string.Format("{0}:{1}", hostname, port);
            incomingPort = port;

            // Prepare the TCP client
            prepareClient();

            try
            {
                totalReconnects++;
                tcpClient.Connect(hostname, port);
            }
            catch (SocketException se)
            {
                SocketError errorCode = (SocketError)se.ErrorCode;

                switch (errorCode)
                {
                    case SocketError.IsConnected:
                        break;

                    case SocketError.AddressAlreadyInUse:
                        Logging.warn(string.Format("Socket exception for {0}:{1} has failed. Address already in use.", hostname, port));
                        break;

                    default:
                        {
                            Logging.warn(string.Format("Socket connection for {0}:{1} has failed.", hostname, port));
                        }
                        break;
                }

                disconnect();

                running = false;
                return false;
            }
            catch (Exception)
            {
                Logging.warn(string.Format("Network client connection to {0}:{1} has failed.", hostname, port));
                running = false;
                return false;
            }

            Logging.info(string.Format("Network client connected to {0}:{1}", hostname, port));

            start(tcpClient.Client);
            return true;
        }

        // Reconnect with the previous settings
        public bool reconnect()
        {
            lock (reconnectLock)
            {
                if (tcpHostname.Length < 1)
                {
                    Logging.warn("Network client reconnect failed due to invalid hostname.");
                    return false;
                }

                // Safely close the threads
                running = false;

                disconnect();

                Logging.info(string.Format("--> Reconnecting to {0}, total reconnects: {1}", getFullAddress(true), totalReconnects));
                return connectToServer(tcpHostname, tcpPort);
            }
        }

        // Receive thread
        protected override void recvLoop()
        {
            ProtocolMessage.sendHelloMessage(this, false);

            base.recvLoop();
        }

        public override void disconnect()
        {
            base.disconnect();
            tcpClient.Close();
        }

        // Returns the number of failed reconnects
        public int getTotalReconnectsCount()
        {
            return totalReconnects;
        }
    }

}
