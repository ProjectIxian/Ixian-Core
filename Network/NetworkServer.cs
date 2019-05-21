using System;
using System.Collections.Generic;
using System.Threading;
using System.Net;
using System.Net.Sockets;
using DLT.Meta;
using System.Linq;
using IXICore;

namespace DLT
{
    namespace Network
    {
        public struct NetOpsData
        {
            public IPEndPoint listenAddress;
        }

        public class NetworkServer
        {
            public static string publicIPAddress = "127.0.0.1";


            private static bool continueRunning = false;
            private static Thread netControllerThread = null;
            private static TcpListener listener;
            public static List<RemoteEndpoint> connectedClients = new List<RemoteEndpoint>();

            private static Dictionary<string, DateTime> nodeBlacklist = new Dictionary<string, DateTime>();
            private static ThreadLiveCheck TLC;

            private static DateTime lastIncomingConnectionTime = DateTime.UtcNow;
            public static bool connectable = true;

            static NetworkServer()
            {
            }

            private NetworkServer()
            {
            }

            public static void beginNetworkOperations()
            {
                if (netControllerThread != null)
                {
                    // already running
                    Logging.info("Network server thread is already running.");
                    return;
                }

                TLC = new ThreadLiveCheck();
                netControllerThread = new Thread(networkOpsLoop);
                netControllerThread.Name = "Network_Server_Controller_Thread";
                connectedClients = new List<RemoteEndpoint>();
                continueRunning = true;

                // Read the server port from the configuration
                NetOpsData nod = new NetOpsData();
                nod.listenAddress = new IPEndPoint(IPAddress.Any, Config.serverPort);
                netControllerThread.Start(nod);

                // Retrieve the public-accessible IP address
                publicIPAddress = Config.publicServerIP; // CoreNetworkUtils.GetLocalIPAddress();


                Logging.info(string.Format("Public network node address: {0} port {1}", publicIPAddress, Config.serverPort));

            }

            public static void stopNetworkOperations()
            {
                if (netControllerThread == null)
                {
                    // not running
                    Logging.info("Network server thread was already halted.");
                    return;
                }
                continueRunning = false;

                netControllerThread.Abort();
                netControllerThread = null;

                // Close blocking socket
                listener.Stop();

                Logging.info("Closing network server connected clients");
                // Clear all clients
                lock (connectedClients)
                {
                    // Immediately close all connected client sockets
                    foreach (RemoteEndpoint client in connectedClients)
                    {
                        client.stop();
                    }

                    connectedClients.Clear();
                }
            }

            public static void handleDisconnectedClients()
            {
                List<RemoteEndpoint> netClients = null;
                lock (connectedClients)
                {
                    netClients = new List<RemoteEndpoint>(connectedClients);
                }

                // Prepare a list of failed clients
                List<RemoteEndpoint> failed_clients = new List<RemoteEndpoint>();

                foreach (RemoteEndpoint client in netClients)
                {
                    if (client.isConnected())
                    {
                        continue;
                    }
                    failed_clients.Add(client);
                }

                // Go through the list of failed clients and remove them
                foreach (RemoteEndpoint client in failed_clients)
                {
                    client.stop();
                    lock (connectedClients)
                    {
                        // Remove this endpoint from the network server
                        connectedClients.Remove(client);
                    }
                }
            }

            // Restart the network server
            public static void restartNetworkOperations()
            {
                Logging.info("Stopping network server...");
                stopNetworkOperations();
                Thread.Sleep(1000);
                Logging.info("Restarting network server...");
                beginNetworkOperations();
            }

            private static void networkOpsLoop(object data)
            {
                if (data is NetOpsData)
                {
                    try
                    {
                        NetOpsData netOpsData = (NetOpsData)data;
                        listener = new TcpListener(netOpsData.listenAddress);
                        listener.Start();
                    }
                    catch (Exception e)
                    {
                        Logging.error(string.Format("Exception starting server: {0}", e.ToString()));
                        return;
                    }
                }
                else
                {
                    Logging.error(String.Format("NetworkServer.networkOpsLoop called with incorrect data object. Expected 'NetOpsData', got '{0}'", data.GetType().ToString()));
                    return;
                }
                // housekeeping tasks
                while (continueRunning)
                {
                    TLC.Report();
                    handleDisconnectedClients();
                    // Use a blocking mechanism
                    try
                    {
                        Socket handlerSocket = listener.AcceptSocket();
                        acceptConnection(handlerSocket);
                    }
                    catch (SocketException)
                    {
                        // Could be an interupt request
                    }
                    catch (Exception)
                    {
                        if (continueRunning)
                        {
                            Logging.error("Exception occured in network server while trying to accept socket connection.");
                            restartNetworkOperations();
                        }
                        return;
                    }

                    // Sleep to prevent cpu usage
                    Thread.Sleep(100);

                }
                Logging.info("Server listener thread ended.");
            }

            // Send data to all connected clients
            // Returns true if the data was sent to at least one client
            public static bool broadcastData(char[] types, ProtocolMessageCode code, byte[] data, byte[] helper_data, RemoteEndpoint skipEndpoint = null)
            {
                bool result = false;
                lock (connectedClients)
                {
                    foreach (RemoteEndpoint endpoint in connectedClients)
                    {
                        if (skipEndpoint != null)
                        {
                            if (endpoint == skipEndpoint)
                                continue;
                        }

                        if (!endpoint.isConnected())
                        {
                            continue;
                        }

                        if (endpoint.helloReceived == false)
                        {
                            continue;
                        }

                        if (types != null)
                        {
                            if (endpoint.presenceAddress == null || !types.Contains(endpoint.presenceAddress.type))
                            {
                                continue;
                            }
                        }

                        endpoint.sendData(code, data, helper_data);
                        result = true;
                    }
                }
                return result;
            }

            // Sends event data to all subscribed clients
            public static bool broadcastEventData(NetworkEvents.Type type, ProtocolMessageCode code, byte[] data, byte[] address, byte[] helper_data, RemoteEndpoint skipEndpoint = null)
            {
                bool result = false;
                lock (connectedClients)
                {
                    foreach (RemoteEndpoint endpoint in connectedClients)
                    {
                        if (skipEndpoint != null)
                        {
                            if (endpoint == skipEndpoint)
                                continue;
                        }

                        if (!endpoint.isConnected())
                        {
                            continue;
                        }

                        if (endpoint.helloReceived == false)
                        {
                            continue;
                        }

                        if (endpoint.presenceAddress == null || endpoint.presenceAddress.type != 'C')
                        {
                            continue;
                        }

                        // Finally, check if the endpoint is subscribed to this event and address
                        if (endpoint.isSubscribedToEvent(type, address))
                        {
                            endpoint.sendData(code, data, helper_data);
                            result = true;
                        }
                    }
                }
                return result;
            }


            // Forwards a network message to a specific presense address if it's in the client list
            public static bool forwardMessage(byte[] address, ProtocolMessageCode code, byte[] message)
            {
                if (address == null)
                {
                    Logging.warn("Cannot forward message to null address.");
                    return false;
                }

                Logging.info(String.Format(">>>> Preparing to forward to {0}",
                    Base58Check.Base58CheckEncoding.EncodePlain(address)));

                lock (connectedClients)
                {
                    foreach (RemoteEndpoint endpoint in connectedClients)
                    {
                        // Skip connections without presence information
                        if (endpoint.presence == null)
                            continue;

                        byte[] client_wallet = endpoint.presence.wallet;

                        if (client_wallet != null && address.SequenceEqual(client_wallet))
                        {
                            Logging.info(">>>> Forwarding message");
                            endpoint.sendData(code, message);

                        }

                    }
                }

                // TODO: broadcast to network if no connect clients found?

                return false;
            }


            public static bool sendToClient(string neighbor, ProtocolMessageCode code, byte[] data, byte[] helper_data)
            {
                RemoteEndpoint client = null;
                lock (connectedClients)
                {
                    foreach (RemoteEndpoint ep in connectedClients)
                    {
                        if (ep.getFullAddress() == neighbor)
                        {
                            client = ep;
                            break;
                        }
                    }
                }
                if (client != null)
                {
                    client.sendData(code, data, helper_data);
                    return true;
                }
                return false;
            }

            // Returns all the connected clients
            public static string[] getConnectedClients(bool useIncomingPort = false)
            {
                List<String> result = new List<String>();

                lock (connectedClients)
                {
                    foreach (RemoteEndpoint client in connectedClients)
                    {
                        if (client.isConnected())
                        {
                            try
                            {
                                string client_name = client.getFullAddress(useIncomingPort);
                                result.Add(client_name);
                            }
                            catch (Exception e)
                            {
                                Logging.warn(string.Format("NetworkServer->getConnectedClients: {0}", e.ToString()));
                            }
                        }
                    }
                }

                return result.ToArray();
            }

            private static void acceptConnection(Socket clientSocket)
            {
                IPEndPoint clientEndpoint = (IPEndPoint)clientSocket.RemoteEndPoint;
                // Add timeouts and set socket options
                //clientSocket.ReceiveTimeout = 5000;
                //clientSocket.SendTimeout = 5000;
                clientSocket.LingerState = new LingerOption(true, 3);
                clientSocket.NoDelay = true;
                clientSocket.Blocking = true;

                if (!Node.isAcceptingConnections())
                {
                    Thread.Sleep(100); // wait a bit for check connectivity purposes
                    clientSocket.Send(CoreProtocolMessage.prepareProtocolMessage(ProtocolMessageCode.bye, new byte[1]));
                    clientSocket.Shutdown(SocketShutdown.Both);
                    clientSocket.Disconnect(true);
                    return;
                }

                lastIncomingConnectionTime = DateTime.UtcNow;
                connectable = true;

                // Setup the remote endpoint
                RemoteEndpoint remoteEndpoint = new RemoteEndpoint();

                lock (connectedClients)
                {
                    if (connectedClients.Count + 1 > CoreConfig.maximumServerMasterNodes)
                    {
                        Logging.warn(string.Format("Maximum number of connected clients reached. Disconnecting client: {0}:{1}",
                            clientEndpoint.Address.ToString(), clientEndpoint.Port));
                        clientSocket.Send(CoreProtocolMessage.prepareProtocolMessage(ProtocolMessageCode.bye, new byte[1]));
                        clientSocket.Shutdown(SocketShutdown.Both);
                        clientSocket.Disconnect(true);
                        return;
                    }

                    var existing_clients = connectedClients.Where(re => re.remoteIP.Address == clientEndpoint.Address);
                    if (existing_clients.Count() > 0)
                    {
                        Logging.warn(String.Format("Client {0}:{1} already connected as {2}.",
                            clientEndpoint.Address.ToString(), clientEndpoint.Port, existing_clients.First().ToString()));
                        clientSocket.Send(CoreProtocolMessage.prepareProtocolMessage(ProtocolMessageCode.bye, new byte[1]));
                        clientSocket.Shutdown(SocketShutdown.Both);
                        clientSocket.Disconnect(true);
                        return;
                    }

                    connectedClients.Add(remoteEndpoint);

                    Logging.info(String.Format("Client connection accepted: {0} | #{1}/{2}", clientEndpoint.ToString(), connectedClients.Count + 1, CoreConfig.maximumServerMasterNodes));

                    remoteEndpoint.start(clientSocket);
                }
            }

            // Removes an endpoint from the connected clients list
            public static bool removeEndpoint(RemoteEndpoint endpoint)
            {
                bool result = false;
                lock (connectedClients)
                {
                    result = connectedClients.Remove(endpoint);
                }
                return result;
            }

            public static int getQueuedMessageCount()
            {
                int messageCount = 0;
                lock (connectedClients)
                {
                    foreach (RemoteEndpoint client in connectedClients)
                    {
                        messageCount += client.getQueuedMessageCount();
                    }
                }
                return messageCount;
            }

            public static RemoteEndpoint getClient(int idx)
            {
                lock (connectedClients)
                {
                    int i = 0;
                    RemoteEndpoint lastClient = null;
                    foreach (RemoteEndpoint client in connectedClients)
                    {
                        if (client.isConnected())
                        {
                            lastClient = client;
                        }
                        if (i == idx && lastClient != null)
                        {
                            break;
                        }
                        i++;
                    }
                    return lastClient;
                }
            }


            // Adds a node to the blacklist
            public static void blacklistNode(string ip)
            {
                lock (nodeBlacklist)
                {
                    nodeBlacklist.AddOrReplace(ip, DateTime.UtcNow);
                }
            }

            // Returns true if node is blacklisted
            // TODO TODO TODO TODO blacklist by IP or wallet address or both?
            public static bool isNodeBlacklisted(string ip)
            {
                lock (nodeBlacklist)
                {
                    if (nodeBlacklist.ContainsKey(ip))
                    {
                        DateTime dt = nodeBlacklist[ip];
                        if ((DateTime.UtcNow - dt).TotalSeconds > 600)
                        {
                            nodeBlacklist.Remove(ip);
                        }
                        return true;
                    }
                }
                return false;
            }

            // Check if the server is running
            public static bool isRunning()
            {
                return continueRunning;
            }

            static public bool isConnectable()
            {
                if (getConnectedClients().Count() > 0)
                {
                    return true;
                }

                if ((DateTime.UtcNow - lastIncomingConnectionTime).TotalSeconds < 300) // if somebody connected within 5 minutes the node is probably connectable
                {
                    return true;
                }

                return connectable;
            }
        }
    }
}
