using DLT.Meta;
using DLT.Network;
using IXICore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace DLT
{
    class NetworkClientManager
    {
        public static List<NetworkClient> networkClients = new List<NetworkClient>();
        private static List<string> connectingClients = new List<string>(); // A list of clients that we're currently connecting

        private static Thread reconnectThread;
        private static bool autoReconnect = true;

        private static bool running = false;
        private static ThreadLiveCheck TLC;

        // Starts the Network Client Manager. First it connects to one of the seed nodes in order to fetch the Presence List.
        // Afterwards, it starts the reconnect and keepalive threads
        public static void start()
        {
            if(running)
            {
                return;
            }
            running = true;
            networkClients = new List<NetworkClient>();

            PeerStorage.readPeersFile();

            // Now add the seed nodes to the list
            foreach (string addr in CoreNetworkUtils.getSeedNodes(Config.isTestNet))
            {
                PeerStorage.addPeerToPeerList(addr, null, false);
            }

            // Connect to a random node first
            bool firstSeedConnected = false;
            while (firstSeedConnected == false)
            {
                string address = PeerStorage.getRandomMasterNodeAddress();
                if (address != "")
                {
                    firstSeedConnected = connectTo(address);
                }
                if (firstSeedConnected == false)
                {
                    Thread.Sleep(1000);
                }
            }

            // Start the reconnect thread
            TLC = new ThreadLiveCheck();
            reconnectThread = new Thread(reconnectClients);
            reconnectThread.Name = "Network_Client_Manager_Reconnect";
            autoReconnect = true;
            reconnectThread.Start();
        }

        public static void stop()
        {
            if(!running)
            {
                return;
            }
            running = false;
            autoReconnect = false;
            isolate();

            // Force stopping of reconnect thread
            if (reconnectThread == null)
                return;
            reconnectThread.Abort();
            reconnectThread = null;
        }

        // Immediately disconnects all clients
        public static void isolate()
        {
            Logging.info("Isolating network clients...");

            lock (networkClients)
            {
                // Disconnect each client
                foreach (NetworkClient client in networkClients)
                {
                    client.stop();
                }

                // Empty the client list
                networkClients.Clear();
            }
        }

        // Reconnects to network clients
        public static void restartClients()
        {
            Logging.info("Stopping network clients...");
            stop();
            Thread.Sleep(100);
            Logging.info("Starting network clients...");
            start();
        }

        // Connects to a specified node, with the syntax host:port
        public static bool connectTo(string host)
        {
            if (host == null || host.Length < 3)
            {
                Logging.error(String.Format("Invalid host address {0}", host));
                return false;
            }

            string[] server = host.Split(':');
            if (server.Count() < 2)
            {
                Logging.warn(string.Format("Cannot connect to invalid hostname: {0}", host));
                return false;
            }

            // Resolve the hostname first
            string resolved_server_name = NetworkUtils.resolveHostname(server[0]);

            // Skip hostnames we can't resolve
            if (resolved_server_name.Length < 1)
            {
                Logging.warn(string.Format("Cannot resolve IP for {0}, skipping connection.", server[0]));
                return false;
            }

            string resolved_host = string.Format("{0}:{1}", resolved_server_name, server[1]);

            // Verify against the publicly disclosed ip
            // Don't connect to self
            if (resolved_server_name.Equals(Config.publicServerIP, StringComparison.Ordinal))
            {
                if (server[1].Equals(string.Format("{0}", Config.serverPort), StringComparison.Ordinal))
                {
                    Logging.info(string.Format("Skipping connection to public self seed node {0}", host));
                    return false;
                }
            }

            // Get all self addresses and run through them
            List<string> self_addresses = CoreNetworkUtils.GetAllLocalIPAddresses();
            foreach (string self_address in self_addresses)
            {
                // Don't connect to self
                if (resolved_server_name.Equals(self_address, StringComparison.Ordinal))
                {
                    if (server[1].Equals(string.Format("{0}", Config.serverPort), StringComparison.Ordinal))
                    {
                        Logging.info(string.Format("Skipping connection to self seed node {0}", host));
                        return false;
                    }
                }
            }

            lock (connectingClients)
            {
                foreach (string client in connectingClients)
                {
                    if (resolved_host.Equals(client, StringComparison.Ordinal))
                    {
                        // We're already connecting to this client
                        return false;
                    }
                }

                // The the client to the connecting clients list
                connectingClients.Add(resolved_host);
            }

            // Check if node is already in the client list
            lock (networkClients)
            {
                foreach (NetworkClient client in networkClients)
                {
                    if (client.getFullAddress(true).Equals(resolved_host, StringComparison.Ordinal))
                    {
                        // Address is already in the client list
                        return false;
                    }
                }
            }

            // Check if node is already in the server list
            string[] connectedClients = NetworkServer.getConnectedClients(true);
            for (int i = 0; i < connectedClients.Length; i++)
            {
                if (connectedClients[i].Equals(resolved_host, StringComparison.Ordinal))
                {
                    // Address is already in the client list
                    return false;
                }
            }

            // Connect to the specified node
            NetworkClient new_client = new NetworkClient();
            // Recompose the connection address from the resolved IP and the original port
            bool result = new_client.connectToServer(resolved_server_name, Convert.ToInt32(server[1]));

            // Add this node to the client list if connection was successfull
            if (result == true)
            {
                // Add this node to the client list
                lock (networkClients)
                {
                    networkClients.Add(new_client);
                }

            }

            // Remove this node from the connecting clients list
            lock (connectingClients)
            {
                connectingClients.Remove(resolved_host);
            }

            return result;
        }

        // Send data to all connected nodes
        // Returns true if the data was sent to at least one client
        public static bool broadcastData(char[] types, ProtocolMessageCode code, byte[] data, byte[] helper_data, RemoteEndpoint skipEndpoint = null)
        {
            bool result = false;
            lock (networkClients)
            {
                foreach (NetworkClient client in networkClients)
                {
                    if (skipEndpoint != null)
                    {
                        if (client == skipEndpoint)
                            continue;
                    }

                    if (!client.isConnected())
                    {
                        continue;
                    }

                    if (client.helloReceived == false)
                    {
                        continue;
                    }

                    if (types != null)
                    {
                        if (client.presenceAddress == null || !types.Contains(client.presenceAddress.type))
                        {
                            continue;
                        }
                    }


                    client.sendData(code, data, helper_data);
                    result = true;
                }
            }
            return result;
        }

        public static bool sendToClient(string neighbor, ProtocolMessageCode code, byte[] data, byte[] helper_data)
        {
            NetworkClient client = null;
            lock (networkClients)
            {
                foreach (NetworkClient c in networkClients)
                {
                    if (c.getFullAddress() == neighbor)
                    {
                        client = c;
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
        public static string[] getConnectedClients()
        {
            List<String> result = new List<String>();

            lock (networkClients)
            {
                foreach (NetworkClient client in networkClients)
                {
                    if (client.isConnected())
                    {
                        try
                        {
                            string client_name = client.getFullAddress();
                            result.Add(client_name);
                        }
                        catch (Exception e)
                        {
                            Logging.warn(string.Format("NetworkClientManager->getConnectedClients: {0}", e.ToString()));
                        }
                    }
                }
            }

            return result.ToArray();
        }


        public static void recalculateLocalTimeDifference()
        {
            if(Config.forceTimeOffset != int.MaxValue)
            {
                Core.networkTimeDifference = Config.forceTimeOffset;
                return;
            }
            lock (networkClients)
            {
                if (networkClients.Count < 1)
                    return;

                long totalTimeDiff = 0;

                int client_count = 0;

                foreach (NetworkClient client in networkClients)
                {
                    if (client.helloReceived && client.timeSyncComplete)
                    {
                        totalTimeDiff += client.timeDifference;
                        client_count++;
                    }
                }

                long timeDiff = totalTimeDiff / client_count;

                // amortize +- 2 seconds
                if (timeDiff >= -2 && timeDiff <= 2)
                {
                    timeDiff = 0;
                }

                Core.networkTimeDifference = timeDiff;
            }
        }


        // Returns a random new potential neighbor. Returns null if no new neighbor is found.
        public static string scanForNeighbor()
        {
            string connectToAddress = null;
            // Find only masternodes
            while (connectToAddress == null)
            {
                bool addr_valid = true;
                string address = PeerStorage.getRandomMasterNodeAddress();

                if (address == "")
                {
                    break;
                }

                // Next, check if we're connecting to a self address of this node
                string[] server = address.Split(':');

                if (server.Length < 2)
                {
                    break;
                }

                // Resolve the hostname first
                string resolved_server_name = NetworkUtils.resolveHostname(server[0]);
                string resolved_server_name_with_port = resolved_server_name + ":" + server[1];

                // Check if we are already connected to this address
                lock (networkClients)
                {
                    foreach (NetworkClient client in networkClients)
                    {
                        if (client.getFullAddress(true).Equals(resolved_server_name_with_port, StringComparison.Ordinal))
                        {
                            // Address is already in the client list
                            addr_valid = false;
                            break;
                        }
                    }
                }

                // Check if node is already in the server list
                string[] connectedClients = NetworkServer.getConnectedClients(true);
                for (int i = 0; i < connectedClients.Length; i++)
                {
                    if (connectedClients[i].Equals(resolved_server_name_with_port, StringComparison.Ordinal))
                    {
                        // Address is already in the client list
                        addr_valid = false;
                        break;
                    }
                }

                if (addr_valid == false)
                    continue;

                // Check against connecting clients list as well
                lock (connectingClients)
                {
                    foreach (string client in connectingClients)
                    {
                        if (resolved_server_name_with_port.Equals(client, StringComparison.Ordinal))
                        {
                            // Address is already in the connecting client list
                            addr_valid = false;
                            break;
                        }
                    }

                }

                if (addr_valid == false)
                    continue;

                // Get all self addresses and run through them
                List<string> self_addresses = CoreNetworkUtils.GetAllLocalIPAddresses();
                foreach (string self_address in self_addresses)
                {
                    // Don't connect to self
                    if (resolved_server_name.Equals(self_address, StringComparison.Ordinal))
                    {
                        if (server[1].Equals(string.Format("{0}", Config.serverPort), StringComparison.Ordinal))
                        {
                            addr_valid = false;
                        }
                    }
                }

                // If the address is valid, add it to the candidates
                if (addr_valid)
                {
                    connectToAddress = address;
                }
            }

            return connectToAddress;
        }

        // Scan for and connect to a new neighbor
        private static void connectToRandomNeighbor()
        {
            string neighbor = scanForNeighbor();
            if (neighbor != null)
            {
                Logging.info(string.Format("Attempting to add new neighbor: {0}", neighbor));
                connectTo(neighbor);
            }
        }

        // Checks for missing clients
        private static void reconnectClients()
        {
            Random rnd = new Random();

            // Wait 5 seconds before starting the loop
            Thread.Sleep(CoreConfig.networkClientReconnectInterval);

            while (autoReconnect)
            {
                TLC.Report();
                handleDisconnectedClients();

                // Check if we need to connect to more neighbors
                if (getConnectedClients().Count() < CoreConfig.simultaneousConnectedNeighbors)
                {
                    // Scan for and connect to a new neighbor
                    connectToRandomNeighbor();
                }
                else if (getConnectedClients().Count() > CoreConfig.simultaneousConnectedNeighbors)
                {
                    List<NetworkClient> netClients = null;
                    lock (networkClients)
                    {
                        netClients = new List<NetworkClient>(networkClients);
                    }
                    CoreProtocolMessage.sendBye(netClients[0], ProtocolByeCode.bye, "Disconnected for shuffling purposes.", "", false);

                    lock (networkClients)
                    {
                        networkClients.Remove(netClients[0]);
                    }
                }

                // Connect randomly to a new node. Currently a 1% chance to reconnect during this iteration
                if (rnd.Next(100) == 1)
                {
                    connectToRandomNeighbor();
                }

                // Wait 5 seconds before rechecking
                Thread.Sleep(CoreConfig.networkClientReconnectInterval);
            }
        }

        private static void handleDisconnectedClients()
        {
            List<NetworkClient> netClients = null;
            lock (networkClients)
            {
                netClients = new List<NetworkClient>(networkClients);
            }

            // Prepare a list of failed clients
            List<NetworkClient> failed_clients = new List<NetworkClient>();

            List<NetworkClient> dup_clients = new List<NetworkClient>();

            foreach (NetworkClient client in netClients)
            {
                if (dup_clients.Find(x => x.getFullAddress(true) == client.getFullAddress(true)) != null)
                {
                    failed_clients.Add(client);
                    continue;
                }
                dup_clients.Add(client);
                if (client.isConnected())
                {
                    continue;
                }
                // Check if we exceeded the maximum reconnect count
                if (client.getTotalReconnectsCount() >= CoreConfig.maximumNeighborReconnectCount || client.fullyStopped)
                {
                    // Remove this client so we can search for a new neighbor
                    failed_clients.Add(client);
                }
                else
                {
                    // Reconnect
                    client.reconnect();
                }
            }

            // Go through the list of failed clients and remove them
            foreach (NetworkClient client in failed_clients)
            {
                client.stop();
                lock (networkClients)
                {
                    networkClients.Remove(client);
                }
            }
        }


        public static int getQueuedMessageCount()
        {
            int messageCount = 0;
            lock (networkClients)
            {
                foreach (NetworkClient client in networkClients)
                {
                    messageCount += client.getQueuedMessageCount();
                }
            }
            return messageCount;
        }

        public static NetworkClient getClient(int idx)
        {
            lock (networkClients)
            {
                int i = 0;
                NetworkClient lastClient = null;
                foreach(NetworkClient client in networkClients)
                {
                    if(client.isConnected())
                    {
                        lastClient = client;
                    }
                    if(i == idx && lastClient != null)
                    {
                        break;
                    }
                    i++;
                }
                return lastClient;
            }
        }
    }
}
