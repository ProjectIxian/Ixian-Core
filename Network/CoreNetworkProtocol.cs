using DLT;
using DLT.Meta;
using DLT.Network;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace IXICore
{
    public class CoreProtocolMessage
    {
        // Returns a specified header checksum
        public static byte getHeaderChecksum(byte[] header)
        {
            byte sum = 0x7F;
            for (int i = 0; i < header.Length; i++)
            {
                sum ^= header[i];
            }
            return sum;
        }

        // Prepare a network protocol message. Works for both client-side and server-side
        public static byte[] prepareProtocolMessage(ProtocolMessageCode code, byte[] data, byte[] checksum = null)
        {
            byte[] result = null;

            // Prepare the protocol sections
            int data_length = data.Length;

            if (data_length > CoreConfig.maxMessageSize)
            {
                Logging.error(String.Format("Tried to send data bigger than max allowed message size - {0} with code {1}.", data_length, code));
                return null;
            }

            byte[] data_checksum = checksum;

            if (checksum == null)
            {
                data_checksum = Crypto.sha512sqTrunc(data, 0, 0, 32);
            }

            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    // Protocol sections are code, length, checksum, data
                    // Write each section in binary, in that specific order
                    writer.Write((byte)'X');
                    writer.Write((int)code);
                    writer.Write(data_length);
                    writer.Write(data_checksum);

                    writer.Flush();
                    m.Flush();

                    byte header_checksum = getHeaderChecksum(m.ToArray());
                    writer.Write(header_checksum);

                    writer.Write((byte)'I');
                    writer.Write(data);
                }
                result = m.ToArray();
            }

            return result;
        }

        public static void sendBye(RemoteEndpoint endpoint, ProtocolByeCode code, string message, string data, bool removeAddressEntry = true)
        {
            using (MemoryStream m2 = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m2))
                {
                    writer.Write((int)code);
                    writer.Write(message);
                    writer.Write(data);
                    endpoint.sendData(ProtocolMessageCode.bye, m2.ToArray());
                    Logging.info("Sending bye to {0} with message '{1}' and data '{2}'", endpoint.getFullAddress(), message, data);
                }
            }
            if (removeAddressEntry)
            {
                if (endpoint.presence != null && endpoint.presence.wallet != null && endpoint.presenceAddress != null)
                {
                    PresenceList.removeAddressEntry(endpoint.presence.wallet, endpoint.presenceAddress);
                }
                //PeerStorage.removePeer(endpoint.getFullAddress(true));
            }
        }


        // Read a protocol message from a byte array
        public static void readProtocolMessage(byte[] recv_buffer, RemoteEndpoint endpoint)
        {
            if (endpoint == null)
            {
                Logging.error("Endpoint was null. readProtocolMessage");
                return;
            }

            ProtocolMessageCode code = ProtocolMessageCode.hello;
            byte[] data = null;

            using (MemoryStream m = new MemoryStream(recv_buffer))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    // Check for multi-message packets. One packet can contain multiple network messages.
                    while (reader.BaseStream.Position < reader.BaseStream.Length)
                    {
                        byte[] data_checksum;
                        try
                        {
                            byte startByte = reader.ReadByte();

                            int message_code = reader.ReadInt32();
                            code = (ProtocolMessageCode)message_code;

                            int data_length = reader.ReadInt32();

                            // If this is a connected client, filter messages
                            if (endpoint.GetType() == typeof(RemoteEndpoint))
                            {
                                if (endpoint.presence == null)
                                {
                                    // Check for presence and only accept hello and syncPL messages if there is no presence.
                                    if (code == ProtocolMessageCode.hello || code == ProtocolMessageCode.syncPresenceList || code == ProtocolMessageCode.getBalance || code == ProtocolMessageCode.newTransaction)
                                    {

                                    }
                                    else
                                    {
                                        // Ignore anything else
                                        return;
                                    }
                                }
                            }




                            data_checksum = reader.ReadBytes(32); // sha512qu, 32 bytes
                            byte header_checksum = reader.ReadByte();
                            byte endByte = reader.ReadByte();
                            data = reader.ReadBytes(data_length);
                        }
                        catch (Exception e)
                        {
                            Logging.error(String.Format("NET: dropped packet. {0}", e));
                            return;
                        }
                        // Compute checksum of received data
                        byte[] local_checksum = Crypto.sha512sqTrunc(data, 0, 0, 32);

                        // Verify the checksum before proceeding
                        if (local_checksum.SequenceEqual(data_checksum) == false)
                        {
                            Logging.error("Dropped message (invalid checksum)");
                            continue;
                        }

                        // Can proceed to parse the data parameter based on the protocol message code.
                        // Data can contain multiple elements.
                        //parseProtocolMessage(code, data, socket, endpoint);
                        NetworkQueue.receiveProtocolMessage(code, data, data_checksum, endpoint);
                    }
                }
            }
        }


        public static bool processHelloMessage(RemoteEndpoint endpoint, BinaryReader reader)
        {
            // Node already has a presence
            if (endpoint.presence != null)
            {
                // Ignore the hello message in this case
                return false;
            }

            // Another layer to catch any incompatible node exceptions for the hello message
            try
            {
                int protocol_version = reader.ReadInt32();

                Logging.info(string.Format("Received Hello: Node version {0}", protocol_version));
                // Check for incompatible nodes
                if (protocol_version < CoreConfig.protocolVersion)
                {
                    Logging.warn(String.Format("Hello: Connected node version ({0}) is too old! Upgrade the node.", protocol_version));
                    sendBye(endpoint, ProtocolByeCode.deprecated, string.Format("Your node version is too old. Should be at least {0} is {1}", CoreConfig.protocolVersion, protocol_version), CoreConfig.protocolVersion.ToString(), true);
                    return false;
                }

                int addrLen = reader.ReadInt32();
                byte[] addr = reader.ReadBytes(addrLen);

                bool test_net = reader.ReadBoolean();
                char node_type = reader.ReadChar();
                string node_version = reader.ReadString();
                string device_id = reader.ReadString();

                int pkLen = reader.ReadInt32();
                byte[] pubkey = reader.ReadBytes(pkLen);

                int port = reader.ReadInt32();
                long timestamp = reader.ReadInt64();

                int sigLen = reader.ReadInt32();
                byte[] signature = reader.ReadBytes(sigLen);

                // Check the testnet designator and disconnect on mismatch
                if (test_net != Config.isTestNet)
                {
                    Logging.warn(string.Format("Rejected node {0} due to incorrect testnet designator: {1}", endpoint.fullAddress, test_net));
                    sendBye(endpoint, ProtocolByeCode.incorrectNetworkType, string.Format("Incorrect testnet designator: {0}. Should be {1}", test_net, Config.isTestNet), test_net.ToString(), true);
                    return false;
                }

                // Check the address and pubkey and disconnect on mismatch
                if (!addr.SequenceEqual((new Address(pubkey)).address))
                {
                    Logging.warn(string.Format("Pubkey and address do not match."));
                    sendBye(endpoint, ProtocolByeCode.authFailed, "Pubkey and address do not match.", "", true);
                    return false;
                }

                endpoint.incomingPort = port;

                // Verify the signature
                if (node_type == 'C')
                {
                    // TODO: verify if the client is connectable and if so, add the presence

                    // Client is not connectable, don't add a presence
                    return true;
                }
                else
                if (CryptoManager.lib.verifySignature(Encoding.UTF8.GetBytes(CoreConfig.ixianChecksumLockString + "-" + device_id + "-" + timestamp + "-" + endpoint.getFullAddress(true)), pubkey, signature) == false)
                {
                    CoreProtocolMessage.sendBye(endpoint, ProtocolByeCode.incorrectIp, "Verify signature failed in hello message, likely an incorrect IP was specified. Detected IP:", endpoint.address);
                    Logging.warn(string.Format("Connected node used an incorrect signature in hello message, likely an incorrect IP was specified. Detected IP: {0}", endpoint.address));
                    return false;
                }

                // if we're a client update the network time difference
                if (endpoint.GetType() == typeof(NetworkClient))
                {
                    long timeDiff = endpoint.calculateTimeDifference();

                    // amortize +- 2 seconds
                    if (timeDiff >= -2 && timeDiff <= 2)
                    {
                        timeDiff = 0;
                    }

                    ((NetworkClient)endpoint).timeDifference = timeDiff;
                }

                // Store the presence address for this remote endpoint
                endpoint.presenceAddress = new PresenceAddress(device_id, endpoint.getFullAddress(true), node_type, node_version, Core.getCurrentTimestamp(), null);

                // Create a temporary presence with the client's address and device id
                Presence presence = new Presence(addr, pubkey, null, endpoint.presenceAddress);

                if (endpoint.GetType() != typeof(NetworkClient))
                {
                    // Connect to this node only if it's a master node or a full history node
                    if (node_type == 'M' || node_type == 'H')
                    {
                        // Check the wallet balance for the minimum amount of coins
                        IxiNumber balance = Node.walletState.getWalletBalance(addr);
                        if (balance < CoreConfig.minimumMasterNodeFunds)
                        {
                            Logging.warn(string.Format("Rejected master node {0} due to insufficient funds: {1}", endpoint.getFullAddress(), balance.ToString()));
                            sendBye(endpoint, ProtocolByeCode.insufficientFunds, string.Format("Insufficient funds. Minimum is {0}", CoreConfig.minimumMasterNodeFunds), balance.ToString(), true);
                            return false;
                        }
                        // Limit to one IP per masternode
                        // TODO TODO TODO - think about this and do it properly
                        /*string[] hostname_split = hostname.Split(':');
                        if (PresenceList.containsIP(hostname_split[0], 'M'))
                        {
                            using (MemoryStream m2 = new MemoryStream())
                            {
                                using (BinaryWriter writer = new BinaryWriter(m2))
                                {
                                    writer.Write(string.Format("This IP address ( {0} ) already has a masternode connected.", hostname_split[0]));
                                    Logging.info(string.Format("Rejected master node {0} due to duplicate IP address", hostname));
                                    socket.Send(prepareProtocolMessage(ProtocolMessageCode.bye, m2.ToArray()), SocketFlags.None);
                                    socket.Disconnect(true);
                                    return;
                                }
                            }
                        }*/
                    }

                    // we're the server
                    if (node_type == 'M' || node_type == 'H' || node_type == 'R')
                    {
                        if (!checkNodeConnectivity(endpoint))
                        {
                            return false;
                        }
                    }
                }


                // Retrieve the final presence entry from the list (or create a fresh one)
                endpoint.presence = PresenceList.updateEntry(presence);

            }
            catch (Exception e)
            {
                // Disconnect the node in case of any reading errors
                Logging.warn(string.Format("Older node connected. {0}", e.ToString()));
                sendBye(endpoint, ProtocolByeCode.deprecated, "Please update your Ixian node to connect.", "", true);
                return false;
            }
            return true;
        }

        public static void sendHelloMessage(RemoteEndpoint endpoint, bool sendHelloData)
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    string publicHostname = string.Format("{0}:{1}", Config.publicServerIP, Config.serverPort);

                    // Send the node version
                    writer.Write(CoreConfig.protocolVersion);

                    // Send the public node address
                    byte[] address = Node.walletStorage.getPrimaryAddress();
                    writer.Write(address.Length);
                    writer.Write(address);

                    // Send the testnet designator
                    writer.Write(Config.isTestNet);

                    char node_type = Node.getNodeType();
                    writer.Write(node_type);

                    // Send the version
                    writer.Write(Config.version);

                    // Send the node device id
                    writer.Write(Config.device_id);

                    // Send the wallet public key
                    writer.Write(Node.walletStorage.getPrimaryPublicKey().Length);
                    writer.Write(Node.walletStorage.getPrimaryPublicKey());

                    // Send listening port
                    writer.Write(Config.serverPort);

                    // Send timestamp
                    long timestamp = Core.getCurrentTimestamp();
                    writer.Write(timestamp);

                    // send signature
                    byte[] signature = CryptoManager.lib.getSignature(Encoding.UTF8.GetBytes(CoreConfig.ixianChecksumLockString + "-" + Config.device_id + "-" + timestamp + "-" + publicHostname), Node.walletStorage.getPrimaryPrivateKey());
                    writer.Write(signature.Length);
                    writer.Write(signature);


                    if (sendHelloData)
                    {
                        Block block = Node.getLastBlock();
                        if (block == null)
                        {
                            Logging.warn("Clients are connecting, but we have no blocks yet to send them!");
                            return;
                        }


                        ulong lastBlock = block.blockNum;
                        writer.Write(lastBlock);

                        writer.Write(block.blockChecksum.Length);
                        writer.Write(block.blockChecksum);

                        writer.Write(block.walletStateChecksum.Length);
                        writer.Write(block.walletStateChecksum);

                        writer.Write(Node.getRequiredConsensus());

                        writer.Write(block.version);

                        // Write the legacy level
                        writer.Write(Legacy.getLegacyLevel());


                        endpoint.sendData(ProtocolMessageCode.helloData, m.ToArray());

                    }
                    else
                    {
                        endpoint.sendData(ProtocolMessageCode.hello, m.ToArray());
                    }
                }
            }
        }


        // Broadcast a protocol message across clients and nodes
        // Returns true if it sent the message at least one endpoint. Returns false if the message couldn't be sent to any endpoints
        public static bool broadcastProtocolMessage(char[] types, ProtocolMessageCode code, byte[] data, byte[] helper_data, RemoteEndpoint skipEndpoint = null)
        {
            if (data == null)
            {
                Logging.warn(string.Format("Invalid protocol message data for {0}", code));
                return false;
            }

            bool c_result = NetworkClientManager.broadcastData(types, code, data, helper_data, skipEndpoint);
            bool s_result = NetworkServer.broadcastData(types, code, data, helper_data, skipEndpoint);

            if (!c_result && !s_result)
                return false;

            return true;
        }

        // Broadcast an event-specific protocol message across subscribed clients
        // Returns true if it sent the message to at least one endpoint. Returns false if the message couldn't be sent to any endpoints
        public static bool broadcastEventDataMessage(NetworkEvents.Type type, byte[] address, ProtocolMessageCode code, byte[] data, byte[] helper_data, RemoteEndpoint skipEndpoint = null)
        {
            // Send it to subscribed C nodes
            bool f_result = NetworkServer.broadcastEventData(type, code, data, address, helper_data, skipEndpoint);

            if (!f_result)
                return false;

            return true;
        }


        // Broadcasts protocol message to a single random node with block height higher than the one specified with parameter block_num
        public static bool broadcastProtocolMessageToSingleRandomNode(char[] types, ProtocolMessageCode code, byte[] data, ulong block_num, RemoteEndpoint skipEndpoint = null)
        {
            if (data == null)
            {
                Logging.warn(string.Format("Invalid protocol message data for {0}", code));
                return false;
            }

            lock (NetworkClientManager.networkClients)
            {
                lock (NetworkServer.connectedClients)
                {
                    int serverCount = 0;
                    int clientCount = 0;
                    List<NetworkClient> servers = null;
                    List<RemoteEndpoint> clients = null;

                    if (types == null)
                    {
                        servers = NetworkClientManager.networkClients.FindAll(x => x.blockHeight > block_num);
                        clients = NetworkServer.connectedClients.FindAll(x => x.blockHeight > block_num);

                        serverCount = servers.Count();
                        clientCount = clients.Count();

                        if (serverCount == 0 && clientCount == 0)
                        {
                            servers = NetworkClientManager.networkClients.FindAll(x => x.blockHeight == block_num);
                            clients = NetworkServer.connectedClients.FindAll(x => x.blockHeight == block_num);
                        }
                    }
                    else
                    {
                        servers = NetworkClientManager.networkClients.FindAll(x => x.blockHeight > block_num && x.presenceAddress != null && types.Contains(x.presenceAddress.type));
                        clients = NetworkServer.connectedClients.FindAll(x => x.blockHeight > block_num && x.presenceAddress != null && types.Contains(x.presenceAddress.type));

                        serverCount = servers.Count();
                        clientCount = clients.Count();

                        if (serverCount == 0 && clientCount == 0)
                        {
                            servers = NetworkClientManager.networkClients.FindAll(x => x.blockHeight == block_num && x.presenceAddress != null && types.Contains(x.presenceAddress.type));
                            clients = NetworkServer.connectedClients.FindAll(x => x.blockHeight == block_num && x.presenceAddress != null && types.Contains(x.presenceAddress.type));
                        }
                    }

                    serverCount = servers.Count();
                    clientCount = clients.Count();

                    if (serverCount == 0 && clientCount == 0)
                    {
                        return false;
                    }

                    Random r = new Random();
                    int rIdx = r.Next(serverCount + clientCount);

                    RemoteEndpoint re = null;

                    if (rIdx < serverCount)
                    {
                        re = servers[rIdx];
                    }
                    else
                    {
                        re = clients[rIdx - serverCount];
                    }

                    if (re == skipEndpoint && serverCount + clientCount > 1)
                    {
                        if (rIdx + 1 < serverCount)
                        {
                            re = servers[rIdx + 1];
                        }
                        else if (rIdx + 1 < serverCount + clientCount)
                        {
                            re = clients[rIdx + 1 - serverCount];
                        }
                        else if (serverCount > 0)
                        {
                            re = servers[0];
                        }
                        else if (clientCount > 0)
                        {
                            re = clients[0];
                        }
                    }

                    if (re != null && re.isConnected())
                    {
                        re.sendData(code, data);
                        return true;
                    }
                    return false;
                }
            }
        }


        public static bool checkNodeConnectivity(RemoteEndpoint endpoint)
        {
            // TODO TODO TODO TODO we should put this in a separate thread
            string hostname = endpoint.getFullAddress(true);
            if (CoreNetworkUtils.PingAddressReachable(hostname) == false)
            {
                Logging.warn("Node {0} was not reachable on the advertised address.", hostname);
                CoreProtocolMessage.sendBye(endpoint, ProtocolByeCode.notConnectable, "External " + hostname + " not reachable!", "");
                return false;
            }
            return true;
        }
    }
}
