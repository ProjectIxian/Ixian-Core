using IXICore.Meta;
using IXICore.Network;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace IXICore
{
    /// <summary>
    ///  Common functions for manipulating Ixian protocol message.
    /// </summary>
    public class CoreProtocolMessage
    {
        /// <summary>
        ///  Calculates a single-byte checksum from the given header.
        /// </summary>
        /// <remarks>
        ///  A single byte of checksum is not extremely robust, but it is simple and fast.
        /// </remarks>
        /// <param name="header">Message header.</param>
        /// <returns>Checksum byte.</returns>
        public static byte getHeaderChecksum(byte[] header)
        {
            byte sum = 0x7F;
            for (int i = 0; i < header.Length; i++)
            {
                sum ^= header[i];
            }
            return sum;
        }

        /// <summary>
        ///  Prepares (serializes) a protocol message from the given Ixian message code and appropriate data. Checksum can be supplied, but 
        ///  if it isn't, this function will calculate it using the default method.
        /// </summary>
        /// <remarks>
        ///  This function can be used from the server and client side.
        ///  Please note: This function does not validate that the payload `data` conforms to the expected message for `code`. It is the 
        ///  caller's job to ensure that.
        /// </remarks>
        /// <param name="code">Message code.</param>
        /// <param name="data">Payload for the message.</param>
        /// <param name="checksum">Optional checksum. If not supplied, or if null, this function will calculate it with the default method.</param>
        /// <returns>Serialized message as a byte-field</returns>
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

            using (MemoryStream m = new MemoryStream(4096))
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
#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("CoreProtocolMessage::prepareProtocolMessage: {0}", m.Length));
#endif
                }
                result = m.ToArray();
            }

            return result;
        }

        /// <summary>
        /// Prepares and sends the disconnect message to the specified remote endpoint.
        /// </summary>
        /// <param name="endpoint">Remote client.</param>
        /// <param name="code">Disconnection reason.</param>
        /// <param name="message">Optional text message for the user of the remote client.</param>
        /// <param name="data">Optional payload to further explain the disconnection reason.</param>
        /// <param name="removeAddressEntry">If true, the remote address will be removed from the `PresenceList`.</param>
        public static void sendBye(RemoteEndpoint endpoint, ProtocolByeCode code, string message, string data, bool removeAddressEntry = true)
        {
            using (MemoryStream m2 = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m2))
                {
                    writer.Write((int)code);
                    writer.Write(message);
                    writer.Write(data);
#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("CoreProtocolMessage::sendBye: {0}", m2.Length));
#endif

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


        /// <summary>
        ///  Reads a protocol message from the specified byte-field and calls appropriate methods to process this message.
        /// </summary>
        /// <remarks>
        ///  This function checks all applicable checksums and validates that the message is complete before calling one of the specialized
        ///  methods to handle actual decoding and processing.
        /// </remarks>
        /// <param name="recv_buffer">Byte-field with an Ixian protocol message.</param>
        /// <param name="endpoint">Remote endpoint from where the message was received.</param>
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
                                    if (code == ProtocolMessageCode.hello || code == ProtocolMessageCode.getPresenceList || code == ProtocolMessageCode.getBalance || code == ProtocolMessageCode.newTransaction)
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

        /// <summary>
        ///  Processes a Hello Ixian protocol message and updates the `PresenceList` as appropriate.
        /// </summary>
        /// <remarks>
        ///  This function should normally be called from `NetworkProtocol.parseProtocolMessage()`
        /// </remarks>
        /// <param name="endpoint">Remote endpoint from which the message was received.</param>
        /// <param name="reader">Reader object placed at the beginning of the hello message data.</param>
        /// <returns>True if the message was formatted properly and accepted.</returns>
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

                endpoint.serverPubKey = pubkey;

                int port = reader.ReadInt32();
                long timestamp = reader.ReadInt64();

                int sigLen = reader.ReadInt32();
                byte[] signature = reader.ReadBytes(sigLen);

                // Check the testnet designator and disconnect on mismatch
                if (test_net != CoreConfig.isTestNet)
                {
                    Logging.warn(string.Format("Rejected node {0} due to incorrect testnet designator: {1}", endpoint.fullAddress, test_net));
                    sendBye(endpoint, ProtocolByeCode.incorrectNetworkType, string.Format("Incorrect testnet designator: {0}. Should be {1}", test_net, CoreConfig.isTestNet), test_net.ToString(), true);
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
                    // TODO: verify if the client is connectable, then if connectable, check if signature verifies

                    /*if (CryptoManager.lib.verifySignature(Encoding.UTF8.GetBytes(ConsensusConfig.ixianChecksumLockString + "-" + device_id + "-" + timestamp + "-" + endpoint.getFullAddress(true)), pubkey, signature) == false)
                    {
                        CoreProtocolMessage.sendBye(endpoint, ProtocolByeCode.incorrectIp, "Verify signature failed in hello message, likely an incorrect IP was specified. Detected IP:", endpoint.address);
                        Logging.warn(string.Format("Connected node used an incorrect signature in hello message, likely an incorrect IP was specified. Detected IP: {0}", endpoint.address));
                        return false;
                    }*/
                    // TODO store the full address if connectable
                    // Store the presence address for this remote endpoint
                    endpoint.presenceAddress = new PresenceAddress(device_id, "", node_type, node_version, Core.getCurrentTimestamp() - CoreConfig.clientKeepAliveInterval, null);
                }
                else
                {
                    if (!CryptoManager.lib.verifySignature(Encoding.UTF8.GetBytes(ConsensusConfig.ixianChecksumLockString + "-" + device_id + "-" + timestamp + "-" + endpoint.getFullAddress(true)), pubkey, signature))
                    {
                        CoreProtocolMessage.sendBye(endpoint, ProtocolByeCode.incorrectIp, "Verify signature failed in hello message, likely an incorrect IP was specified. Detected IP:", endpoint.address);
                        Logging.warn(string.Format("Connected node used an incorrect signature in hello message, likely an incorrect IP was specified. Detected IP: {0}", endpoint.address));
                        return false;
                    }

                    // Store the presence address for this remote endpoint
                    endpoint.presenceAddress = new PresenceAddress(device_id, endpoint.getFullAddress(true), node_type, node_version, Core.getCurrentTimestamp() - CoreConfig.serverKeepAliveInterval, null);
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


                    // Check the address and local address and disconnect on mismatch
                    if (endpoint.serverWalletAddress != null && !addr.SequenceEqual(endpoint.serverWalletAddress))
                    {
                        Logging.warn(string.Format("Local address mismatch, possible Man-in-the-middle attack."));
                        sendBye(endpoint, ProtocolByeCode.addressMismatch, "Local address mismatch.", "", true);
                        return false;
                    }
                }


                // Create a temporary presence with the client's address and device id
                Presence presence = new Presence(addr, pubkey, null, endpoint.presenceAddress);

                if (endpoint.GetType() != typeof(NetworkClient))
                {
                    // we're the server

                    if (node_type == 'M' || node_type == 'H' || node_type == 'R')
                    {
                        if (node_type != 'R')
                        {
                            // Check the wallet balance for the minimum amount of coins
                            IxiNumber balance = IxianHandler.getWalletBalance(addr);
                            if (balance < ConsensusConfig.minimumMasterNodeFunds)
                            {
                                Logging.warn(string.Format("Rejected master node {0} due to insufficient funds: {1}", endpoint.getFullAddress(), balance.ToString()));
                                sendBye(endpoint, ProtocolByeCode.insufficientFunds, string.Format("Insufficient funds. Minimum is {0}", ConsensusConfig.minimumMasterNodeFunds), balance.ToString(), true);
                                return false;
                            }
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
                Logging.warn(string.Format("Exception occured in Hello Message {0}", e.ToString()));
                sendBye(endpoint, ProtocolByeCode.deprecated, "Something went wrong during hello, make sure you're running the latest version of Ixian DLT.", "");
                return false;
            }

            if(NetworkClientManager.getConnectedClients().Count() == 1)
            {
                PresenceList.forceSendKeepAlive = true;
            }

            return true;
        }

        /// <summary>
        ///  Prepares and sends an Ixian protocol 'Hello' message to the specified remote endpoint.
        /// </summary>
        /// <remarks>
        ///  A valid Ixian 'Hello' message includes certain Node data, verified by a public-key signature, which this function prepares using
        ///  the primary wallet's keypair. If this message is a reply to the other endpoint's hello message, then
        /// </remarks>
        /// <param name="endpoint">Remote endpoint to send the message to.</param>
        /// <param name="sendHelloData">True if the message is the first hello sent to the remote node, false if it is a reply to the challenge.</param>
        /// <param name="challenge_response">Response byte-field to the other node's hello challenge</param>
        public static void sendHelloMessage(RemoteEndpoint endpoint, bool sendHelloData, byte[] challenge_response)
        {
            using (MemoryStream m = new MemoryStream(1856))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    string publicHostname = IxianHandler.getFullPublicAddress();

                    // Send the node version
                    writer.Write(CoreConfig.protocolVersion);

                    // Send the public node address
                    byte[] address = IxianHandler.getWalletStorage().getPrimaryAddress();
                    writer.Write(address.Length);
                    writer.Write(address);

                    // Send the testnet designator
                    writer.Write(CoreConfig.isTestNet);

                    char node_type = PresenceList.myPresenceType;
                    writer.Write(node_type);

                    // Send the version
                    writer.Write(CoreConfig.productVersion);

                    // Send the node device id
                    writer.Write(CoreConfig.device_id);

                    // Send the wallet public key
                    writer.Write(IxianHandler.getWalletStorage().getPrimaryPublicKey().Length);
                    writer.Write(IxianHandler.getWalletStorage().getPrimaryPublicKey());

                    // Send listening port
                    writer.Write(IxianHandler.publicPort);

                    // Send timestamp
                    long timestamp = Core.getCurrentTimestamp();
                    writer.Write(timestamp);

                    // send signature
                    byte[] signature = CryptoManager.lib.getSignature(Encoding.UTF8.GetBytes(ConsensusConfig.ixianChecksumLockString + "-" + CoreConfig.device_id + "-" + timestamp + "-" + publicHostname), IxianHandler.getWalletStorage().getPrimaryPrivateKey());
                    writer.Write(signature.Length);
                    writer.Write(signature);


                    if (sendHelloData)
                    {
                        Block block = IxianHandler.getLastBlock();
                        if (block == null)
                        {
                            Logging.warn("Clients are connecting, but we have no blocks yet to send them!");
                            CoreProtocolMessage.sendBye(endpoint, ProtocolByeCode.notReady, string.Format("The node isn't ready yet, please try again later."), "", true);
                            return;
                        }


                        ulong lastBlock = block.blockNum;
                        writer.Write(lastBlock);

                        writer.Write(block.blockChecksum.Length);
                        writer.Write(block.blockChecksum);

                        writer.Write(block.walletStateChecksum.Length);
                        writer.Write(block.walletStateChecksum);

                        writer.Write((int)0); // deprecated, can be replaced with something else of type int32

                        writer.Write(block.version);

                        // Write the legacy level
                        writer.Write((ulong)0); // deprecated, can be replaced with something else of type UInt64

                        writer.Write(challenge_response.Length);
                        writer.Write(challenge_response);
#if TRACE_MEMSTREAM_SIZES
                        Logging.info(String.Format("CoreProtocolMessage::sendHelloMessage: {0}", m.Length));
#endif

                        endpoint.sendData(ProtocolMessageCode.helloData, m.ToArray());

                    }
                    else
                    {
                        List<byte> challenge = new List<byte>();

                        challenge.AddRange(IxianHandler.getWalletStorage().getPrimaryAddress());
                        Random rnd = new Random();
                        challenge.AddRange(BitConverter.GetBytes(rnd.Next(20000)));

                        byte[] challenge_bytes = challenge.ToArray();

                        endpoint.challenge = challenge_bytes;

                        writer.Write(challenge_bytes.Length);
                        writer.Write(challenge_bytes);
#if TRACE_MEMSTREAM_SIZES
                        Logging.info(String.Format("CoreProtocolMessage::sendHelloMessage: {0}", m.Length));
#endif

                        endpoint.sendData(ProtocolMessageCode.hello, m.ToArray());
                    }
                }
            }
        }


        /// <summary>
        ///  Prepares and broadcasts an Ixian protocol message to all connected nodes, filtered by `types`.
        /// </summary>
        /// <remarks>
        ///  The payload `data` should be properly formatted for the given `code` - this function will not ensure that this is so and
        ///  the caller must provide a valid message to this function.
        ///  The `skipEndpoint` parameter is useful when re-broadcasting a message received from a specific endpoint and do not wish to echo the same
        ///  data back to the sender.
        /// </remarks>
        /// <param name="types">Types of nodes to send this message to.</param>
        /// <param name="code">Protocol code.</param>
        /// <param name="data">Message payload</param>
        /// <param name="helper_data">Additional information, as required by the protocol message</param>
        /// <param name="skipEndpoint">Remote endpoint which should be skipped (data should not be sent to it).</param>
        /// <returns>True, if at least one message was sent to at least one other node. False if no messages were sent.</returns>
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
        /// <summary>
        ///  Broadcasts an event message to all clients who are subscribed to receive the specific event type and wallet address.
        /// </summary>
        /// <remarks>
        ///  Events are filtered by type and address. A client must subscribe to the specifif type for specific addresses in order to receive this data.
        ///  The payload `data` should be properly formatted for the given `code` - this function will not ensure that this is so and
        ///  the caller must provide a valid message to this function.
        ///  The `skipEndpoint` parameter is useful when re-broadcasting a message received from a specific endpoint and do not wish to echo the same
        ///  data back to the sender.
        /// </remarks>
        /// <param name="type">Type of the event message - used to filter subscribers</param>
        /// <param name="address">Address, which triggered the event.</param>
        /// <param name="code">Ixian protocol code.</param>
        /// <param name="data">Payload data.</param>
        /// <param name="helper_data">Optional additional data, as required by `code`.</param>
        /// <param name="skipEndpoint">Endpoint to skip when broadcasting.</param>
        /// <returns>True, if at least one message was sent to at least one remote endpoint. False if no messages were sent.</returns>
        public static bool broadcastEventDataMessage(NetworkEvents.Type type, byte[] address, ProtocolMessageCode code, byte[] data, byte[] helper_data, RemoteEndpoint skipEndpoint = null)
        {
            // Send it to subscribed C nodes
            bool f_result = NetworkServer.broadcastEventData(type, code, data, address, helper_data, skipEndpoint);
            return f_result;
        }


        // Broadcasts protocol message to a single random node with block height higher than the one specified with parameter block_num
        /// <summary>
        ///  Sends the specified protocol message to one of the connected remote endpoints, chosen randomly.
        /// </summary>
        /// <remarks>
        ///  The payload `data` should be properly formatted for the given `code` - this function will not ensure that this is so and
        ///  the caller must provide a valid message to this function.
        ///  The `skipEndpoint` parameter is useful when re-broadcasting a message received from a specific endpoint and do not wish to echo the same
        ///  data back to the sender.
        ///  The `block_num` parameter is used to filter the remote endpoints based on their latest known block height.
        /// </remarks>
        /// <param name="types">Types of the nodes where the message should be sent.</param>
        /// <param name="code">Ixian protocol code.</param>
        /// <param name="data">Payload data.</param>
        /// <param name="block_num">Block which should be searched for the endpoint addresses.</param>
        /// <param name="skipEndpoint">Minimum block height for endpoints which should receive this message.</param>
        /// <returns>True, if at least one message was sent to at least one remote endpoint. False if no messages were sent.</returns>
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
                        servers = NetworkClientManager.networkClients.FindAll(x => x.blockHeight > block_num && x.isConnected() && x.helloReceived);
                        clients = NetworkServer.connectedClients.FindAll(x => x.blockHeight > block_num && x.isConnected() && x.helloReceived);

                        serverCount = servers.Count();
                        clientCount = clients.Count();

                        if (serverCount == 0 && clientCount == 0)
                        {
                            servers = NetworkClientManager.networkClients.FindAll(x => x.blockHeight == block_num && x.isConnected() && x.helloReceived);
                            clients = NetworkServer.connectedClients.FindAll(x => x.blockHeight == block_num && x.isConnected() && x.helloReceived);
                        }
                    }
                    else
                    {
                        servers = NetworkClientManager.networkClients.FindAll(x => x.blockHeight > block_num && x.presenceAddress != null && types.Contains(x.presenceAddress.type) && x.isConnected() && x.helloReceived);
                        clients = NetworkServer.connectedClients.FindAll(x => x.blockHeight > block_num && x.presenceAddress != null && types.Contains(x.presenceAddress.type) && x.isConnected() && x.helloReceived);

                        serverCount = servers.Count();
                        clientCount = clients.Count();

                        if (serverCount == 0 && clientCount == 0)
                        {
                            servers = NetworkClientManager.networkClients.FindAll(x => x.blockHeight == block_num && x.presenceAddress != null && types.Contains(x.presenceAddress.type) && x.isConnected() && x.helloReceived);
                            clients = NetworkServer.connectedClients.FindAll(x => x.blockHeight == block_num && x.presenceAddress != null && types.Contains(x.presenceAddress.type) && x.isConnected() && x.helloReceived);
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

        /// <summary>
        ///  Verifies that the given remote endpoint is reachable by connecting to it and sending a short message.
        /// </summary>
        /// <remarks>
        ///  This function is used to ensure that the remote endpoing has listed the correct IP and port information for their `PresenceList` entry.
        /// </remarks>
        /// <param name="endpoint">Target endpoint to verify for connectivity.</param>
        /// <returns>True, if the endpoing is connectable.</returns>
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

        /// <summary>
        /// Subscribes client to transactionFrom, transactionTo and balance
        /// </summary>
        /// <remarks>
        ///  This function is used to ensure that the remote endpoing has listed the correct IP and port information for their `PresenceList` entry.
        /// </remarks>
        /// <param name="endpoint">Target endpoint to verify for connectivity.</param>
        public static void subscribeToEvents(RemoteEndpoint endpoint)
        {
            if (endpoint.presenceAddress.type != 'M')
            {
                return;
            }

            // TODO TODO TODO events can be optimized as there is no real need to subscribe them to every connected node

            // Subscribe to transaction events
            byte[] event_data = NetworkEvents.prepareEventMessageData(NetworkEvents.Type.transactionFrom, IxianHandler.getWalletStorage().getPrimaryAddress());
            endpoint.sendData(ProtocolMessageCode.attachEvent, event_data);

            event_data = NetworkEvents.prepareEventMessageData(NetworkEvents.Type.transactionTo, IxianHandler.getWalletStorage().getPrimaryAddress());
            endpoint.sendData(ProtocolMessageCode.attachEvent, event_data);

            event_data = NetworkEvents.prepareEventMessageData(NetworkEvents.Type.balance, IxianHandler.getWalletStorage().getPrimaryAddress());
            endpoint.sendData(ProtocolMessageCode.attachEvent, event_data);
        }
    }
}
