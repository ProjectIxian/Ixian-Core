using Force.Crc32;
using IXICore.Inventory;
using IXICore.Meta;
using IXICore.Network;
using IXICore.Utils;
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
        public static void readProtocolMessage(QueueMessageRaw raw_message, RemoteEndpoint endpoint)
        {
            if (endpoint == null)
            {
                Logging.error("Endpoint was null. readProtocolMessage");
                return;
            }

            ProtocolMessageCode code = raw_message.code;

            // Filter messages
            if (endpoint.presence == null)
            {
                // Check for presence and only accept hello and bye messages if there is no presence.
                if (code != ProtocolMessageCode.hello 
                    && code != ProtocolMessageCode.helloData
                    && code != ProtocolMessageCode.bye)
                {
                    return;
                }
            }
            if(raw_message.legacyChecksum != null)
            {
                // Compute checksum of received data
                byte[] local_checksum = Crypto.sha512sqTrunc(raw_message.data, 0, 0, 32);

                // Verify the checksum before proceeding
                if (local_checksum.SequenceEqual(raw_message.legacyChecksum) == false)
                {
                    Logging.error("Dropped message (invalid legacy checksum)");
                    return;
                }
            }else
            {
                // Compute checksum of received data
                uint local_checksum = Crc32CAlgorithm.Compute(raw_message.data);

                // Verify the checksum before proceeding
                if (local_checksum != raw_message.checksum)
                {
                    Logging.error("Dropped message (invalid checksum)");
                    return;
                }
            }


            // Can proceed to parse the data parameter based on the protocol message code.
            // Data can contain multiple elements.
            //parseProtocolMessage(code, data, socket, endpoint);
            NetworkQueue.receiveProtocolMessage(code, raw_message.data, Crc32CAlgorithm.Compute(raw_message.data), endpoint);
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
        public static bool processHelloMessageV5(RemoteEndpoint endpoint, BinaryReader reader, bool set_hello_received = true)
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
                endpoint.version = protocol_version;

                Logging.info("Received Hello: Node version {0}", protocol_version);
                // Check for incompatible nodes
                if (protocol_version < 5)
                {
                    Logging.warn("Hello: Connected node version ({0}) is too old! Upgrade the node.", protocol_version);
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
                byte[] pubkey = null;
                if (pkLen > 0)
                {
                    pubkey = reader.ReadBytes(pkLen);
                }

                endpoint.serverPubKey = pubkey;

                int port = reader.ReadInt32();

                long timestamp = reader.ReadInt64();

                int sigLen = reader.ReadInt32();
                byte[] signature = reader.ReadBytes(sigLen);

                // Check the testnet designator and disconnect on mismatch
                if (test_net != IxianHandler.isTestNet)
                {
                    Logging.warn("Rejected node {0} due to incorrect testnet designator: {1}", endpoint.fullAddress, test_net);
                    sendBye(endpoint, ProtocolByeCode.incorrectNetworkType, string.Format("Incorrect testnet designator: {0}. Should be {1}", test_net, IxianHandler.isTestNet), test_net.ToString(), true);
                    return false;
                }

                // Check the address and pubkey and disconnect on mismatch
                if (!addr.SequenceEqual((new Address(pubkey)).address))
                {
                    Logging.warn("Pubkey and address do not match.");
                    sendBye(endpoint, ProtocolByeCode.authFailed, "Pubkey and address do not match.", "", true);
                    return false;
                }

                endpoint.incomingPort = port;

                if (PeerStorage.isBlacklisted(addr) || PeerStorage.isBlacklisted(endpoint.getFullAddress(true)))
                {
                    Logging.warn("Hello: Connected node is blacklisted ({0} - {1}).", endpoint.getFullAddress(true), Base58Check.Base58CheckEncoding.EncodePlain(addr));
                    sendBye(endpoint, ProtocolByeCode.bye, "Blacklisted", "", true);
                    return false;
                }

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
                    endpoint.presenceAddress = new PresenceAddress(System.Guid.Parse(device_id).ToByteArray(), "", node_type, node_version, Clock.getNetworkTimestamp() - CoreConfig.clientKeepAliveInterval, null);
                }
                else
                {
                    // TODO update verify signature with binary structure
                    if (!CryptoManager.lib.verifySignature(Encoding.UTF8.GetBytes(ConsensusConfig.ixianChecksumLockString + "-" + device_id + "-" + timestamp + "-" + endpoint.getFullAddress(true)), pubkey, signature))
                    {
                        sendBye(endpoint, ProtocolByeCode.incorrectIp, "Verify signature failed in hello message, likely an incorrect IP was specified. Detected IP:", endpoint.address);
                        Logging.warn("Connected node used an incorrect signature in hello message, likely an incorrect IP was specified. Detected IP: {0}", endpoint.address);
                        return false;
                    }

                    // Store the presence address for this remote endpoint
                    endpoint.presenceAddress = new PresenceAddress(System.Guid.Parse(device_id).ToByteArray(), endpoint.getFullAddress(true), node_type, node_version, Clock.getNetworkTimestamp() - CoreConfig.serverKeepAliveInterval, null);
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
                        Logging.warn("Local address mismatch, possible Man-in-the-middle attack.");
                        sendBye(endpoint, ProtocolByeCode.addressMismatch, "Local address mismatch.", "", true);
                        return false;
                    }

                    PeerStorage.updateLastConnected(endpoint.getFullAddress(true));
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
                                Logging.warn("Rejected master node {0} due to insufficient funds: {1}", endpoint.getFullAddress(), balance.ToString());
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

                    int challenge_len = reader.ReadInt32();
                    byte[] challenge = reader.ReadBytes(challenge_len);

                    if (challenge_len < 20 || challenge_len > 60)
                    {
                        Logging.warn("Invalid challenge requested {0}", challenge_len);
                        sendBye(endpoint, ProtocolByeCode.authFailed, "Invalid challenge requested.", "");
                        return false;
                    }

                    byte[] challenge_response = CryptoManager.lib.getSignature(challenge, IxianHandler.getWalletStorage().getPrimaryPrivateKey());

                    sendHelloMessageV5(endpoint, true, challenge_response);
                    if(set_hello_received)
                    {
                        endpoint.helloReceived = true;
                    }
                }


                // Retrieve the final presence entry from the list (or create a fresh one)
                endpoint.presence = PresenceList.updateEntry(presence);

            }
            catch (Exception e)
            {
                // Disconnect the node in case of any reading errors
                Logging.warn("Exception occured in Hello Message {0}", e.ToString());
                sendBye(endpoint, ProtocolByeCode.deprecated, "Something went wrong during hello, make sure you're running the latest version of Ixian DLT.", "");
                return false;
            }

            if (NetworkClientManager.getConnectedClients().Count() == 1)
            {
                PresenceList.forceSendKeepAlive = true;
            }



            return true;
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
        public static bool processHelloMessageV6(RemoteEndpoint endpoint, BinaryReader reader, bool set_hello_received = true)
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
                int protocol_version = (int)reader.ReadIxiVarUInt();
                endpoint.version = protocol_version;

                Logging.info("Received Hello: Node version {0}", protocol_version);
                // Check for incompatible nodes
                if (protocol_version < 6)
                {
                    Logging.warn("Hello: Connected node version ({0}) is too old! Upgrade the node.", protocol_version);
                    sendBye(endpoint, ProtocolByeCode.deprecated, string.Format("Your node version is too old. Should be at least {0} is {1}", CoreConfig.protocolVersion, protocol_version), CoreConfig.protocolVersion.ToString(), true);
                    return false;
                }

                int addrLen = (int)reader.ReadIxiVarUInt();
                byte[] addr = reader.ReadBytes(addrLen);

                bool test_net = reader.ReadBoolean();
                char node_type = reader.ReadChar();
                string node_version = reader.ReadString();
                int device_id_len = (int)reader.ReadIxiVarUInt();
                byte[] device_id = reader.ReadBytes(device_id_len);

                int pkLen = (int)reader.ReadIxiVarUInt();
                byte[] pubkey = null;
                if (pkLen > 0)
                {
                    pubkey = reader.ReadBytes(pkLen);
                }

                endpoint.serverPubKey = pubkey;

                int port = (int)reader.ReadIxiVarInt();

                long timestamp = reader.ReadIxiVarInt();

                int sigLen = (int)reader.ReadIxiVarUInt();
                byte[] signature = reader.ReadBytes(sigLen);

                int challenge = 0;
                bool in_hello = false;
                if (endpoint.GetType() != typeof(NetworkClient))
                {
                    challenge = (int)reader.ReadIxiVarUInt();
                    in_hello = true;
                }

                // Check the testnet designator and disconnect on mismatch
                if (test_net != IxianHandler.isTestNet)
                {
                    Logging.warn("Rejected node {0} due to incorrect testnet designator: {1}", endpoint.fullAddress, test_net);
                    sendBye(endpoint, ProtocolByeCode.incorrectNetworkType, string.Format("Incorrect testnet designator: {0}. Should be {1}", test_net, IxianHandler.isTestNet), test_net.ToString(), true);
                    return false;
                }

                // Check the address and pubkey and disconnect on mismatch
                if (!addr.SequenceEqual((new Address(pubkey)).address))
                {
                    Logging.warn("Pubkey and address do not match.");
                    sendBye(endpoint, ProtocolByeCode.authFailed, "Pubkey and address do not match.", "", true);
                    return false;
                }

                endpoint.incomingPort = port;

                if (PeerStorage.isBlacklisted(addr) || PeerStorage.isBlacklisted(endpoint.getFullAddress(true)))
                {
                    Logging.warn("Hello: Connected node is blacklisted ({0} - {1}).", endpoint.getFullAddress(true), Base58Check.Base58CheckEncoding.EncodePlain(addr));
                    sendBye(endpoint, ProtocolByeCode.bye, "Blacklisted", "", true);
                    return false;
                }

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
                    endpoint.presenceAddress = new PresenceAddress(device_id, "", node_type, node_version, Clock.getNetworkTimestamp() - CoreConfig.clientKeepAliveInterval, null);
                }
                else
                {
                    using (MemoryStream mSig = new MemoryStream(1024))
                    {
                        using (BinaryWriter sigWriter = new BinaryWriter(mSig))
                        {
                            sigWriter.Write(ConsensusConfig.ixianChecksumLock);
                            sigWriter.Write(device_id);
                            sigWriter.Write(timestamp);
                            sigWriter.Write(endpoint.getFullAddress(true));
                            if(in_hello)
                            {
                                sigWriter.Write(challenge);
                            }else
                            {
                                sigWriter.Write(endpoint.challenge);
                            }
                        }
                        if (!CryptoManager.lib.verifySignature(mSig.ToArray(), pubkey, signature))
                        {
                            sendBye(endpoint, ProtocolByeCode.incorrectIp, "Verify signature failed in hello message, likely an incorrect IP was specified. Detected IP:", endpoint.address);
                            Logging.warn("Connected node used an incorrect signature in hello message, likely an incorrect IP was specified. Detected IP: {0}", endpoint.address);
                            return false;
                        }
                    }

                    // Store the presence address for this remote endpoint
                    endpoint.presenceAddress = new PresenceAddress(device_id, endpoint.getFullAddress(true), node_type, node_version, Clock.getNetworkTimestamp() - CoreConfig.serverKeepAliveInterval, null);
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
                        Logging.warn("Local address mismatch, possible Man-in-the-middle attack.");
                        sendBye(endpoint, ProtocolByeCode.addressMismatch, "Local address mismatch.", "", true);
                        return false;
                    }

                    PeerStorage.updateLastConnected(endpoint.getFullAddress(true));
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
                                Logging.warn("Rejected master node {0} due to insufficient funds: {1}", endpoint.getFullAddress(), balance.ToString());
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

                    sendHelloMessageV6(endpoint, true, challenge);
                    if (set_hello_received)
                    {
                        endpoint.helloReceived = true;
                    }
                }


                // Retrieve the final presence entry from the list (or create a fresh one)
                endpoint.presence = PresenceList.updateEntry(presence);

            }
            catch (Exception e)
            {
                // Disconnect the node in case of any reading errors
                Logging.warn("Exception occured in Hello Message {0}", e.ToString());
                sendBye(endpoint, ProtocolByeCode.deprecated, "Something went wrong during hello, make sure you're running the latest version of Ixian DLT.", "");
                return false;
            }

            if (NetworkClientManager.getConnectedClients().Count() == 1)
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
        public static void sendHelloMessageV5(RemoteEndpoint endpoint, bool sendHelloData, byte[] challenge_response)
        {
            using (MemoryStream m = new MemoryStream(1856))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    string publicHostname = IxianHandler.getFullPublicAddress();

                    // Send the node version
                    writer.Write(5);

                    // Send the public node address
                    byte[] address = IxianHandler.getWalletStorage().getPrimaryAddress();
                    writer.Write(address.Length);
                    writer.Write(address);

                    // Send the testnet designator
                    writer.Write(IxianHandler.isTestNet);

                    char node_type = PresenceList.myPresenceType;
                    writer.Write(node_type);

                    // Send the version
                    writer.Write(CoreConfig.productVersion);

                    string device_id_str = new System.Guid(CoreConfig.device_id).ToString();

                    // Send the node device id
                    writer.Write(device_id_str);

                    // Send the wallet public key
                    writer.Write(IxianHandler.getWalletStorage().getPrimaryPublicKey().Length);
                    writer.Write(IxianHandler.getWalletStorage().getPrimaryPublicKey());

                    // Send listening port
                    writer.Write(IxianHandler.publicPort);

                    // Send timestamp
                    long timestamp = Clock.getTimestamp() + endpoint.calculateTimeDifference();
                    writer.Write(timestamp);

                    // send signature
                    byte[] signature = CryptoManager.lib.getSignature(Encoding.UTF8.GetBytes(ConsensusConfig.ixianChecksumLockString + "-" + device_id_str + "-" + timestamp + "-" + publicHostname), IxianHandler.getWalletStorage().getPrimaryPrivateKey());
                    writer.Write(signature.Length);
                    writer.Write(signature);


                    if (sendHelloData)
                    {
                        Block block = IxianHandler.getLastBlock();
                        if (block == null)
                        {
                            Logging.warn("Clients are connecting, but we have no blocks yet to send them!");
                            sendBye(endpoint, ProtocolByeCode.notReady, string.Format("The node isn't ready yet, please try again later."), "", true);
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

                        writer.Write(endpoint.getFullAddress(true));

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
        ///  Prepares and sends an Ixian protocol 'Hello' message to the specified remote endpoint.
        /// </summary>
        /// <remarks>
        ///  A valid Ixian 'Hello' message includes certain Node data, verified by a public-key signature, which this function prepares using
        ///  the primary wallet's keypair. If this message is a reply to the other endpoint's hello message, then
        /// </remarks>
        /// <param name="endpoint">Remote endpoint to send the message to.</param>
        /// <param name="sendHelloData">True if the message is the first hello sent to the remote node, false if it is a reply to the challenge.</param>
        /// <param name="challenge_response">Response byte-field to the other node's hello challenge</param>
        public static void sendHelloMessageV6(RemoteEndpoint endpoint, bool sendHelloData, int challenge)
        {
            using (MemoryStream m = new MemoryStream(1856))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    string publicHostname = IxianHandler.getFullPublicAddress();

                    // Send the node version
                    writer.WriteIxiVarInt(6);

                    // Send the public node address
                    byte[] address = IxianHandler.getWalletStorage().getPrimaryAddress();
                    writer.WriteIxiVarInt(address.Length);
                    writer.Write(address);

                    // Send the testnet designator
                    writer.Write(IxianHandler.isTestNet);

                    char node_type = PresenceList.myPresenceType;
                    writer.Write(node_type);

                    // Send the version
                    writer.Write(CoreConfig.productVersion);

                    // Send the node device id
                    writer.WriteIxiVarInt(CoreConfig.device_id.Length);
                    writer.Write(CoreConfig.device_id);

                    // Send the wallet public key
                    writer.WriteIxiVarInt(IxianHandler.getWalletStorage().getPrimaryPublicKey().Length);
                    writer.Write(IxianHandler.getWalletStorage().getPrimaryPublicKey());

                    // Send listening port
                    writer.WriteIxiVarInt(IxianHandler.publicPort);

                    // Send timestamp
                    long timestamp = Clock.getTimestamp() + endpoint.calculateTimeDifference();
                    writer.WriteIxiVarInt(timestamp);

                    // generate signature
                    using (MemoryStream mSig = new MemoryStream(1024))
                    {
                        using (BinaryWriter sigWriter = new BinaryWriter(mSig))
                        {
                            sigWriter.Write(ConsensusConfig.ixianChecksumLock);
                            sigWriter.Write(CoreConfig.device_id);
                            sigWriter.Write(timestamp);
                            sigWriter.Write(publicHostname);
                            sigWriter.Write(challenge);
                        }
                        byte[] signature = CryptoManager.lib.getSignature(mSig.ToArray(), IxianHandler.getWalletStorage().getPrimaryPrivateKey());
                        writer.WriteIxiVarInt(signature.Length);
                        writer.Write(signature);
                    }

                    if (sendHelloData)
                    {
                        Block block = IxianHandler.getLastBlock();
                        if (block == null)
                        {
                            Logging.warn("Clients are connecting, but we have no blocks yet to send them!");
                            sendBye(endpoint, ProtocolByeCode.notReady, string.Format("The node isn't ready yet, please try again later."), "", true);
                            return;
                        }


                        writer.WriteIxiVarInt(block.blockNum);

                        writer.WriteIxiVarInt(block.blockChecksum.Length);
                        writer.Write(block.blockChecksum);

                        writer.WriteIxiVarInt(block.version);

                        writer.Write(endpoint.getFullAddress(true));

#if TRACE_MEMSTREAM_SIZES
                        Logging.info(String.Format("CoreProtocolMessage::sendHelloMessage: {0}", m.Length));
#endif

                        endpoint.sendData(ProtocolMessageCode.helloData, m.ToArray());

                    }
                    else
                    {
                        byte[] challenge_bytes = IxiVarInt.GetIxiVarIntBytes(challenge);
                        endpoint.challenge = BitConverter.GetBytes(challenge);
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
            if (endpoint.presenceAddress.type != 'M' && endpoint.presenceAddress.type != 'H')
            {
                return;
            }

            // TODO TODO TODO events can be optimized as there is no real need to subscribe them to every connected node

            // Subscribe to transaction events, for own addresses
            var my_addresses = IxianHandler.getWalletStorage().getMyAddresses();
            Cuckoo filter = new Cuckoo(my_addresses.Count());
            foreach(var addr in my_addresses)
            {
                filter.Add(addr.address);
            }
            byte[] filter_data = filter.getFilterBytes();
            byte[] event_data = NetworkEvents.prepareEventMessageData(NetworkEvents.Type.transactionFrom, filter_data);
            endpoint.sendData(ProtocolMessageCode.attachEvent, event_data);

            event_data = NetworkEvents.prepareEventMessageData(NetworkEvents.Type.transactionTo, filter_data);
            endpoint.sendData(ProtocolMessageCode.attachEvent, event_data);

            event_data = NetworkEvents.prepareEventMessageData(NetworkEvents.Type.balance, filter_data);
            endpoint.sendData(ProtocolMessageCode.attachEvent, event_data);
        }

        public static bool broadcastGetTransaction(string txid, ulong block_num, RemoteEndpoint endpoint = null, bool broadcast_to_single_node = true)
        {
            using (MemoryStream mw = new MemoryStream())
            {
                using (BinaryWriter writerw = new BinaryWriter(mw))
                {
                    writerw.Write(txid);
                    writerw.Write(block_num);
#if TRACE_MEMSTREAM_SIZES
                        Logging.info(String.Format("NetworkProtocol::broadcastGetTransaction: {0}", mw.Length));
#endif

                    if (endpoint != null)
                    {
                        if (endpoint.isConnected())
                        {
                            endpoint.sendData(ProtocolMessageCode.getTransaction, mw.ToArray());
                            return true;
                        }
                    }
                    // TODO TODO TODO TODO TODO determine if historic transaction and send to 'H' instead of 'M'
                    if (broadcast_to_single_node)
                    {
                        return broadcastProtocolMessageToSingleRandomNode(new char[] { 'M', 'H' }, ProtocolMessageCode.getTransaction, mw.ToArray(), block_num);
                    }
                    else
                    {
                        return broadcastProtocolMessage(new char[] { 'M', 'H' }, ProtocolMessageCode.getTransaction, mw.ToArray(), null);
                    }
                }
            }
        }

        public static bool broadcastGetTransaction2(byte[] txid, ulong block_num, RemoteEndpoint endpoint = null, bool broadcast_to_single_node = true)
        {
            using (MemoryStream mw = new MemoryStream())
            {
                using (BinaryWriter writerw = new BinaryWriter(mw))
                {
                    writerw.WriteIxiVarInt(txid.Length);
                    writerw.Write(txid);
                    writerw.WriteIxiVarInt(block_num);
#if TRACE_MEMSTREAM_SIZES
                        Logging.info(String.Format("NetworkProtocol::broadcastGetTransaction: {0}", mw.Length));
#endif

                    if (endpoint != null)
                    {
                        if (endpoint.isConnected())
                        {
                            endpoint.sendData(ProtocolMessageCode.getTransaction2, mw.ToArray());
                            return true;
                        }
                    }
                    // TODO TODO TODO TODO TODO determine if historic transaction and send to 'H' instead of 'M'
                    if (broadcast_to_single_node)
                    {
                        return broadcastProtocolMessageToSingleRandomNode(new char[] { 'M', 'H' }, ProtocolMessageCode.getTransaction2, mw.ToArray(), block_num);
                    }
                    else
                    {
                        return broadcastProtocolMessage(new char[] { 'M', 'H' }, ProtocolMessageCode.getTransaction2, mw.ToArray(), null);
                    }
                }
            }
        }

        public static bool addToInventory(char[] types, InventoryItem item, RemoteEndpoint skip_endpoint, ProtocolMessageCode code, byte[] data, byte[] helper)
        {
            bool c_result = NetworkClientManager.addToInventory(types, item, skip_endpoint, code, data, helper);
            bool s_result = NetworkServer.addToInventory(types, item, skip_endpoint, code, data, helper);
            return c_result || s_result;
        }

        public static void processBye(byte[] data, RemoteEndpoint endpoint)
        {
            using (MemoryStream m = new MemoryStream(data))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    endpoint.stop();

                    bool byeV1 = false;
                    try
                    {
                        ProtocolByeCode byeCode = (ProtocolByeCode)reader.ReadInt32();
                        string byeMessage = reader.ReadString();
                        string byeData = reader.ReadString();

                        byeV1 = true;

                        switch (byeCode)
                        {
                            case ProtocolByeCode.bye: // all good
                                break;

                            case ProtocolByeCode.deprecated: // deprecated node disconnected
                                Logging.info(string.Format("Disconnected with message: {0} {1}", byeMessage, byeData));
                                break;

                            case ProtocolByeCode.incorrectIp: // incorrect IP
                                if (IxiUtils.validateIPv4(byeData))
                                {
                                    if (NetworkClientManager.getConnectedClients(true).Length < 2)
                                    {
                                        IxianHandler.publicIP = byeData;
                                        Logging.info("Changed internal IP Address to " + byeData + ", reconnecting");
                                    }
                                }
                                break;

                            case ProtocolByeCode.notConnectable: // not connectable from the internet
                                Logging.error("This node must be connectable from the internet, to connect to the network.");
                                Logging.error("Please setup uPNP and/or port forwarding on your router for port " + IxianHandler.publicPort + ".");
                                NetworkServer.connectable = false;
                                break;

                            case ProtocolByeCode.insufficientFunds:
                                Logging.info("Insufficient funds to connect as master node.");
                                break;

                            default:
                                Logging.warn(string.Format("Disconnected with message: {0} {1}", byeMessage, byeData));
                                break;
                        }
                    }
                    catch (Exception)
                    {

                    }
                    if (byeV1)
                    {
                        return;
                    }

                    reader.BaseStream.Seek(0, SeekOrigin.Begin);

                    // Retrieve the message
                    string message = reader.ReadString();

                    if (message.Length > 0)
                        Logging.info(string.Format("Disconnected with message: {0}", message));
                    else
                        Logging.info("Disconnected");
                }
            }
        }
    }
}
