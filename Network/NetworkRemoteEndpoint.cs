using IXICore.Meta;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace IXICore.Network
{
    public class TimeSyncData
    {
        public long timeDifference = 0;
        public long remoteTime = 0;
        public long processedTime = 0;
    }

    public class RemoteEndpoint
    {
        public string fullAddress = "127.0.0.1:0";
        public string address = "127.0.0.1";
        public int incomingPort = 0;

        public long connectionStartTime = 0;

        public long timeDifference = 0;
        public bool timeSyncComplete = false;

        public bool helloReceived = false;
        public ulong blockHeight = 0;

        protected long lastDataReceivedTime = 0;
        protected long lastDataSentTime = 0;

        public bool fullyStopped = false;

        public IPEndPoint remoteIP;
        public Socket clientSocket;
        public RemoteEndpointState state;

        // Maintain two threads for handling data receiving and sending
        protected Thread recvThread = null;
        protected Thread sendThread = null;
        protected Thread parseThread = null;

        public Presence presence = null;
        public PresenceAddress presenceAddress = null;

        protected bool running = false;

        // Maintain a list of subscribed event addresses with event type
        private Dictionary<NetworkEvents.Type, Cuckoo> subscribedFilters = new Dictionary<NetworkEvents.Type, Cuckoo>();

        // Maintain a queue of messages to send
        private List<QueueMessage> sendQueueMessagesHighPriority = new List<QueueMessage>();
        private List<QueueMessage> sendQueueMessagesNormalPriority = new List<QueueMessage>();
        private List<QueueMessage> sendQueueMessagesLowPriority = new List<QueueMessage>();

        // Maintain a queue of raw received data
        private List<QueueMessageRaw> recvRawQueueMessages = new List<QueueMessageRaw>();

        private byte[] socketReadBuffer = null;

        protected List<TimeSyncData> timeSyncs = new List<TimeSyncData>();

        protected bool enableSendTimeSyncMessages = true;

        private int messagesPerSecond = 0;
        private int lastMessagesPerSecond = 0;
        private DateTime lastMessageStatTime;

        private ThreadLiveCheck TLC;

        public byte[] serverWalletAddress = null;
        public byte[] serverPubKey = null;

        public byte[] challenge = null;

        protected void prepareSocket(Socket socket)
        {
            // The socket will linger for 3 seconds after 
            // Socket.Close is called.
            socket.LingerState = new LingerOption(true, 3);

            // Disable the Nagle Algorithm for this tcp socket.
            socket.NoDelay = true;

            socket.ReceiveTimeout = 120000;
            //socket.ReceiveBufferSize = 1024 * 64;
            //socket.SendBufferSize = 1024 * 64;
            socket.SendTimeout = 120000;

            socket.Blocking = true;
        }

        public void start(Socket socket = null)
        {
            if (fullyStopped)
            {
                Logging.error("Can't start a fully stopped RemoteEndpoint");
                return;
            }

            if (running)
            {
                return;
            }

            if (socket != null)
            {
                clientSocket = socket;
            }
            if (clientSocket == null)
            {
                Logging.error("Could not start NetworkRemoteEndpoint, socket is null");
                return;
            }

            prepareSocket(clientSocket);

            remoteIP = (IPEndPoint)clientSocket.RemoteEndPoint;
            address = remoteIP.Address.ToString();
            fullAddress = address + ":" + remoteIP.Port;
            presence = null;
            presenceAddress = null;

            connectionStartTime = Clock.getTimestamp();

            lock (subscribedFilters)
            {
                subscribedFilters.Clear();
            }

            lastDataReceivedTime = Clock.getTimestamp();
            lastDataSentTime = Clock.getTimestamp();

            state = RemoteEndpointState.Established;

            timeDifference = 0;
            timeSyncComplete = false;
            timeSyncs.Clear();

            running = true;

            // Abort all related threads
            if (recvThread != null)
            {
                recvThread.Abort();
                recvThread = null;
            }
            if (sendThread != null)
            {
                sendThread.Abort();
                sendThread = null;
            }
            if (parseThread != null)
            {
                parseThread.Abort();
                parseThread = null;
            }

            try
            {
                TLC = new ThreadLiveCheck();
                // Start receive thread
                recvThread = new Thread(new ThreadStart(recvLoop));
                recvThread.Name = "Network_Remote_Endpoint_Receive_Thread";
                recvThread.Start();

                // Start send thread
                sendThread = new Thread(new ThreadStart(sendLoop));
                sendThread.Name = "Network_Remote_Endpoint_Send_Thread";
                sendThread.Start();

                // Start parse thread
                parseThread = new Thread(new ThreadStart(parseLoop));
                parseThread.Name = "Network_Remote_Endpoint_Parse_Thread";
                parseThread.Start();
            }
            catch (Exception e)
            {
                Logging.error("Exception start remote endpoint: {0}", e.Message);
            }
        }

        // Aborts all related endpoint threads and data
        public void stop()
        {
            fullyStopped = true;

            Thread.Sleep(50); // clear any last messages

            state = RemoteEndpointState.Closed;
            running = false;

            Thread.Sleep(50); // wait for threads to stop

            lock (sendQueueMessagesHighPriority)
            {
                sendQueueMessagesHighPriority.Clear();
            }

            lock (sendQueueMessagesNormalPriority)
            {
                sendQueueMessagesNormalPriority.Clear();
            }

            lock (sendQueueMessagesLowPriority)
            {
                sendQueueMessagesLowPriority.Clear();
            }

            lock (recvRawQueueMessages)
            {
                recvRawQueueMessages.Clear();
            }

            lock (subscribedFilters)
            {
                subscribedFilters.Clear();
            }

            // Abort all related threads
            if (recvThread != null)
            {
                //recvThread.Abort();
                recvThread = null;
            }
            if (sendThread != null)
            {
                //sendThread.Abort();
                sendThread = null;
            }
            if (parseThread != null)
            {
                //parseThread.Abort();
                parseThread = null;
            }

            disconnect();
        }

        // Receive thread
        protected virtual void recvLoop()
        {
            Thread.CurrentThread.IsBackground = true;
            socketReadBuffer = new byte[8192];
            lastMessageStatTime = DateTime.UtcNow;
            while (running)
            {
                TLC.Report();
                // Let the protocol handler receive and handle messages
                try
                {
                    byte[] data = readSocketData();
                    if (data != null)
                    {
                        parseDataInternal(data, this);
                        messagesPerSecond++;
                    }
                }
                catch (Exception e)
                {
                    if(running)
                    {
                        Logging.warn(string.Format("recvRE: Disconnected client {0} with exception {1}", getFullAddress(), e.ToString()));
                    }
                    state = RemoteEndpointState.Closed;
                }

                // Check if the client disconnected
                if (state == RemoteEndpointState.Closed)
                {
                    running = false;
                    break;
                }

                TimeSpan timeSinceLastStat = DateTime.UtcNow - lastMessageStatTime;
                if (timeSinceLastStat.TotalSeconds < 0 || timeSinceLastStat.TotalSeconds > 2)
                {
                    lastMessageStatTime = DateTime.UtcNow;
                    lastMessagesPerSecond = (int)(messagesPerSecond / timeSinceLastStat.TotalSeconds);
                    messagesPerSecond = 0;
                }

                if (lastMessagesPerSecond < 1)
                {
                    lastMessagesPerSecond = 1;
                }
                    
                // Sleep a while to throttle the client
                // Check if there are too many messages
                // TODO TODO TODO this can be handled way better
                int total_message_count = NetworkQueue.getQueuedMessageCount() + NetworkQueue.getTxQueuedMessageCount();
                if(total_message_count > 500)
                {
                    Thread.Sleep(100 * lastMessagesPerSecond);
                    if (messagesPerSecond == 0)
                    {
                        lastMessageStatTime = DateTime.UtcNow;
                    }
                    lastDataReceivedTime = Clock.getTimestamp();
                }
                else if (total_message_count > 100)
                {
                    Thread.Sleep(total_message_count / 10);
                }
                else
                {
                    Thread.Sleep(1);
                }
            }
        }

        public virtual void disconnect()
        {
            // Close the client socket
            if (clientSocket != null)
            {
                try
                {
                    clientSocket.Shutdown(SocketShutdown.Both);
                    clientSocket.Close();
                    clientSocket = null;
                }
                catch (Exception e)
                {
                    Logging.warn(string.Format("recvRE: Could not shutdown client socket: {0}", e.ToString()));
                }
            }
        }

        protected void sendTimeSyncMessages()
        {
            // send 5 messages with current network timestamp
            List<byte> time_sync_data = new List<byte>();
            for (int i = 0; i < 5; i++)
            {
                time_sync_data.Clear();
                time_sync_data.Add(2);
                time_sync_data.AddRange(BitConverter.GetBytes(Clock.getNetworkTimestampMillis()));
                try
                {
                    int time_sync_data_len = time_sync_data.ToArray().Length;
                    for (int sent = 0; sent < time_sync_data_len;)
                    {
                        sent += clientSocket.Send(time_sync_data.ToArray(), sent, time_sync_data_len, SocketFlags.None);
                    }
                }
                catch (Exception ex)
                {
                    // this may sometimes happen if clients/servers drop the connection from their side
                    Logging.warn(String.Format("Exception while attempting to send time sync: {0}.", ex.Message));
                }
            }
        }


        // Send thread
        protected void sendLoop()
        {
            // Prepare an special message object to use while sending, without locking up the queue messages
            QueueMessage active_message = new QueueMessage();

            if (enableSendTimeSyncMessages)
            {
                sendTimeSyncMessages();
            }

            int messageCount = 0;

            while (running)
            {
                TLC.Report();
                long curTime = Clock.getTimestamp();
                if(helloReceived == false && curTime - connectionStartTime > 10)
                {
                    // haven't received hello message for 10 seconds, stop running
                    Logging.warn(String.Format("Node {0} hasn't received hello data from remote endpoint for over 10 seconds, disconnecting.", getFullAddress()));
                    state = RemoteEndpointState.Closed;
                    running = false;
                    break;
                }
                if (curTime - lastDataReceivedTime > CoreConfig.pingTimeout)
                {
                    // haven't received any data for 10 seconds, stop running
                    Logging.warn(String.Format("Node {0} hasn't received any data from remote endpoint for over {1} seconds, disconnecting.", getFullAddress(), CoreConfig.pingTimeout));
                    state = RemoteEndpointState.Closed;
                    running = false;
                    break;
                }
                if(curTime - lastDataSentTime > CoreConfig.pongInterval)
                {
                    try
                    {
                        clientSocket.Send(new byte[1] { 1 }, SocketFlags.None);
                        lastDataSentTime = curTime;
                        continue;
                    }
                    catch (Exception)
                    {
                        state = RemoteEndpointState.Closed;
                        running = false;
                        break;
                    }
                }

                bool message_found = false;
                lock (sendQueueMessagesHighPriority)
                {
                    lock (sendQueueMessagesNormalPriority)
                    {
                        if ((messageCount > 0 && messageCount % 5 == 0) || (sendQueueMessagesNormalPriority.Count == 0 && sendQueueMessagesHighPriority.Count == 0))
                        {
                            lock (sendQueueMessagesLowPriority)
                            {
                                if (sendQueueMessagesLowPriority.Count > 0)
                                {
                                    // Pick the oldest message
                                    QueueMessage candidate = sendQueueMessagesLowPriority[0];
                                    active_message.code = candidate.code;
                                    active_message.data = candidate.data;
                                    active_message.checksum = candidate.checksum;
                                    active_message.skipEndpoint = candidate.skipEndpoint;
                                    active_message.helperData = candidate.helperData;
                                    // Remove it from the queue
                                    sendQueueMessagesLowPriority.Remove(candidate);
                                    message_found = true;
                                }
                            }
                            messageCount = 0;
                        }

                        if (message_found == false && ((messageCount > 0 && messageCount % 3 == 0) || sendQueueMessagesHighPriority.Count == 0))
                        {
                            if (sendQueueMessagesNormalPriority.Count > 0)
                            {
                                // Pick the oldest message
                                QueueMessage candidate = sendQueueMessagesNormalPriority[0];
                                active_message.code = candidate.code;
                                active_message.data = candidate.data;
                                active_message.checksum = candidate.checksum;
                                active_message.skipEndpoint = candidate.skipEndpoint;
                                active_message.helperData = candidate.helperData;
                                // Remove it from the queue
                                sendQueueMessagesNormalPriority.Remove(candidate);
                                message_found = true;
                            }
                        }

                        if (message_found == false && sendQueueMessagesHighPriority.Count > 0)
                        {
                            // Pick the oldest message
                            QueueMessage candidate = sendQueueMessagesHighPriority[0];
                            active_message.code = candidate.code;
                            active_message.data = candidate.data;
                            active_message.checksum = candidate.checksum;
                            active_message.skipEndpoint = candidate.skipEndpoint;
                            active_message.helperData = candidate.helperData;
                            // Remove it from the queue
                            sendQueueMessagesHighPriority.Remove(candidate);
                            message_found = true;
                        }
                    }
                }

                if (message_found)
                {
                    messageCount++;
                    // Active message set, attempt to send it
                    sendDataInternal(active_message.code, active_message.data, active_message.checksum);
                    if(active_message.code == ProtocolMessageCode.bye)
                    {
                        Thread.Sleep(500); // grace sleep to get the message through
                        running = false;
                        fullyStopped = true;
                    }
                    Thread.Sleep(1);
                }
                else
                {
                    // Sleep for 10ms to prevent cpu waste
                    Thread.Sleep(10);
                }
            }
        }

        // Parse thread
        protected void parseLoop()
        {
            // Prepare an special message object to use while sending, without locking up the queue messages
            QueueMessageRaw active_message = new QueueMessageRaw();

            while (running)
            {
                TLC.Report();
                try
                {
                    bool message_found = false;
                    lock (recvRawQueueMessages)
                    {
                        if (recvRawQueueMessages.Count > 0)
                        {
                            // Pick the oldest message
                            QueueMessageRaw candidate = recvRawQueueMessages[0];
                            active_message.data = candidate.data;
                            active_message.endpoint = candidate.endpoint;
                            // Remove it from the queue
                            recvRawQueueMessages.Remove(candidate);
                            message_found = true;
                        }
                    }

                    if (message_found)
                    {
                        // Active message set, add it to Network Queue
                        CoreProtocolMessage.readProtocolMessage(active_message.data, this);
                    }
                    else
                    {
                        Thread.Sleep(10);
                    }

                }
                catch (Exception e)
                {
                    Logging.error(String.Format("Exception occured for client {0} in parseLoopRE: {1} ", getFullAddress(), e));
                }
                // Sleep a bit to prevent cpu waste
                Thread.Yield();
            }

        }

        protected void parseDataInternal(byte[] data, RemoteEndpoint endpoint)
        {
            QueueMessageRaw message = new QueueMessageRaw();
            message.data = data;
            message.endpoint = endpoint;

            lock (recvRawQueueMessages)
            {
                recvRawQueueMessages.Add(message);
            }
        }


        // Internal function that sends data through the socket
        protected void sendDataInternal(ProtocolMessageCode code, byte[] data, byte[] checksum)
        {
            byte[] ba = CoreProtocolMessage.prepareProtocolMessage(code, data, checksum);
            NetDump.Instance.appendSent(clientSocket, ba, ba.Length);
            try
            {
                for (int sentBytes = 0; sentBytes < ba.Length && running;)
                {
                    int bytesToSendCount = ba.Length - sentBytes;
                    if (bytesToSendCount > 8000)
                    {
                        bytesToSendCount = 8000;
                    }


                    int curSentBytes = clientSocket.Send(ba, sentBytes, bytesToSendCount, SocketFlags.None);

                    lastDataSentTime = Clock.getTimestamp();


                    // Sleep a bit to allow other threads to do their thing
                    Thread.Yield();

                    sentBytes += curSentBytes;
                    // TODO TODO TODO timeout
                }
                if (clientSocket.Connected == false)
                {
                    if (running)
                    {
                        Logging.warn(String.Format("sendRE: Failed senddata to remote endpoint {0}, Closing.", getFullAddress()));
                    }
                    state = RemoteEndpointState.Closed;
                }
            }
            catch (Exception e)
            {
                if (running)
                {
                    Logging.warn(String.Format("sendRE: Socket exception for {0}, closing. {1}", getFullAddress(), e));
                }
                state = RemoteEndpointState.Closed;

            }
        }

        private void addMessageToSendQueue(List<QueueMessage> message_queue, QueueMessage message)
        {
            if (message.helperData != null)
            {
                if (message_queue.Exists(x => x.code == message.code && x.helperData != null && message.helperData.SequenceEqual(x.helperData)))
                {
                    int msg_index = message_queue.FindIndex(x => x.code == message.code && x.helperData != null && message.helperData.SequenceEqual(x.helperData));
                    message_queue[msg_index] = message;
                    return;
                }
            }
            else
            {
                bool duplicate = message_queue.Exists(x => x.code == message.code && message.checksum.SequenceEqual(x.checksum));
                if (duplicate)
                {
                    Logging.warn(string.Format("Attempting to add a duplicate message (code: {0}) to the network queue for {1}", message.code, getFullAddress()));
                    return;
                }
            }
            // Check if there are too many messages
            if (message_queue.Count > CoreConfig.maxSendQueue)
            {
                message_queue.RemoveAt(10);
            }

            message_queue.Add(message);
        }


        // Sends data over the network
        public void sendData(ProtocolMessageCode code, byte[] data, byte[] helper_data = null)
        {
            if (data == null)
            {
                Logging.warn(string.Format("Invalid protocol message data for {0}", code));
                return;
            }

            QueueMessage message = new QueueMessage();
            message.code = code;
            message.data = data;
            message.checksum = Crypto.sha512sqTrunc(data, 0, 0, 32);
            message.skipEndpoint = null;
            message.helperData = helper_data;

            if(code == ProtocolMessageCode.bye || code == ProtocolMessageCode.keepAlivePresence 
                || code == ProtocolMessageCode.getPresence || code == ProtocolMessageCode.updatePresence)
            {
                lock (sendQueueMessagesHighPriority)
                {
                    addMessageToSendQueue(sendQueueMessagesHighPriority, message);
                }
            }else if(code != ProtocolMessageCode.transactionData && code != ProtocolMessageCode.newTransaction)
            {
                lock (sendQueueMessagesNormalPriority)
                {
                    addMessageToSendQueue(sendQueueMessagesNormalPriority, message);
                }
            }
            else
            {
                lock (sendQueueMessagesLowPriority)
                {
                    addMessageToSendQueue(sendQueueMessagesLowPriority, message);
                }
            }
        }

        public int getQueuedMessageCount()
        {
            lock (sendQueueMessagesHighPriority)
            {
                lock (sendQueueMessagesNormalPriority)
                {
                    lock (sendQueueMessagesLowPriority)
                    {
                        return sendQueueMessagesHighPriority.Count + sendQueueMessagesNormalPriority.Count + sendQueueMessagesLowPriority.Count;
                    }
                }
            }
        }

        public bool isConnected()
        {
            try
            {
                if (clientSocket == null)
                {
                    return false;
                }

                return clientSocket.Connected && running;
            }
            catch (Exception)
            {
                return false;
            }
        }

        // Get the ip/hostname and port
        public string getFullAddress(bool useIncomingPorts = false)
        {
            if(useIncomingPorts)
            {
                return address + ":" + incomingPort;
            }
            return fullAddress;
        }

        private int getDataLengthFromMessageHeader(List<byte> header)
        {
            int data_length = -1;
            // we should have the full header, save the data length
            using (MemoryStream m = new MemoryStream(header.ToArray()))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    reader.ReadByte(); // skip start byte
                    int code = reader.ReadInt32(); // skip message code
                    data_length = reader.ReadInt32(); // finally read data length
                    byte[] data_checksum = reader.ReadBytes(32); // skip checksum sha512qu/sha512sq, 32 bytes
                    byte checksum = reader.ReadByte(); // header checksum byte
                    byte endByte = reader.ReadByte(); // end byte

                    if (endByte != 'I')
                    {
                        Logging.warn("Header end byte was not 'I'");
                        return -1;
                    }

                    if (CoreProtocolMessage.getHeaderChecksum(header.Take(41).ToArray()) != checksum)
                    {
                        Logging.warn(String.Format("Header checksum mismatch"));
                        return -1;
                    }

                    if (data_length <= 0)
                    {
                        Logging.warn(String.Format("Data length was {0}, code {1}", data_length, code));
                        return -1;
                    }

                    if (data_length > CoreConfig.maxMessageSize)
                    {
                        Logging.warn(String.Format("Received data length was bigger than max allowed message size - {0}, code {1}.", data_length, code));
                        return -1;
                    }
                }
            }
            return data_length;
        }

        protected void readTimeSyncData()
        {
            if(timeSyncComplete)
            {
                return;
            }

            Socket socket = clientSocket;

            int rcv_count = 8;
            for (int i = 0; i < rcv_count && socket.Connected;)
            {
                i += socket.Receive(socketReadBuffer, i, rcv_count - i, SocketFlags.None);
                Thread.Yield();
            }
            lock (timeSyncs)
            {
                long my_cur_time = Clock.getTimestampMillis();
                long cur_remote_time = BitConverter.ToInt64(socketReadBuffer, 0);
                long time_difference = my_cur_time - cur_remote_time;
                if (timeSyncs.Count > 0)
                {
                    TimeSyncData prev_tsd = timeSyncs.Last();
                    time_difference -= my_cur_time - prev_tsd.processedTime;
                }
                TimeSyncData tsd = new TimeSyncData() { timeDifference = time_difference, remoteTime = cur_remote_time, processedTime = my_cur_time };
                timeSyncs.Add(tsd);
                if(timeSyncs.Count() >= 5)
                {
                    timeSyncComplete = true;
                }
            }
        }

        // Reads data from a socket and returns a byte array
        protected byte[] readSocketData()
        {
            Socket socket = clientSocket;

            byte[] data = null;

            // Check for socket availability
            if (socket.Connected == false)
            {
                throw new Exception("Socket already disconnected at other end");
            }

            if (socket.Available < 1)
            {
                // Sleep a while to prevent cpu cycle waste
                Thread.Sleep(10);
                return data;
            }

            // Read multi-packet messages
            // TODO: optimize this as it's not very efficient
            List<byte> big_buffer = new List<byte>();

            bool message_found = false;

            try
            {
                int data_length = 0;
                int header_length = 43; // start byte + int32 (4 bytes) + int32 (4 bytes) + checksum (32 bytes) + header checksum (1 byte) + end byte
                int bytesToRead = 1;
                while (message_found == false && socket.Connected && running)
                {
                    //int pos = bytesToRead > NetworkProtocol.recvByteHist.Length ? NetworkProtocol.recvByteHist.Length - 1 : bytesToRead;
                    /*lock (NetworkProtocol.recvByteHist)
                    {
                        NetworkProtocol.recvByteHist[pos]++;
                    }*/
                    int byteCounter = socket.Receive(socketReadBuffer, bytesToRead, SocketFlags.None);
                    NetDump.Instance.appendReceived(socket, socketReadBuffer, byteCounter);
                    if (byteCounter > 0)
                    {
                        lastDataReceivedTime = Clock.getTimestamp();
                        if (big_buffer.Count > 0)
                        {
                            big_buffer.AddRange(socketReadBuffer.Take(byteCounter));
                            if (big_buffer.Count == header_length)
                            {
                                data_length = getDataLengthFromMessageHeader(big_buffer);
                                if (data_length <= 0)
                                {
                                    data_length = 0;
                                    big_buffer.Clear();
                                    bytesToRead = 1;
                                }
                            }
                            else if (big_buffer.Count == data_length + header_length)
                            {
                                // we have everything that we need, save the last byte and break
                                message_found = true;
                            }else if(big_buffer.Count < header_length)
                            {
                                bytesToRead = header_length - big_buffer.Count;
                            }else if(big_buffer.Count > data_length + header_length)
                            {
                                Logging.error(String.Format("Unhandled edge case occured in RemoteEndPoint:readSocketData for node {0}", getFullAddress()));
                                return null;
                            }
                            if (data_length > 0)
                            {
                                bytesToRead = data_length + header_length - big_buffer.Count;
                                if (bytesToRead > 8000)
                                {
                                    bytesToRead = 8000;
                                }
                            }
                        }
                        else
                        {
                            if (socketReadBuffer[0] == 'X') // X is the message start byte
                            {
                                big_buffer.Add(socketReadBuffer[0]);
                                bytesToRead = header_length - 1; // header length - start byte
                            }else if(helloReceived == false)
                            {
                                if(socketReadBuffer[0] == 2)
                                {
                                    readTimeSyncData();
                                }
                            }
                        }
                        Thread.Yield();
                    }
                    else
                    {
                        // sleep a litte while waiting for bytes
                        Thread.Sleep(10);
                        // TODO TODO TODO, should reset the big_buffer if a timeout occurs
                    }
                }
            }
            catch (Exception e)
            {
                if (running)
                {
                    Logging.error(String.Format("NET: endpoint {0} disconnected {1}", getFullAddress(), e));
                    throw;
                }
            }
            if (message_found)
            {
                data = big_buffer.ToArray();
            }
            return data;
        }


        // Subscribe to event
        public bool attachEvent(NetworkEvents.Type type, byte[] filter)
        {
            if (address == null)
                return false;

            lock (subscribedFilters)
            {
                // Check the quota
                int num_subscribed_addresses = subscribedFilters.Values.Aggregate(0, (acc, f) => acc + f.numItems);
                if (num_subscribed_addresses > CoreConfig.maximumSubscribableEvents)
                {
                    return false;
                }
            }
            Cuckoo cuckoo_filter = null;
            try
            {
                cuckoo_filter = new Cuckoo(filter);
            } catch(Exception)
            {
                Logging.warn("Error while attempting to replace {0} filter for endpoint {1}",
                    type.ToString(),
                    getFullAddress()
                    );
                return false;
            }

            if (cuckoo_filter == null)
            {
                Logging.warn("Cannot attach event {0} to Remote Endpoint {1}, cuckoo filter is null.",
                    type.ToString(),
                    getFullAddress()
                    );
                return false;
            }


            lock (subscribedFilters) {
                // Subscribing a new cuckoo for a particular event type will replace the old one
                subscribedFilters.AddOrReplace(type, cuckoo_filter);
            }

            return true;
        }


        // Unsubscribe from event
        public bool detachEventType(NetworkEvents.Type type)
        {
            lock (subscribedFilters)
            {
                // Check if we're subscribed already to this address
                if (subscribedFilters.ContainsKey(type) == true)
                {
                    subscribedFilters.Remove(type);
                }
            }

            return true;
        }

        public bool detachEventAddress(NetworkEvents.Type type, byte[] address)
        {
            if(address == null)
            {
                return true;
            }
            lock(subscribedFilters)
            {
                if(subscribedFilters.ContainsKey(type) == true)
                {
                    subscribedFilters[type].Delete(address);
                }
            }
            return true;
        }

        // Check if the remote endpoint is subscribed to an event for a specific address
        // Returns true if subscribed
        public bool isSubscribedToAddress(NetworkEvents.Type type, byte[] address)
        {
            if (address == null)
                return false;

            lock (subscribedFilters)
            {
                if(subscribedFilters.ContainsKey(type) == true)
                {
                    return subscribedFilters[type].Contains(address);
                }
            }

            return false;
        }

        public long calculateTimeDifference()
        {
            lock (timeSyncs)
            {
                if(timeSyncs.Count == 0)
                {
                    return 0;
                }
                long time_diff = timeSyncs.OrderBy(x => x.timeDifference).First().timeDifference;
                return time_diff / 1000;
            }
        }
    }
}