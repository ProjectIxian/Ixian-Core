using IXICore.Meta;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace IXICore.Network
{
    public struct QueueMessage
    {
        public ProtocolMessageCode code;
        public byte[] data;
        public uint checksum;
        public RemoteEndpoint skipEndpoint;
        public byte[] helperData;
    }

    public struct QueueMessageRaw
    {
        public ProtocolMessageCode code;
        public byte[] data;
        public byte[] legacyChecksum;
        public uint checksum;
        public RemoteEndpoint endpoint;
    }

    class NetworkQueue
    {
        private static bool shouldStop = false; // flag to signal shutdown of threads
        private static ThreadLiveCheck TLC;

        private static bool running = false;

        // Internal queue message entity with socket and remoteendpoint support
        struct QueueMessageRecv
        {
            public ProtocolMessageCode code;
            public byte[] data;
            public int length;
            public uint checksum;
            public RemoteEndpoint endpoint;
            public byte[] helperData;
        }

        // Maintain a queue of messages to receive
        private static List<QueueMessageRecv> queueMessages = new List<QueueMessageRecv>();
        private static List<QueueMessageRecv> txqueueMessages = new List<QueueMessageRecv>();


        public static int getQueuedMessageCount()
        {
            lock (queueMessages)
            {
                return queueMessages.Count;
            }
        }

        public static int getTxQueuedMessageCount()
        {
            lock (txqueueMessages)
            {
                return txqueueMessages.Count;
            }
        }

        private static byte[] extractHelperData(ProtocolMessageCode code, byte[] data)
        {
            if (code == ProtocolMessageCode.blockData || code == ProtocolMessageCode.newBlock)
            {
                return data.Take(8).ToArray();
            }
            return null;
        }

        public static void receiveProtocolMessage(ProtocolMessageCode code, byte[] data, uint checksum, RemoteEndpoint endpoint)
        {
            QueueMessageRecv message = new QueueMessageRecv
            {
                code = code,
                data = data,
                length = data.Length,
                checksum = checksum,
                endpoint = endpoint,
                helperData = extractHelperData(code, data)
            };


            lock (txqueueMessages)
            {
                // Move block related messages to txqueue
                bool found_get_request = false;
                bool found_tx_request = false;
                switch (code)
                {
#pragma warning disable CS0618 // Type or member is obsolete
                    case ProtocolMessageCode.getTransaction:
                    case ProtocolMessageCode.getTransaction2:
                    case ProtocolMessageCode.getTransaction3:
                    case ProtocolMessageCode.getTransactions:
                    case ProtocolMessageCode.getTransactions2:
                    case ProtocolMessageCode.getBlock:
                    case ProtocolMessageCode.getBlock2:
                    case ProtocolMessageCode.getBlockHeaders:
                    case ProtocolMessageCode.getBlockHeaders2:
                    case ProtocolMessageCode.getSignatures:
                    case ProtocolMessageCode.getBlockSignatures2:
                    case ProtocolMessageCode.getPIT:
                    case ProtocolMessageCode.getPIT2:
#pragma warning restore CS0618 // Type or member is obsolete
                        found_get_request = true;
                        found_tx_request = true;
                        break;

#pragma warning disable CS0618 // Type or member is obsolete
                    case ProtocolMessageCode.transactionsChunk:
                    case ProtocolMessageCode.newTransaction:
                    case ProtocolMessageCode.transactionData:
                    case ProtocolMessageCode.blockTransactionsChunk:
                    case ProtocolMessageCode.blockHeaders:
                    case ProtocolMessageCode.blockHeaders2:
                    case ProtocolMessageCode.newBlock:
                    case ProtocolMessageCode.blockData:
                    case ProtocolMessageCode.blockSignature:
                    case ProtocolMessageCode.blockSignatures:
                    case ProtocolMessageCode.blockSignature2:
                    case ProtocolMessageCode.signaturesChunk:
                    case ProtocolMessageCode.pitData:
                    case ProtocolMessageCode.pitData2:
                    case ProtocolMessageCode.inventory:
                    case ProtocolMessageCode.inventory2:
#pragma warning restore CS0618 // Type or member is obsolete
                        found_get_request = false;
                        found_tx_request = true;
                        break;
                }
                if(found_tx_request)
                {
                    if(found_get_request)
                    {
                        if (message.helperData != null)
                        {
                            if (txqueueMessages.Exists(x => x.code == message.code && x.helperData.SequenceEqual(message.helperData) && x.endpoint == message.endpoint))
                            {
                                int msg_index = txqueueMessages.FindIndex(x => x.code == message.code && message.helperData.SequenceEqual(x.helperData));
                                if (txqueueMessages[msg_index].length < message.length)
                                {
                                    txqueueMessages[msg_index] = message;
                                }
                                return;
                            }
                        }

                        if (txqueueMessages.Exists(x => x.code == message.code && x.checksum == message.checksum && x.endpoint == message.endpoint))
                        {
                            Logging.trace("Attempting to add a duplicate message (code: {0}) to the network queue", code);
                            return;
                        }
                    }
                    else
                    {
                        if (message.helperData != null)
                        {
                            if (txqueueMessages.Exists(x => x.code == message.code && x.helperData.SequenceEqual(message.helperData)))
                            {
                                int msg_index = txqueueMessages.FindIndex(x => x.code == message.code && message.helperData.SequenceEqual(x.helperData));
                                if (txqueueMessages[msg_index].length < message.length)
                                {
                                    txqueueMessages[msg_index] = message;
                                }
                                return;
                            }
                        }

                        if (txqueueMessages.Exists(x => x.code == message.code && x.checksum == message.checksum))
                        {
                            Logging.trace("Attempting to add a duplicate message (code: {0}) to the network queue", code);
                            return;
                        }
                    }

                    bool add = true;
                    if (txqueueMessages.Count > 20)
                    {
                        switch (code)
                        {
#pragma warning disable CS0618 // Type or member is obsolete
                            case ProtocolMessageCode.getTransaction:
                            case ProtocolMessageCode.getTransaction2:
                            case ProtocolMessageCode.getTransaction3:
                            case ProtocolMessageCode.getTransactions:
                            case ProtocolMessageCode.getTransactions2:
                            case ProtocolMessageCode.transactionsChunk:
                            case ProtocolMessageCode.blockTransactionsChunk:
                            case ProtocolMessageCode.getBlock:
                            case ProtocolMessageCode.getBlock2:
                            case ProtocolMessageCode.getBlockHeaders:
                            case ProtocolMessageCode.getBlockHeaders2:
                            case ProtocolMessageCode.blockHeaders:
                            case ProtocolMessageCode.blockHeaders2:
                            case ProtocolMessageCode.newBlock:
                            case ProtocolMessageCode.blockData:
                            case ProtocolMessageCode.blockSignature:
                            case ProtocolMessageCode.blockSignatures:
                            case ProtocolMessageCode.blockSignature2:
                            case ProtocolMessageCode.getSignatures:
                            case ProtocolMessageCode.getBlockSignatures2:
                            case ProtocolMessageCode.signaturesChunk:
                            case ProtocolMessageCode.getPIT:
                            case ProtocolMessageCode.getPIT2:
                            case ProtocolMessageCode.pitData:
                            case ProtocolMessageCode.pitData2:
                            case ProtocolMessageCode.inventory:
                            case ProtocolMessageCode.inventory2:
#pragma warning restore CS0618 // Type or member is obsolete
                                {
                                    txqueueMessages.Insert(5, message);
                                    add = false;
                                    break;
                                }
                        }
                    }
                    if (add)
                    {
                        // Add it to the tx queue
                        txqueueMessages.Add(message);
                    }
                    return;
                }
            }

            lock (queueMessages)
            {
                // ignore duplicates
                if (queueMessages.Exists(x => x.code == message.code && x.checksum == message.checksum && x.endpoint == message.endpoint))
                {
                    Logging.trace("Attempting to add a duplicate message (code: {0}) to the network queue", code);
                    return;
                }

                // Handle normal messages, but prioritize block-related messages
                switch (code)
                {
                    case ProtocolMessageCode.bye:
                    case ProtocolMessageCode.hello:
                    case ProtocolMessageCode.helloData:
                        queueMessages.Insert(0, message);
                        return;

                    case ProtocolMessageCode.keepAlivePresence:
                    case ProtocolMessageCode.getPresence:
                    case ProtocolMessageCode.getPresence2:
                    case ProtocolMessageCode.updatePresence:
                        // Prioritize if queue is large
                        if (queueMessages.Count > 10)
                        {
                            queueMessages.Insert(5, message);
                            return;
                        }

                        break;
                }

                // Add it to the normal queue
                queueMessages.Add(message);
            }
        }


        // Start the network queue
        public static void start()
        {
            if (running)
            {
                return;
            }

            running = true;

            shouldStop = false;
            queueMessages.Clear();
            txqueueMessages.Clear();

            TLC = new ThreadLiveCheck();
            // Multi-threaded network queue parsing
            for (int i = 0; i < 1; i++)
            {
                Thread queue_thread = new Thread(queueThreadLoop);
                queue_thread.Name = "Network_Queue_Thread_#" + i.ToString();
                queue_thread.Start();
            }

            Thread txqueue_thread = new Thread(txqueueThreadLoop);
            txqueue_thread.Name = "Network_Queue_TX_Thread";
            txqueue_thread.Start();

            Logging.info("Network queue thread started.");
        }

        // Signals all the queue threads to stop
        public static bool stop()
        {
            shouldStop = true;
            running = false;
            return true;
        }

        // Resets the network queues
        public static void reset()
        {
            lock (queueMessages)
            {
                queueMessages.Clear();
            }

            lock (txqueueMessages)
            {
                txqueueMessages.Clear();
            }
        }

        // Actual network queue logic
        public static void queueThreadLoop()
        {
            // Prepare an special message object to use while receiving and parsing, without locking up the queue messages
            QueueMessageRecv active_message = new QueueMessageRecv();

            while (!shouldStop)
            {
                TLC.Report();
                bool message_found = false;
                lock (queueMessages)
                {
                    if (queueMessages.Count > 0)
                    {
                        // Pick the oldest message
                        active_message = queueMessages[0];
                        message_found = true;
                        // Remove it from the queue
                        queueMessages.RemoveAt(0);
                    }
                }

                if (message_found)
                {
                    Logging.trace("Received {0} ({1}B) - {2}...", active_message.code, active_message.data.Length, Crypto.hashToString(active_message.data.Take(60).ToArray()));
                    // Active message set, attempt to parse it
                    IxianHandler.parseProtocolMessage(active_message.code, active_message.data, active_message.endpoint);
                }
                else
                {
                    // Sleep for 10ms to prevent cpu waste
                    Thread.Sleep(10);
                }
            }
            Logging.info("Network queue thread stopped.");
        }

        // Actual tx network queue logic
        public static void txqueueThreadLoop()
        {
            // Prepare an special message object to use while receiving and parsing, without locking up the queue messages
            QueueMessageRecv active_message = new QueueMessageRecv();

            while (!shouldStop)
            {
                TLC.Report();
                bool message_found = false;
                lock (txqueueMessages)
                {
                    if (txqueueMessages.Count > 0)
                    {
                        // Pick the oldest message
                        active_message = txqueueMessages[0];
                        message_found = true;
                        // Remove it from the queue
                        txqueueMessages.RemoveAt(0);
                    }
                }

                if (message_found)
                {
                    Logging.trace("Received {0} ({1}B) - {2}...", active_message.code, active_message.data.Length, Crypto.hashToString(active_message.data.Take(60).ToArray()));
                    // Active message set, attempt to parse it
                    IxianHandler.parseProtocolMessage(active_message.code, active_message.data, active_message.endpoint);
                }
                else
                {
                    // Sleep for 10ms to prevent cpu waste
                    Thread.Sleep(10);
                }
            }
            Logging.info("Network Tx queue thread stopped.");
        }
    }
}
