using DLT;
using DLT.Meta;
using DLT.Network;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DLT
{
    namespace Network
    {
        struct QueueMessage
        {
            public ProtocolMessageCode code;
            public byte[] data;
            public byte[] checksum;
            public RemoteEndpoint skipEndpoint;
        }

        struct QueueMessageRaw
        {
            public byte[] data;
            public RemoteEndpoint endpoint;
        }

        class NetworkQueue
        {
            private static bool shouldStop = false; // flag to signal shutdown of threads

            // Internal queue message entity with socket and remoteendpoint support
            struct QueueMessageRecv
            {
                public ProtocolMessageCode code;
                public byte[] data;
                public byte[] checksum;
                public RemoteEndpoint endpoint;
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


            public static void receiveProtocolMessage(ProtocolMessageCode code, byte[] data, byte[] checksum, RemoteEndpoint endpoint)
            {
                QueueMessageRecv message = new QueueMessageRecv
                {
                    code = code,
                    data = data,
                    checksum = checksum,
                    endpoint = endpoint
                };

                lock (txqueueMessages)
                {
                    // Move transaction messages to the transaction queue
                    if (code == ProtocolMessageCode.newTransaction || code == ProtocolMessageCode.transactionData
                        || code == ProtocolMessageCode.transactionsChunk || code == ProtocolMessageCode.newBlock || code == ProtocolMessageCode.blockData)
                    {
                        if (txqueueMessages.Exists(x => x.code == message.code && x.checksum.SequenceEqual(message.checksum)))
                        {
                            //Logging.warn(string.Format("Attempting to add a duplicate message (code: {0}) to the network queue", code));
                            return;
                        }

                        if (txqueueMessages.Count > 20 && 
                            (code == ProtocolMessageCode.transactionsChunk || code == ProtocolMessageCode.newBlock || code == ProtocolMessageCode.blockData))
                        {
                            txqueueMessages.Insert(5, message);
                        }
                        else
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
                    if (queueMessages.Exists(x => x.code == message.code && x.checksum.SequenceEqual(message.checksum) && x.endpoint == message.endpoint))
                    {
                        //Logging.warn(string.Format("Attempting to add a duplicate message (code: {0}) to the network queue", code));
                        return;
                    }

                    // Handle normal messages, but prioritize block-related messages
                    if(code == ProtocolMessageCode.bye || code == ProtocolMessageCode.hello || code == ProtocolMessageCode.helloData)
                    {
                        queueMessages.Insert(0, message);
                        return;
                    }else if (code == ProtocolMessageCode.keepAlivePresence || code == ProtocolMessageCode.getPresence
                        || code == ProtocolMessageCode.updatePresence)
                    {
                        // Prioritize if queue is large
                        if (queueMessages.Count > 10)
                        {
                            queueMessages.Insert(5, message);
                            return;
                        }
                    }

                    // Add it to the normal queue
                    queueMessages.Add(message);
                }
            }


            // Start the network queue
            public static void start()
            {
                shouldStop = false;
                queueMessages.Clear();
                txqueueMessages.Clear();

                // Multi-threaded network queue parsing
                for (int i = 0; i < 1; i++)
                {
                    Thread queue_thread = new Thread(queueThreadLoop);
                    queue_thread.Start();
                }

                Thread txqueue_thread = new Thread(txqueueThreadLoop);
                txqueue_thread.Start();

                Logging.info("Network queue thread started.");
            }

            // Signals all the queue threads to stop
            public static bool stop()
            {
                shouldStop = true;
                return true;
            }

            // Resets the network queues
            public static void reset()
            {
                lock(queueMessages)
                {
                    queueMessages.Clear();
                }

                lock(txqueueMessages)
                {
                    txqueueMessages.Clear();
                }
            }

            // Actual network queue logic
            public static void queueThreadLoop()
            {
                // Prepare an special message object to use while receiving and parsing, without locking up the queue messages
                QueueMessageRecv active_message = new QueueMessageRecv();
                QueueMessageRecv candidate = new QueueMessageRecv();

                while (!shouldStop)
                {
                    bool message_found = false;
                    lock(queueMessages)
                    {
                        if(queueMessages.Count > 0)
                        {
                            // Pick the oldest message
                            candidate = queueMessages[0];
                            active_message.code = candidate.code;
                            active_message.data = candidate.data;
                            active_message.checksum = candidate.checksum;
                            active_message.endpoint = candidate.endpoint;
                            message_found = true;
                        }
                    }

                    if (message_found)
                    {
                        // Active message set, attempt to parse it
                        ProtocolMessage.parseProtocolMessage(active_message.code, active_message.data, active_message.endpoint);
                        lock (queueMessages)
                        {
                            // Remove it from the queue
                            queueMessages.Remove(candidate);
                        }
                        // Sleep a bit to allow other threads to do their thing
                        Thread.Yield();
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
                QueueMessageRecv candidate = new QueueMessageRecv();

                while (!shouldStop)
                {
                    bool message_found = false;
                    lock (txqueueMessages)
                    {
                        if (txqueueMessages.Count > 0)
                        {
                            // Pick the oldest message
                            candidate = txqueueMessages[0];
                            active_message.code = candidate.code;
                            active_message.data = candidate.data;
                            active_message.checksum = candidate.checksum;
                            active_message.endpoint = candidate.endpoint;
                            message_found = true;
                        }
                    }

                    if (message_found)
                    {
                        // Active message set, attempt to parse it
                        ProtocolMessage.parseProtocolMessage(active_message.code, active_message.data, active_message.endpoint);
                        lock (txqueueMessages)
                        {
                            // Remove it from the queue
                            txqueueMessages.Remove(candidate);
                        }
                        // Sleep a bit to allow other threads to do their thing
                        Thread.Yield();
                    }
                    else
                    {
                        // Sleep for 10ms to prevent cpu waste
                        Thread.Sleep(10);
                    }
                }
                Logging.info("Network queue thread stopped.");
            }
        }
    }
}
