using IXICore.Meta;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace IXICore.Utils
{
    struct NetOutQueueItem
    {
        public string socketDesc;
        public byte[] buffer;
    }

    public class NetDump
    {
        private static NetDump _singletonInstance;

        public static NetDump Instance {
            get
            {
                if(_singletonInstance == null)
                {
                    _singletonInstance = new NetDump();
                }
                return _singletonInstance;
            }
        }
        private readonly object recvLock = new object();
        private Dictionary<int, Queue<NetOutQueueItem>> allRecvQueues = new Dictionary<int, Queue<NetOutQueueItem>>();
        private readonly object sendLock = new object();
        private Dictionary<int, Queue<NetOutQueueItem>> allSendQueues = new Dictionary<int, Queue<NetOutQueueItem>>();

        private readonly static byte[] marker = { 0x10, 0xAB, 0xCD, 0xEF };

        [ThreadStatic]
        private static Queue<NetOutQueueItem> recvQueue;
        [ThreadStatic]
        private static Queue<NetOutQueueItem> sendQueue;

        private string outputFilename;
        private Dictionary<int, BufferedStream> allRecvFiles = new Dictionary<int, BufferedStream>();
        private Dictionary<int, BufferedStream> allSendFiles = new Dictionary<int, BufferedStream>();

        private Thread outputWriter;
        private ThreadLiveCheck TLC;

        
        public bool running { get; private set; }

        private NetDump()
        {
            TLC = new ThreadLiveCheck();
            outputWriter = new Thread(outputWriterWorker);
            outputWriter.Name = "Network_Dumper_Thread";
        }

        public void appendReceived(Socket s, byte[] data, int count)
        {
            if (!running) return;
            if (recvQueue == null)
            {
                lock (recvLock)
                {
                    recvQueue = new Queue<NetOutQueueItem>();
                    allRecvQueues.Add(Thread.CurrentThread.ManagedThreadId, recvQueue);
                }

            }
            lock (recvQueue)
            {
                if (recvQueue.Count > 100)
                {
                    Logging.warn("Losing dump of received messages due to throughput!");
                    return;
                }
                recvQueue.Enqueue(new NetOutQueueItem
                {
                    socketDesc = s.LocalEndPoint.ToString() + "-" + s.RemoteEndPoint.ToString(),
                    buffer = data.Take(count).ToArray()
                });
            }
        }

        public void appendSent(Socket s, byte[] data, int count)
        {
            if (!running) return;
            if(sendQueue == null)
            {
                lock(sendLock)
                {
                    sendQueue = new Queue<NetOutQueueItem>();
                    allSendQueues.Add(Thread.CurrentThread.ManagedThreadId, sendQueue);
                }
            }
            lock (sendQueue)
            {
                if (sendQueue.Count > 100)
                {
                    Logging.warn("Losing dump of sent messages due to throughput!");
                    return;
                }
                sendQueue.Enqueue(new NetOutQueueItem
                {
                    socketDesc = s.LocalEndPoint.ToString() + "-" + s.RemoteEndPoint.ToString(),
                    buffer = data.Take(count).ToArray()
                });
            }
        }

        public void start(string filename)
        {
            Logging.info("Network dump thread starting...");
            running = true;
            outputFilename = filename;
            outputWriter.Start();
        }

        public void shutdown()
        {
            Logging.info("Stopping network dump thread...");
            running = false;
            if (outputWriter != null && outputWriter.ThreadState == ThreadState.Running)
            {
                outputWriter.Join();
            }
            Logging.info("Network dump thread stopped.");
        }

        private void outputWriterWorker()
        {
            while(running)
            {
                TLC.Report();
                int[] keys = null;
                lock(recvLock)
                {
                    keys = allRecvQueues.Keys.ToArray();
                }
                foreach(int tid in keys)
                {
                    if(allRecvQueues[tid].Count > 0)
                    {
                        writeOutputReceived(tid);
                    }
                }
                lock(sendLock)
                {
                    keys = allSendQueues.Keys.ToArray();
                }
                foreach(int tid in keys)
                {
                    if(allSendQueues[tid].Count>0)
                    {
                        writeOutputSent(tid);
                    }
                }
                Thread.Sleep(250);
            }
            // send remainder
            lock(recvLock)
            {
                foreach(int tid in allRecvQueues.Keys)
                {
                    int written = 0;
                    do
                    {
                        written = writeOutputReceived(tid);
                    } while (written > 0);
                }
            }
            lock(sendLock)
            {
                foreach(int tid in allSendQueues.Keys)
                {
                    int written = 0;
                    do
                    {
                        written = writeOutputSent(tid);
                    } while (written > 0);
                }
            }
            
            foreach(int tid in allRecvFiles.Keys)
            {
                allRecvFiles[tid].Flush();
            }
            foreach(int tid in allSendFiles.Keys)
            {
                allSendFiles[tid].Flush();
            }

        }

        private int writeOutputReceived(int thread_id)
        {
            lock(allRecvQueues[thread_id])
            {
                int num_bytes = 0;
                while(allRecvQueues[thread_id].Count > 0 && num_bytes < 65535)
                {
                    if(!allRecvFiles.ContainsKey(thread_id))
                    {
                        allRecvFiles.Add(thread_id, new BufferedStream(new FileStream(outputFilename + "_" + thread_id + "_recv.dat", FileMode.Create)));
                    }
                    NetOutQueueItem queue_item = allRecvQueues[thread_id].Dequeue();
                    byte[] socket_desc = Encoding.UTF8.GetBytes(queue_item.socketDesc);
                    allRecvFiles[thread_id].Write(marker, 0, marker.Length);
                    allRecvFiles[thread_id].Write(socket_desc, 0, socket_desc.Length);
                    allRecvFiles[thread_id].Write(queue_item.buffer, 0, queue_item.buffer.Length);
                    num_bytes += socket_desc.Length + queue_item.buffer.Length;
                }
                return num_bytes;
            }
        }

        private int writeOutputSent(int thread_id)
        {
            lock (allSendQueues[thread_id])
            {
                int num_bytes = 0;
                while (allSendQueues[thread_id].Count > 0 && num_bytes < 65535)
                {
                    if (!allSendFiles.ContainsKey(thread_id))
                    {
                        allSendFiles.Add(thread_id, new BufferedStream(new FileStream(outputFilename + "_" + thread_id + "_sent.dat", FileMode.Create)));
                    }
                    NetOutQueueItem queue_item = allSendQueues[thread_id].Dequeue();
                    byte[] socket_desc = Encoding.UTF8.GetBytes(queue_item.socketDesc);
                    allSendFiles[thread_id].Write(marker, 0, marker.Length);
                    allSendFiles[thread_id].Write(socket_desc, 0, socket_desc.Length);
                    allSendFiles[thread_id].Write(queue_item.buffer, 0, queue_item.buffer.Length);
                    num_bytes += socket_desc.Length + queue_item.buffer.Length;
                }
                return num_bytes;
            }
        }
    }
}
