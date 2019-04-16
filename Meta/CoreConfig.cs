using DLT;
using System;
using System.Collections.Generic;
using System.Text;

namespace IXICore
{
    class CoreConfig
    {
        // Protocol
        public static readonly int protocolVersion = 5; // Ixian protocol version
        public static readonly int walletStateChunkSplit = 10000; // 10K wallets per chunk
        public static ulong redactedWindowSize = 43200; // approx 15 days. Represents the redacted window size of this node
        public static ulong minRedactedWindowSize = 43200; // Represents the minimum redacted window size on any node
        private static readonly ulong minRedactedWindowSize_v0 = 43200; // approx 15 days. Represents the redacted window size of v0 and v1 blocks
        private static readonly ulong minRedactedWindowSize_v2 = 20000; // approx 7 days. Represents the redacted window size of v2 blocks
        public static readonly byte[] ixianInfiniMineAddress = Base58Check.Base58CheckEncoding.DecodePlain("1ixianinfinimine234234234234234234234234234242HP");
        public static readonly int defaultRsaKeySize = 4096;
        public static readonly int matcherBytesPerAddress = 4; // Used for client address masking
        public static readonly ulong superblockInterval = 1000; // generate super block every n blocks

        // Networking
        public static readonly int maxNetworkQueue = 10000; // Maximum number of received messages in network queue before throttling starts
        public static readonly int maxSendQueue = 10000; // Maximum number of sent messages in queue per endpoint
        public static readonly int maxMessageSize = 5000000; // Maximum message size in bytes
        public static readonly int pongInterval = 2; // pong interval in seconds (if no data is sent for x seconds, pong will be sent)
        public static readonly int pingTimeout = 10; // how long to wait in seconds for data before disconnecting a node
        public static readonly int networkClientReconnectInterval = 10 * 1000; // Time in milliseconds
        public static readonly int keepAliveInterval = 45; // Number of seconds to wait until next keepalive ping
        public static readonly int maximumNeighborReconnectCount = 3; // Number of retries before proceeding to a different neighbor node
        public static int simultaneousConnectedNeighbors = 6; // Desired number of simulatenously connected neighbor nodes
        public static readonly int maximumSubscribableEvents = 500; // Maximum number of events a client can be subscribed to
        public static readonly int maximumServerMasterNodes = 200; // Maximum number of clients this server can accept 
        public static readonly int maximumServerClients = 200; // Maximum number of clients this server can accept
        public static readonly double networkConsensusRatio = 0.75;

        // Transactions and fees
        public static readonly IxiNumber minimumMasterNodeFunds = new IxiNumber("20000"); // Limit master nodes to this amount or above
        public static readonly IxiNumber transactionPrice = new IxiNumber("0.00005000"); // Per kB
        public static readonly IxiNumber foundationFeePercent = 3; // 3% of transaction fees
        public static readonly byte[] foundationAddress = Base58Check.Base58CheckEncoding.DecodePlain("153xXfVi1sznPcRqJur8tutgrZecNVYGSzetp47bQvRfNuDix"); // Foundation wallet address
        public static readonly IxiNumber relayPriceInitial = new IxiNumber("0.0002"); // Per kB
        public static readonly ulong maximumTransactionsPerBlock = 2000; // Limit the maximum number of transactions in a newly generated block
        public static readonly int maximumTransactionsPerChunk = 500; // Limit the maximum number of transactions per transaction chunk

        // Misc
        public static readonly byte[] ixianChecksumLock = Encoding.UTF8.GetBytes("Ixian");
        public static readonly string ixianChecksumLockString = "Ixian";

        // Debug
        public static readonly bool threadLiveCheckEnabled = false;


        public static ulong getRedactedWindowSize(int block_version = -1)
        {
            if(block_version == -1)
            {
                return minRedactedWindowSize;
            }
            if (block_version < 2)
            {
                return minRedactedWindowSize_v0;
            }
            if(block_version >= 2)
            {
                return minRedactedWindowSize_v2;
            }
            return minRedactedWindowSize;
        }
    }
}
