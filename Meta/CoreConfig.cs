using DLT;
using System.Text;

namespace IXICore
{
    /// <summary>
    /// Basic Ixian (compile-time) configuration values.
    /// </summary>
    class CoreConfig
    {
        /// <summary>
        /// Current version of the Ixian network protocol.
        /// </summary>
        public static readonly int protocolVersion = 5;

        /// <summary>
        ///  Target Block generation interval, in seconds.
        /// </summary>
        /// <remarks>
        ///  The DLT will strive to generate new Blocks according to this value.
        /// </remarks>
        public static readonly int blockGenerationInterval = 30;

        /// <summary>
        /// Number of wallets to send in each chunk of data when synchronizing new Master Nodes.
        /// </summary>
        public static readonly int walletStateChunkSplit = 10000;

        /// <summary>
        ///  Number of blocks this particular is required to keep before discarding older blocks. Blocks older than the redaction window can be discarded.
        /// </summary>
        /// <remarks>
        ///  The redacted window, together with the block generation inverval specify that blocks should be kept for approximately 15 days.
        /// </remarks>
        public static ulong redactedWindowSize = 43200;
        /// <summary>
        ///  Number of blocks all Master Nodes are required to keep before discarding older blocks. Blocks older than the redaction window can be discarded.
        /// </summary>
        /// <remarks>
        ///  The redacted window, together with the block generation inverval specify that blocks should be kept for approximately 15 days.
        /// </remarks>
        public static ulong minRedactedWindowSize = 43200;
        /// <summary>
        ///  [LEGACY] Number of v0 and v1 blocks all Master Nodes are required to keep before discarding older blocks. Blocks older than the redaction window can be discarded.
        /// </summary>
        private static readonly ulong minRedactedWindowSize_v0 = 43200;
        /// <summary>
        ///  Number of v2 blocks all Master Nodes are required to keep before discarding older blocks. Blocks older than the redaction window can be discarded.
        /// </summary>
        /// <remarks>
        ///  The redacted window, together with the block generation inverval specify that blocks should be kept for approximately 7 days.
        /// </remarks>
        private static readonly ulong minRedactedWindowSize_v2 = 20000;
        /// <summary>
        /// Nonexistant wallet address which is used in the 'from' fields for PoW and PoS transactions, where currency is generated "from nothing".
        /// </summary>
        public static readonly byte[] ixianInfiniMineAddress = Base58Check.Base58CheckEncoding.DecodePlain("1ixianinfinimine234234234234234234234234234242HP");
        /// <summary>
        /// Default security (in bits) of the generated RSA wallet keys.
        /// </summary>
        public static readonly int defaultRsaKeySize = 4096;
        /// <summary>
        ///  This value is used when clients subscribe to events on their connected Master Nodes.
        /// </summary>
        /// <remarks>
        ///  The best privacy would be achieved if the Master Node forwards all Transactions to all clients, who then sort out the 'interesting' ones.
        ///  In this way, the Master Node does not know which addresses are the client's. This, however, is impractical due to the number of transactions and clients each
        ///  Master node should support.
        ///  On the other hand, if a client specifies which addresses it's interested in, this could be a potential leak of information, allowing Master Nodes
        ///  to infer which Wallets are associated with each other and reduce the privacy element of the Ixian DLT Network.
        ///  A specialized algorithm has been developed which allows the client to subscribe to *some* Wallet addresses, but not all, with potential false positives to further obscure the details.
        ///  This will reduce the required bandwidth on the Master Node, while preventing the Master Node from immediately knowing which addresses belong to the client
        ///  (until a transaction for that address appears on the blockchain).
        ///  The setting `matcherBytesPerAddress` selects how precise this matching is and how many false positives it creates. Better precision decreases privacy, but lower precision increases the
        ///  Master Node bandwidth requirements. A balanced default value is chosen here.
        /// </remarks>
        public static readonly int matcherBytesPerAddress = 4;
        /// <summary>
        ///  How often a special kind of block, called a 'superblock' is generated on the Ixian blockchain.
        /// </summary>
        /// <remarks>
        ///  Superblocks condense the information of the previous blocks (from the previous superblock to the current one), so that much of the superfluous blockchain data
        ///  can be dropped and still allow clients to bootstrap safely from potentially untrusted Master Nodes.
        /// </remarks>
        public static readonly ulong superblockInterval = 1000;


        /// <summary>
        ///  Maximum number of messages in the incoming network queue, before the connection are throttled.
        /// </summary>
        public static readonly int maxNetworkQueue = 10000;
        /// <summary>
        ///  Maximum number of outgoing messages in the queue per each remote endpoint.
        /// </summary>
        public static readonly int maxSendQueue = 10000;
        /// <summary>
        ///  Maximum size of a network message in bytes.
        /// </summary>
        public static readonly int maxMessageSize = 5000000;
        /// <summary>
        ///  Pong interval (in seconds) - if no data has been received from connected remote client for this time, a special packet will be sent instead to 'wake up' the receiver.
        /// </summary>
        public static readonly int pongInterval = 2;
        /// <summary>
        ///  Timeout (in seconds) before a remote client is disconnected if no data is received from it.
        /// </summary>
        public static readonly int pingTimeout = 10;
        /// <summary>
        /// Duration (in milliseconds) between reconnection attempts to remote clients.
        /// </summary>
        public static readonly int networkClientReconnectInterval = 10 * 1000;
        /// <summary>
        /// Interval (in seconds) how often to send a 'Keep-Alive' packet into the network.
        /// </summary>
        public static readonly int keepAliveInterval = 45;
        /// <summary>
        /// Number of retries when connecting to a neighbor node, before giving up.
        /// </summary>
        public static readonly int maximumNeighborReconnectCount = 3;
        /// <summary>
        ///  Target number of simultaneously connected neighbors.
        /// </summary>
        /// <remarks>
        ///  If more neighbors are connected, they will slowly be disconnected. 
        ///  If fewer neighbors are connected, more will be added over time.
        /// </remarks>
        public static int simultaneousConnectedNeighbors = 6;
        /// <summary>
        /// Maximum number of events a client can be subscribed to.
        /// </summary>
        public static readonly int maximumSubscribableEvents = 500;
        /// <summary>
        /// Maximum number of neighbor Master Nodes this server can accept (used in DLT Node executable).
        /// </summary>
        public static readonly int maximumServerMasterNodes = 200;
        /// <summary>
        /// Maximum number of client connections this server can accept (used in DLT Node executable).
        /// </summary>
        public static readonly int maximumServerClients = 200;
        /// <summary>
        /// Amount of signatures (ratio) of consenting signatures vs. available Master Nodes before a block can be accepted.
        /// </summary>
        public static readonly double networkConsensusRatio = 0.75;

        /// <summary>
        /// Minimum funds a wallet must have before it is allowed to participate in the block consensus algorithm. (used in DLT Node executable).
        /// </summary>
        public static readonly IxiNumber minimumMasterNodeFunds = new IxiNumber("20000");
        /// <summary>
        /// Transaction fee per kilobyte. Total transaction size is used. (Used in DLT Node executable.)
        /// </summary>
        public static readonly IxiNumber transactionPrice = new IxiNumber("0.00005000");
        /// <summary>
        /// Amount of transaction fees, in percent, that are deposited into the foundation wallet, which funds the development of Ixian technology. (Used in DLT Node executable.)
        /// </summary>
        public static readonly IxiNumber foundationFeePercent = 3;
        /// <summary>
        /// Address of the Ixian foundation wallet, which is used to fund development of the Ixian technology stack. (Used in DLT Node executable.)
        /// </summary>
        public static readonly byte[] foundationAddress = Base58Check.Base58CheckEncoding.DecodePlain("153xXfVi1sznPcRqJur8tutgrZecNVYGSzetp47bQvRfNuDix"); // Foundation wallet address
        /// <summary>
        /// Initial price for relaying a kilobyte of data through an S2 node. (Used in S2 Node executable.)
        /// </summary>
        public static readonly IxiNumber relayPriceInitial = new IxiNumber("0.0002");
        /// <summary>
        /// Maximum number of transactions in each block. (Used in DLT Node executable.)
        /// </summary>
        public static readonly ulong maximumTransactionsPerBlock = 2000;
        /// <summary>
        /// Maximum number of transactions sent in each chunk when a fresh DLT Node is synchronizing. (Used in DLT Node executable.)
        /// </summary>
        public static readonly int maximumTransactionsPerChunk = 500;

        /// <summary>
        /// Initial value for seeding the Transaction SHA512 checksum generator.
        /// </summary>
        public static readonly byte[] ixianChecksumLock = Encoding.UTF8.GetBytes("Ixian");
        /// <summary>
        /// Initial value for seeding various SHA512 checksums throughout Ixian.
        /// </summary>
        public static readonly string ixianChecksumLockString = "Ixian";

        /// <summary>
        ///  If set to true, all threads will report liveness periodically, thus enabling checking for deadlocks.
        /// </summary>
        /// <remarks>
        ///  See class `ThreadLiveCheck` for details.
        /// </remarks>
        public static readonly bool threadLiveCheckEnabled = false;

        /// <summary>
        ///  Retrieves the lenght of the redacted window based on the block version in use.
        /// </summary>
        /// <param name="block_version">Block version for which you'd like to calculate the redacted window.</param>
        /// <returns>Redacted window length.</returns>
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
