namespace IXICore
{
    /// <summary>
    /// Basic Ixian (compile-time) configuration values.
    /// </summary>
    class CoreConfig
    {
        /// <summary>
        /// Current version of IxiCore.
        /// </summary>
        public static readonly string version = "xcore-0.7.5";

        /// <summary>
        /// Current version of the Ixian network protocol.
        /// </summary>
        public static readonly int protocolVersion = 5;

        /// <summary>
        /// Number of wallets to send in each chunk of data when synchronizing new Master Nodes.
        /// </summary>
        public static readonly int walletStateChunkSplit = 10000;

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
        public static readonly int maxMessageSize = 50000000;
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
        public static readonly int networkClientReconnectInterval = 2 * 1000;
        
        /// <summary>
        /// Interval (in seconds) how often to send a 'Keep-Alive' presence packet into the network for server (M, H, R) nodes.
        /// </summary>
        public static readonly int serverKeepAliveInterval = 200;
        
        /// <summary>
        /// Interval (in seconds) how often to send a 'Keep-Alive' presence packet into the network for client nodes.
        /// </summary>
        public static readonly int clientKeepAliveInterval = 100;
        
        /// <summary>
        /// Presence list entry expiration time (in seconds) for server presences
        /// </summary>
        public static readonly int serverPresenceExpiration = 600;

        /// <summary>
        /// Presence list entry expiration time (in seconds) for client presences
        /// </summary>
        public static readonly int clientPresenceExpiration = 300;

        /// <summary>
        /// Number of retries when connecting to a neighbor node, before giving up.
        /// </summary>
        public static int maximumNeighborReconnectCount = 3;
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
        public static int maximumSubscribableEvents = 500;
        /// <summary>
        /// Maximum number of neighbor Master Nodes this server can accept (used in DLT Node executable).
        /// </summary>
        public static int maximumServerMasterNodes = 200;
        /// <summary>
        /// Maximum number of client connections this server can accept (used in DLT Node executable).
        /// </summary>
        public static int maximumServerClients = 200;

        /// <summary>
        ///  If set to true, all threads will report liveness periodically, thus enabling checking for deadlocks.
        /// </summary>
        /// <remarks>
        ///  See class `ThreadLiveCheck` for details.
        /// </remarks>
        public static readonly bool threadLiveCheckEnabled = false;

        /// <summary>
        /// Command to execute when a new transaction is received for this wallet.
        /// </summary>
        public static string walletNotifyCommand = "";

        /// <summary>
        /// Unique node identifier
        /// </summary>
        public static byte[] device_id = System.Guid.NewGuid().ToByteArray();

        /// <summary>
        /// Product version.
        /// </summary>
        public static string productVersion = "";

        /// <summary>
        /// Number of block headers to save in a single file.
        /// </summary>
        public static ulong maxBlockHeadersPerDatabase = 1000;

        /// <summary>
        /// Prevents client/server network operations. Useful for offline data verification and other offline tests.
        /// </summary>
        public static bool preventNetworkOperations = false;

        /// <summary>
        /// Maximum time difference adjustment in seconds. Clock.networkTime value will not be adjusted to above this number.
        /// </summary>
        public static long maxTimeDifferenceAdjustment = 30;

        /// <summary>
        /// Minimum blockheight activity to store
        /// </summary>
        public static long minActivityBlockHeight = 30000;

        /// <summary>
        /// Time in seconds of how long the node will remain on the blacklist, once blacklisted
        /// </summary>
        public static long NodeBlacklistExpiration = 43200;

        /// <summary>
        /// Maximum number of items to be read from inventory.
        /// </summary>
        public static int maxInventoryItems = 500;

        /// <summary>
        /// Interval at which to send inventory packets in seconds.
        /// </summary>
        public static int inventoryInterval = 1;

        /// <summary>
        /// Maximum number of keep alives to be included in the keep alive chunk.
        /// </summary>
        public static int maximumKeepAlivesPerChunk = 500;

        /// <summary>
        /// Maximum number of transactions sent in each chunk when a fresh DLT Node is synchronizing. (Used in DLT Node executable.)
        /// </summary>
        public static int maximumTransactionsPerChunk = 500;

        /// <summary>
        /// Maximum number of transactions to be included in the tx chunk.
        /// </summary>
        public static int maximumBlockHeadersPerChunk = 1000;
    }
}
