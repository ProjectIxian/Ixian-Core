using System;

namespace IXICore
{
    /// <summary>
    ///  A network peer (remote endpoint).
    /// </summary>
    public class Peer
    {
        /// <summary>
        ///  Hostname or IP of the remote peer.
        /// </summary>
        public string hostname;
        /// <summary>
        ///  Ixian Wallet address associated with the peer.
        /// </summary>
        public byte[] walletAddress;
        /// <summary>
        /// Timestamp of the last time the peer has been seen on the network.
        /// </summary>
        public long lastSeen;
        /// <summary>
        ///  Unix epoch value of the last time we have attempted to connect to the peer.
        /// </summary>
        public long lastConnectAttempt;
        /// <summary>
        ///  Unix epoch value of the last time we have fully connected to the peer.
        /// </summary>
        public long lastConnected;
        /// <summary>
        ///  Peer rating.
        /// </summary>
        public int rating;

        /// <summary>
        ///  Unix epoch value of when the peer was blacklisted.
        /// </summary>
        public long blacklisted;

        public Peer(string iHostname, byte[] iWalletAddress, long iLastSeen, long iLastConnectAttempt, long iLastConnected, int iRating)
        {
            hostname = iHostname;
            walletAddress = iWalletAddress;
            lastSeen = iLastSeen;
            lastConnectAttempt = iLastConnectAttempt;
            lastConnected = iLastConnected;
            rating = iRating;
            blacklisted = 0;
        }
    };
}