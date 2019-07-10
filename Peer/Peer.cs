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
        public DateTime lastSeen;
        /// <summary>
        ///  Unix epoch value of the last time we have attempted to connect to the peer.
        /// </summary>
        public long lastConnectAttempt;

        public Peer(string iHostname, byte[] iWalletAddress, DateTime iLastSeen, long iLastConnectAttempt)
        {
            hostname = iHostname;
            walletAddress = iWalletAddress;
            lastSeen = iLastSeen;
            lastConnectAttempt = iLastConnectAttempt;
        }
    };
}