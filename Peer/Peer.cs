using System;

namespace DLT
{
    class Peer
    {
        public string hostname;
        public byte[] walletAddress;
        public DateTime lastSeen;
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