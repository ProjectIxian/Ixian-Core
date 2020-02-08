using IXICore.Network;
using System;
using System.Collections.Generic;

namespace IXICore.Meta
{
    enum NodeStatus
    {
        warmUp = 0, // when the node is warming up
        ready = 1, // when the node is ready to process all data
        stalled = 2, // when the node hasn't received any block updates from the network for over 30 minutes
        stopping = 3 // when the node is stopping
    }

    abstract class IxianNode
    {
        // Required
        public abstract ulong getHighestKnownNetworkBlockHeight();
        public abstract Block getLastBlock();
        public abstract ulong getLastBlockHeight();
        public abstract int getLastBlockVersion();
        public abstract bool addTransaction(Transaction tx);
        public abstract bool isAcceptingConnections();
        public abstract Wallet getWallet(byte[] id);
        public abstract IxiNumber getWalletBalance(byte[] id);
        public abstract WalletStorage getWalletStorage();
        public abstract void parseProtocolMessage(ProtocolMessageCode code, byte[] data, RemoteEndpoint endpoint);

        public abstract void shutdown();

        // Optional
        public virtual void receivedTransactionInclusionVerificationResponse(string txid, bool verified) { }
    }

    static class IxianHandler
    {
        private static IxianNode handlerClass = null;

        private static string _publicIP = "";
        private static int _publicPort = 0;

        public static bool forceShutdown = false;

        public static NodeStatus status = NodeStatus.warmUp;

        public static void setHandler(IxianNode handler_class)
        {
            handlerClass = handler_class;
        }

        private static void verifyHandler()
        {
            if (handlerClass == null)
            {
                throw new Exception("Handler Class must be specified in IxianHandler Class");
            }
        }

        public static ulong getHighestKnownNetworkBlockHeight()
        {
            verifyHandler();
            return handlerClass.getHighestKnownNetworkBlockHeight();
        }

        public static Block getLastBlock()
        {
            verifyHandler();
            return handlerClass.getLastBlock();
        }

        public static ulong getLastBlockHeight()
        {
            verifyHandler();
            return handlerClass.getLastBlockHeight();
        }

        public static int getLastBlockVersion()
        {
            verifyHandler();
            return handlerClass.getLastBlockVersion();
        }

        public static bool addTransaction(Transaction tx)
        {
            verifyHandler();
            return handlerClass.addTransaction(tx);
        }

        public static bool isAcceptingConnections()
        {
            verifyHandler();
            return handlerClass.isAcceptingConnections();
        }

        public static Wallet getWallet(byte[] id)
        {
            verifyHandler();
            return handlerClass.getWallet(id);
        }

        public static IxiNumber getWalletBalance(byte[] id)
        {
            verifyHandler();
            return handlerClass.getWalletBalance(id);
        }

        public static WalletStorage getWalletStorage()
        {
            verifyHandler();
            return handlerClass.getWalletStorage();
        }

        public static void receivedTransactionInclusionVerificationResponse(string txid, bool verified)
        {
            if (handlerClass == null)
            {
                throw new Exception("Handler Class must be specified in IxianHandler Class");
            }
            handlerClass.receivedTransactionInclusionVerificationResponse(txid, verified);
        }

        public static void parseProtocolMessage(ProtocolMessageCode code, byte[] data, RemoteEndpoint endpoint)
        {
            verifyHandler();
            handlerClass.parseProtocolMessage(code, data, endpoint);
        }

        public static void shutdown()
        {
            verifyHandler();
            handlerClass.shutdown();
        }

        /// <summary>
        ///  IP Address on which the node is reachable.
        /// </summary>
        public static string publicIP
        {
            get { return _publicIP; }
            set
            {
                _publicIP = value;
                PresenceList.myPublicAddress = getFullPublicAddress();
            }
        }

        /// <summary>
        ///  Port on which the node is reachable.
        /// </summary>
        public static int publicPort
        {
            get { return _publicPort; }
            set
            {
                _publicPort = value;
                PresenceList.myPublicAddress = getFullPublicAddress();
            }
        }

        public static string getFullPublicAddress()
        {
            return publicIP + ":" + publicPort;
        }

        // Extension methods
        public static TValue TryGet<TKey, TValue>(this IDictionary<TKey, TValue> dictionary, TKey key)
        {
            TValue value;
            dictionary.TryGetValue(key, out value);
            return value;
        }

        public static void AddOrReplace<TKey, TValue>(this IDictionary<TKey, TValue> dico, TKey key, TValue value)
        {
            if (dico.ContainsKey(key))
                dico[key] = value;
            else
                dico.Add(key, value);
        }
    }

    // Extension - lambda comparer for stuff like SortedSet
    public class LambdaComparer<T> : IComparer<T>
    {
        private readonly Comparison<T> comparison;
        public LambdaComparer(Comparison<T> comparison)
        {
            this.comparison = comparison;
        }
        public int Compare(T x, T y)
        {
            return comparison(x, y);
        }
    }

}
