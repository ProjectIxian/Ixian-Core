using DLT;
using System;

namespace IXICore.Meta
{
    abstract class IxianNode
    {
        public abstract ulong getHighestKnownNetworkBlockHeight();
        public abstract Block getLastBlock();
        public abstract ulong getLastBlockHeight();
        public abstract int getLastBlockVersion();
        public abstract char getNodeType();
        public abstract bool addTransaction(Transaction tx);
        public abstract bool isAcceptingConnections();
        public abstract Wallet getWallet(byte[] id);
        public abstract IxiNumber getWalletBalance(byte[] id);
    }

    static class IxianHandler
    {
        private static IxianNode handlerClass = null; 

        public static void setHandler(IxianNode handler_class)
        {
            handlerClass = handler_class;
        }

        public static ulong getHighestKnownNetworkBlockHeight()
        {
            if (handlerClass == null)
            {
                throw new Exception("Handler Class must be specified in IxianHandler Class");
            }
            return handlerClass.getHighestKnownNetworkBlockHeight();
        }

        public static Block getLastBlock()
        {
            if (handlerClass == null)
            {
                throw new Exception("Handler Class must be specified in IxianHandler Class");
            }
            return handlerClass.getLastBlock();
        }

        public static ulong getLastBlockHeight()
        {
            if (handlerClass == null)
            {
                throw new Exception("Handler Class must be specified in IxianHandler Class");
            }
            return handlerClass.getLastBlockHeight();
        }

        public static int getLastBlockVersion()
        {
            if (handlerClass == null)
            {
                throw new Exception("Handler Class must be specified in IxianHandler Class");
            }
            return handlerClass.getLastBlockVersion();
        }

        public static char getNodeType()
        {
            if (handlerClass == null)
            {
                throw new Exception("Handler Class must be specified in IxianHandler Class");
            }
            return handlerClass.getNodeType();
        }

        public static bool addTransaction(Transaction tx)
        {
            if (handlerClass == null)
            {
                throw new Exception("Handler Class must be specified in IxianHandler Class");
            }
            return handlerClass.addTransaction(tx);
        }

        public static bool isAcceptingConnections()
        {
            if (handlerClass == null)
            {
                throw new Exception("Handler Class must be specified in IxianHandler Class");
            }
            return handlerClass.isAcceptingConnections();
        }

        public static Wallet getWallet(byte[] id)
        {
            if (handlerClass == null)
            {
                throw new Exception("Handler Class must be specified in IxianHandler Class");
            }
            return handlerClass.getWallet(id);
        }

        public static IxiNumber getWalletBalance(byte[] id)
        {
            if (handlerClass == null)
            {
                throw new Exception("Handler Class must be specified in IxianHandler Class");
            }
            return handlerClass.getWalletBalance(id);
        }

    }
}
