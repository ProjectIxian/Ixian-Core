using DLT.Meta;
using DLT;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace DLT
{
    namespace Network
    {
        // Message codes are for the most part pairs (send/receive)
        public enum ProtocolMessageCode
        {
            hello,
            helloData,
            bye,
            getBlock,
            blockData,
            getMeta,
            metaData,
            getWallet,
            walletData,
            getTransaction,
            transactionData,
            syncPoolState,
            poolState,
            syncWalletState,
            walletState,
            newWallet,
            newTransaction,
            newBlock,
            getNeighbors,
            neighborData,
            getWalletStateChunk,
            walletStateChunk,
            syncPresenceList,
            presenceList,
            updatePresence,
            removePresence,
            s2data,
            updateTransaction,
            s2prepareSend,
            s2generateKeys,
            s2keys,
            ping,
            getBalance,
            balance,
            keepAlivePresence
        }



        public enum RemoteEndpointState
        {
            Initial,
            Established,
            Closed
        }

        public class RemoteEndpoint
        {
            public IPEndPoint remoteIP;
            public Socket clientSocket;
            public RemoteEndpointState state;
            public bool inIO;
            public Thread thread;

            public Presence presence = null;
            public PresenceAddress presenceAddress = null;
        }


    
            
        public class CoreNetworkUtils
        {
            // The list of seed nodes to connect to first. 
            // Domain/IP seperated by : from the port
            public static string[] seedNodes = new string[]
                    {
                        "10.10.1.15:10001"
                    };


            // Get the local accessible IP address of this node
            public static string GetLocalIPAddress()
            {
                var host = Dns.GetHostEntry(Dns.GetHostName());
                foreach (var ip in host.AddressList)
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                    {
                        return ip.ToString();
                    }
                    
                }
                throw new Exception("No network adapters with an IPv4 address in the system!");
            }

            // Get a list of all accessible local IP addresses of this node
            public static List<string> GetAllLocalIPAddresses()
            {
                List<string> ips = new List<string>();
                var host = Dns.GetHostEntry(Dns.GetHostName());
                foreach (var ip in host.AddressList)
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                    {
                        // Console.WriteLine("\t Local IP: {0}", ip.ToString());
                        ips.Add(ip.ToString());
                    }
                }
                return ips;
            }

        }

    }
}