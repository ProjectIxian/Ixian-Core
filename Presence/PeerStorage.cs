using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using DLT.Meta;

namespace DLT
{
    class PeerStorage
    {
        struct Peer
        {
            public string hostname;
            public string walletAddress;
            public DateTime lastSeen;
            public DateTime lastConnectAttempt;
        };

        private static List<Peer> peerList = new List<Peer>();

        public static string peersFilename = "peers.dat";

        public static void addPeerToPeerList(string hostname, string walletAddress, bool storePeersFile = true)
        {
            if(!validateHostname(hostname))
            {
                return;
            }
            Peer p = new Peer();
            p.hostname = hostname;
            p.walletAddress = walletAddress;
            p.lastSeen = DateTime.Now;
            p.lastConnectAttempt = DateTime.MinValue;

            lock (peerList)
            {
                if(peerList.RemoveAll(x => x.hostname == hostname) > 0)
                {
                    storePeersFile = false; // this hostname:port is already in the file, no need to add it again

                }
                peerList.RemoveAll(x => x.walletAddress == walletAddress);

                peerList.Add(p);

                if (peerList.Count > 500)
                {
                    DateTime minLastSeen = peerList.Min(x => x.lastSeen);
                    peerList.RemoveAll(x => x.lastSeen == minLastSeen);
                }
            }

            if (storePeersFile)
            {
                savePeersFile();
            }
        }

        public static bool validateHostname(string address)
        {
            // Check if the address format is correct
            string[] server = address.Split(':');
            if (server.Count() < 2)
            {
                return false;
            }

            if(server[0] == "127.0.0.1"
                || server[0] == "::1"
                || server[0] == "localhost")
            {
                return false;
            }

            return true;
        }

        public static string getRandomMasterNodeIp()
        {
            List<Peer> connectableList = null;
            lock (peerList)
            {
                connectableList = peerList.FindAll(x => (DateTime.Now - x.lastConnectAttempt).TotalSeconds > 30);
            }
            if (connectableList != null && connectableList.Count > 0)
            {
                Random rnd = new Random();
                Peer p = connectableList[rnd.Next(connectableList.Count)];
                p.lastConnectAttempt = DateTime.Now;
                return p.hostname;
            }
            return "";
        }

        // Saves a list of 500 master node addresses to a file
        public static void savePeersFile()
        {
            lock (peerList)
            {
                // Don't write to file if no masternode presences were found in addition to the current node
                if (peerList.Count < 2)
                    return;

                using (TextWriter tw = new StreamWriter(peersFilename))
                {
                    foreach (Peer p in peerList)
                    {
                        tw.WriteLine(p.hostname);
                    }
                }
            }
        }

        // Retrieves the master node address file's contents
        public static bool readPeersFile()
        {
            // Check if the presence file exists
            if (File.Exists(peersFilename))
            {
                Logging.info("Peers file found. Adding addresses to initial connections.");
            }
            else
            {
                return false;
            }

            try
            {
                lock (peerList)
                {
                    peerList.Clear();
                    List<string> ips = File.ReadAllLines(peersFilename).ToList();
                    foreach (string ip in ips)
                    {
                        addPeerToPeerList(ip, ip, false);
                    }
                }
            }
            catch (Exception)
            {
                return false;
            }

            return true;
        }

        // Deletes the presence file cache
        public static void deletePeersFile()
        {
            if (File.Exists(peersFilename))
            {
                File.Delete(peersFilename);
            }

            return;
        }

    }
}
