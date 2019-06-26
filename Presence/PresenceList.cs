using DLT.Meta;
using DLT.Network;
using IXICore;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DLT
{
    class PresenceList
    {
        public static List<Presence> presences = new List<Presence> { }; // The presence list

        public static PresenceAddress curNodePresenceAddress = null;
        public static Presence curNodePresence = null;

        // private
        private static Dictionary<char, long> presenceCount = new Dictionary<char, long>();

        private static Thread keepAliveThread;
        private static bool autoKeepalive = false;
        public static ThreadLiveCheck TLC;


        // Generate an initial presence list
        public static void generatePresenceList(string initial_ip, char type = 'M')
        {
            Logging.info("Generating presence list.");

            // Initialize with the default presence state
            curNodePresenceAddress = new PresenceAddress(Config.device_id, string.Format("{0}:{1}", initial_ip, Config.serverPort), type, Config.version, 0, null);
            curNodePresence = new Presence(Node.walletStorage.getPrimaryAddress(), Node.walletStorage.getPrimaryPublicKey(), null, curNodePresenceAddress);
        }

        // Searches through the entire presence list to find a matching IP with a specific type.
        // Returns true if found, otherwise false
        public static bool containsIP(string ip, char type)
        {
            lock (presences)
            {
                foreach (Presence pr in presences)
                {
                    foreach (PresenceAddress addr in pr.addresses)
                    {
                        if (addr.type == type)
                        {
                            if (addr.address.StartsWith(ip))
                                return true;
                        }
                    }
                }
            }
            // If we reach this point, no matching address was found
            return false;
        }

        // Searches through the entire presence list to find a presence with a matching wallet
        // Returns the found presence, otherwise null
        public static Presence containsWalletAddress(byte[] wallet)
        {
            if (wallet == null)
                return null;

            lock (presences)
            {
                foreach (Presence pr in presences)
                {
                    if (pr.wallet.SequenceEqual(wallet))
                        return pr;
                }
            }

            return null;
        }

        // Update a presence entry. If the wallet address is not found, it creates a new entry in the Presence List.
        // If the wallet address is found in the presence list, it adds any new addresses from the specified presence.
        public static Presence updateEntry(Presence presence, RemoteEndpoint skipEndpoint = null)
        {
            if(presence == null)
            {
                return null;
            }

            bool entryUpdated = false;

            Presence return_presence = null;
            lock(presences)
            {
                Presence pr = presences.Find(x => x.wallet.SequenceEqual(presence.wallet));
                if (pr != null)
                {
                    entryUpdated = false;

                    // Go through all addresses and add any missing ones
                    foreach (PresenceAddress local_addr in presence.addresses)
                    {
                        long currentTime = Core.getCurrentTimestamp();
                        long lTimestamp = local_addr.lastSeenTime;
                        // Check for tampering. Includes a +300, -30 second synchronization zone
                        if ((currentTime - lTimestamp) > 300 || (currentTime - lTimestamp) < -30)
                        {
                            Logging.warn(string.Format("[PL] Potential KEEPALIVE tampering for {0} {1}. Skipping; {2} - {3}", Crypto.hashToString(pr.wallet), local_addr.address, currentTime, lTimestamp));
                            continue;
                        }

                        bool addressfound = false;

                        PresenceAddress addr = pr.addresses.Find(x => x.device == local_addr.device);
                        if (addr != null)
                        {
                            addressfound = true;
                            if(addr.address != local_addr.address)
                            {
                                addr.address = local_addr.address;
                                addr.lastSeenTime = local_addr.lastSeenTime;
                                entryUpdated = true;
                            }
                            else if (addr.lastSeenTime < local_addr.lastSeenTime)
                            {
                                addr.lastSeenTime = local_addr.lastSeenTime;
                                entryUpdated = true;
                                //Console.WriteLine("[PL] Last time updated for {0}", addr.device);
                            }
                        }

                        // Add the address if it's not found
                        if (addressfound == false && entryUpdated == false)
                        {
                            //Logging.info("[PL] Adding new address for {0}", presence.wallet);
                            pr.addresses.Add(local_addr);
                            entryUpdated = true;

                            lock (presenceCount)
                            {
                                if (!presenceCount.ContainsKey(local_addr.type))
                                {
                                    presenceCount.Add(local_addr.type, 0);
                                }
                                presenceCount[local_addr.type]++;
                            }
                        }

                    }

                    // Check if the entry was updated
                    if(entryUpdated == false)
                    {
                        return pr;
                    }

                    // Return the stored presence list entity
                    return_presence = pr;
                }else
                {
                    // Insert a new entry
                    //Console.WriteLine("[PL] Adding new entry for {0}", presence.wallet);
                    presences.Add(presence);

                    lock (presenceCount)
                    {
                        foreach (PresenceAddress pa in presence.addresses)
                        {
                            if (!presenceCount.ContainsKey(pa.type))
                            {
                                presenceCount.Add(pa.type, 0);
                            }
                            presenceCount[pa.type]++;
                        }
                    }

                    return_presence = presence;
                }
            }

            return return_presence;
        }

        public static bool removeAddressEntry(byte[] wallet_address, PresenceAddress address)
        {
            lock (presences)
            {
                //Console.WriteLine("[PL] Received removal for {0} : {1}", wallet_address, address.address);
                Presence listEntry = presences.Find(x => x.wallet.SequenceEqual(wallet_address));

                // Check if there is such an entry in the presence list
                if (listEntry != null)
                {
                    var addresses_to_remove = listEntry.addresses.FindAll(x => x == address);

                    foreach (var addr in addresses_to_remove)
                    {
                        lock (presenceCount)
                        {
                            if (presenceCount.ContainsKey(addr.type))
                            {
                                presenceCount[addr.type]--;
                            }
                        }
                        listEntry.addresses.Remove(addr);
                    }

                    int address_count = listEntry.addresses.Count;
                    //Console.WriteLine("[PL] --->> Addresses: {0}", address_count);

                    if (address_count == 0)
                    {
                        // Remove it from the list
                        presences.Remove(listEntry);
                    }

                    // If presence address is a relay node, remove all other presences with matching ip:port
                    // TODO: find a better way to handle this while preventing modify-during-enumeration issues
                    if (address.type == 'R')
                    {
                        // Retrieve the ip+port of the relay address
                        string relay_address = address.address;

                        // Store a copy of the presence list to allow safe modifications while enumerating
                        List<Presence> safe_presences = new List<Presence>(presences);

                        // Go through the entire presence list
                        foreach (Presence pr in safe_presences)
                        {
                            // Store a list of presence addresses that correspond to the relay node we're removing
                            List<PresenceAddress> relayClients = new List<PresenceAddress>();

                            foreach (PresenceAddress pa in pr.addresses)
                            {
                                if (pa.address.SequenceEqual(relay_address))
                                {
                                    // Check if it's a client node
                                    if (pa.type == 'C')
                                    {
                                        relayClients.Add(pa);
                                    }
                                }
                            }

                            // Check if the presence contains at least one relay client
                            if (relayClients.Count > 0)
                            {
                                // Go through each relay client and safely remove it's address entry
                                // Note that it also propagates network messages
                                foreach (PresenceAddress par in relayClients)
                                {
                                    removeAddressEntry(pr.wallet, par);
                                }

                                relayClients.Clear();
                            }

                        }

                        // Clear the safe list of presences
                        safe_presences.Clear();
                    }

                    return true;
                }
            }

            return false;
        }


        // Get the current complete presence list
        public static byte[] getBytes()
        {
            lock (presences)
            {
                using (MemoryStream m = new MemoryStream())
                {
                    using (BinaryWriter writer = new BinaryWriter(m))
                    {
                        // Write the number of presences
                        int num_presences = presences.Count();
                        writer.Write(num_presences);

                        // Write each presence
                        foreach (Presence presence in presences)
                        {
                            byte[] presence_data = presence.getBytes();
                            int presence_data_size = presence_data.Length;
                            writer.Write(presence_data_size);
                            writer.Write(presence_data);
                        }
                    }
                    return m.ToArray();
                }
            }
        }

        public static bool syncFromBytes(byte[] bytes)
        {
            // Clear the presence list
            clear();

            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    // Read the number of presences
                    int num_presences = reader.ReadInt32();
                    if (num_presences < 0)
                        return false;

                    try
                    {
                        for (int i = 0; i < num_presences; i++)
                        {
                            int presence_data_size = reader.ReadInt32();
                            if (presence_data_size < 1)
                                continue;
                            byte[] presence_bytes = reader.ReadBytes(presence_data_size);
                            Presence new_presence = new Presence(presence_bytes);
                            lock (presences)
                            {
                                presences.Add(new_presence);
                            }
                            lock (presenceCount)
                            {
                                foreach (PresenceAddress pa in new_presence.addresses)
                                {
                                    if (!presenceCount.ContainsKey(pa.type))
                                    {
                                        presenceCount.Add(pa.type, 0);
                                    }
                                    presenceCount[pa.type]++;
                                }
                            }

                        }
                    }
                    catch (Exception e)
                    {
                        Logging.error(string.Format("Error reading presence list: {0}", e.ToString()));
                        return false;
                    }

                }
            }

            return true;
        }

        public static bool verifyPresence(Presence presence)
        {
            if (presence.wallet.Length > 128 && presence.wallet.Length < 4)
            {
                return false;
            }

            if (presence.pubkey == null || presence.pubkey.Length < 32 || presence.pubkey.Length > 2500)
            {
                return false;
            }

            foreach (var entry in presence.addresses)
            {
                if (entry.device.Length > 64)
                {
                    return false;
                }

                if (entry.nodeVersion.Length > 64)
                {
                    return false;
                }

                if (entry.address.Length > 24 && entry.address.Length < 9)
                {
                    return false;
                }

            }

            return true;
        }

        // Update a presence from a byte array
        public static bool updateFromBytes(byte[] bytes)
        {
            Presence presence = new Presence(bytes);

            if(verifyPresence(presence))
            {
                updateEntry(presence);
                return true;
            }


            return false;
        }

        public static void startKeepAlive()
        {
            TLC = new ThreadLiveCheck();
            // Start the keepalive thread
            autoKeepalive = true;
            keepAliveThread = new Thread(keepAlive);
            keepAliveThread.Name = "Presence_List_Keep_Alive_Thread";
            keepAliveThread.Start();
        }

        public static void stopKeepAlive()
        {
            autoKeepalive = false;
            if (keepAliveThread != null)
            {
                keepAliveThread.Abort();
                keepAliveThread = null;
            }
        }

        // Sends perioding keepalive network messages
        private static void keepAlive()
        {
            while (autoKeepalive)
            {
                TLC.Report();
                // Wait x seconds before rechecking
                for (int i = 0; i < CoreConfig.keepAliveInterval; i++)
                {
                    if (autoKeepalive == false)
                    {
                        Thread.Yield();
                        return;
                    }
                    // Sleep for one second
                    Thread.Sleep(1000);
                }

                if(curNodePresenceAddress.type == 'W')
                {
                    continue; // no need to send PL for worker nodes
                }

                try
                {

                    byte[] ka_bytes = null;
                    ka_bytes = keepAlive_v1();

                    byte[] address = null;

                    // Update self presence
                    PresenceList.receiveKeepAlive(ka_bytes, out address);

                    // Send this keepalive to all connected non-clients
                    CoreProtocolMessage.broadcastProtocolMessage(new char[] { 'M', 'R', 'H', 'W' }, ProtocolMessageCode.keepAlivePresence, ka_bytes, address);

                    // Send this keepalive message to all connected clients
                    CoreProtocolMessage.broadcastEventDataMessage(NetworkEvents.Type.keepAlive, address, ProtocolMessageCode.keepAlivePresence, ka_bytes, address);
                }
                catch (Exception)
                {
                    continue;
                }

            }

            Thread.Yield();
        }

        private static byte[] keepAlive_v0()
        {
            // Prepare the keepalive message
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(0);

                    byte[] wallet = Node.walletStorage.getPrimaryAddress();
                    writer.Write(wallet.Length);
                    writer.Write(wallet);

                    writer.Write(Config.device_id);

                    // Add the unix timestamp
                    long timestamp = Core.getCurrentTimestamp();
                    writer.Write(timestamp);

                    string hostname = Node.getFullAddress();
                    writer.Write(hostname);

                    // Add a verifiable signature
                    byte[] private_key = Node.walletStorage.getPrimaryPrivateKey();
                    byte[] signature = CryptoManager.lib.getSignature(Encoding.UTF8.GetBytes(ConsensusConfig.ixianChecksumLockString + "-" + Config.device_id + "-" + timestamp + "-" + hostname), private_key);
                    writer.Write(signature.Length);
                    writer.Write(signature);

                    PresenceList.curNodePresenceAddress.lastSeenTime = timestamp;
                    PresenceList.curNodePresenceAddress.signature = signature;
                }

                return m.ToArray();
            }
        }

        private static byte[] keepAlive_v1()
        {
            // Prepare the keepalive message
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(1);

                    byte[] wallet = Node.walletStorage.getPrimaryAddress();
                    writer.Write(wallet.Length);
                    writer.Write(wallet);

                    writer.Write(Config.device_id);

                    // Add the unix timestamp
                    long timestamp = Core.getCurrentTimestamp();
                    writer.Write(timestamp);

                    string hostname = Node.getFullAddress();
                    writer.Write(hostname);

                    writer.Write(PresenceList.curNodePresenceAddress.type);

                    // Add a verifiable signature
                    byte[] private_key = Node.walletStorage.getPrimaryPrivateKey();
                    byte[] signature = CryptoManager.lib.getSignature(m.ToArray(), private_key);
                    writer.Write(signature.Length);
                    writer.Write(signature);

                    PresenceList.curNodePresenceAddress.lastSeenTime = timestamp;
                    PresenceList.curNodePresenceAddress.signature = signature;
                }

                return m.ToArray();
            }
        }

        // Called when receiving a keepalive network message. The PresenceList will update the appropriate entry based on the timestamp.
        // Returns TRUE if it updated an entry in the PL
        // Sets the out address parameter to be the KA wallet's address or null if an error occured
        public static bool receiveKeepAlive(byte[] bytes, out byte[] address)
        {
            address = null;

            // Get the current timestamp
            long currentTime = Core.getCurrentTimestamp();

            try
            {
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        int keepAliveVersion = reader.ReadInt32();
                        int walletLen = reader.ReadInt32();
                        byte[] wallet = reader.ReadBytes(walletLen);
                        
                        // Assign the out address parameter
                        address = wallet;

                        string deviceid = reader.ReadString();
                        long timestamp = reader.ReadInt64();
                        string hostname = reader.ReadString();
                        char node_type = '0';
                        if (keepAliveVersion > 0)
                        {
                            node_type = reader.ReadChar();
                        }
                        int sigLen = reader.ReadInt32();
                        byte[] signature = reader.ReadBytes(sigLen);
                        //Logging.info(String.Format("[PL] KEEPALIVE request from {0}", hostname));

                        if (node_type == 'C' || node_type == 'R')
                        {
                            // all good, continue
                        }
                        else if (node_type == 'M' || node_type == 'H')
                        {
                            // check balance
                            if (Node.walletState.getWalletBalance(wallet) < ConsensusConfig.minimumMasterNodeFunds)
                            {
                                return false;
                            }
                        }
                        else if(node_type != '0')
                        {
                            // reject everything else
                            return false;
                        }

                        lock (presences)
                        {
                            Presence listEntry = presences.Find(x => x.wallet.SequenceEqual(wallet));
                            if (listEntry == null && wallet.SequenceEqual(Node.walletStorage.getPrimaryAddress()))
                            {
                                Logging.error(string.Format("My entry was removed from local PL, readding."));
                                updateEntry(curNodePresence);
                                listEntry = presences.Find(x => x.wallet.SequenceEqual(wallet));
                            }

                            // Check if no such wallet found in presence list
                            if (listEntry == null)
                            {
                                // request for additional data
                                using (MemoryStream mw = new MemoryStream())
                                {
                                    using (BinaryWriter writer = new BinaryWriter(mw))
                                    {
                                        writer.Write(wallet.Length);
                                        writer.Write(wallet);

                                        CoreProtocolMessage.broadcastProtocolMessage(new char[] { 'M', 'R' }, ProtocolMessageCode.getPresence, mw.ToArray(), null);
                                    }
                                }
                                return false;
                            }
                            if (keepAliveVersion == 0)
                            {
                                // Verify the signature
                                if (CryptoManager.lib.verifySignature(Encoding.UTF8.GetBytes(ConsensusConfig.ixianChecksumLockString + "-" + deviceid + "-" + timestamp + "-" + hostname), listEntry.pubkey, signature) == false)
                                {
                                    Logging.warn(string.Format("[PL] KEEPALIVE tampering for {0} {1}, incorrect Sig.", Base58Check.Base58CheckEncoding.EncodePlain(listEntry.wallet), hostname));
                                    return false;
                                }
                            }else
                            {
                                // Verify the signature
                                if (CryptoManager.lib.verifySignature(bytes.Take(bytes.Length - sigLen - 4).ToArray(), listEntry.pubkey, signature) == false)
                                {
                                    Logging.warn(string.Format("[PL] KEEPALIVE tampering for {0} {1}, incorrect Sig.", Base58Check.Base58CheckEncoding.EncodePlain(listEntry.wallet), hostname));
                                    return false;
                                }
                            }

                            PresenceAddress pa = listEntry.addresses.Find(x => x.address == hostname && x.device == deviceid);

                            if(pa != null)
                            {
                                // Check the node type
                                if (pa.lastSeenTime != timestamp)
                                {
                                    // Check for outdated timestamp
                                    if (timestamp < pa.lastSeenTime)
                                    {
                                        // We already have a newer timestamp for this entry
                                        return false;
                                    }

                                    // Check for tampering. Includes a +300, -30 second synchronization zone
                                    if ((currentTime - timestamp) > 300 || (currentTime - timestamp) < -30)
                                    {
                                        Logging.warn(string.Format("[PL] Potential KEEPALIVE tampering for {0} {1}. Timestamp {2}", Base58Check.Base58CheckEncoding.EncodePlain(listEntry.wallet), pa.address, timestamp));
                                        return false;
                                    }

                                    // Update the timestamp
                                    pa.lastSeenTime = timestamp;
                                    pa.signature = signature;
                                    if (node_type != '0')
                                    {
                                        if (pa.type != node_type)
                                        {
                                            lock (presenceCount)
                                            {
                                                presenceCount[pa.type]--;
                                                if (!presenceCount.ContainsKey(node_type))
                                                {
                                                    presenceCount.Add(node_type, 0);
                                                }
                                                presenceCount[node_type]++;
                                            }
                                        }
                                        pa.type = node_type;
                                    }

                                    if (pa.type == 'M' || pa.type == 'H')
                                    {
                                        PeerStorage.addPeerToPeerList(hostname, wallet);
                                    }

                                    //Console.WriteLine("[PL] LASTSEEN for {0} - {1} set to {2}", hostname, deviceid, pa.lastSeenTime);
                                    return true;
                                }
                            }
                            else
                            {
                                if (wallet.SequenceEqual(Node.walletStorage.getPrimaryAddress()))
                                {
                                    updateEntry(curNodePresence);
                                    return true;
                                }
                                else
                                {
                                    using (MemoryStream mw = new MemoryStream())
                                    {
                                        using (BinaryWriter writer = new BinaryWriter(mw))
                                        {
                                            writer.Write(wallet.Length);
                                            writer.Write(wallet);

                                            CoreProtocolMessage.broadcastProtocolMessage(new char[] { 'M', 'R' }, ProtocolMessageCode.getPresence, mw.ToArray(), null);
                                        }
                                    }
                                    return false;
                                }
                            }
                        }
                    }
                }
            }
            catch(Exception e)
            {
                Logging.error("Exception occured in receiveKeepAlive: " + e);
                return false;
            }

            return false;
        }

        // Perform routine PL cleanup
        public static bool performCleanup()
        {
            // Get the current timestamp
            long currentTime = Core.getCurrentTimestamp();
            lock (presences)
            {
                // Store a copy of the presence list to allow safe modifications while enumerating
                List<Presence> safe_presences = new List<Presence>(presences);

                foreach (Presence pr in safe_presences)
                {
                    if(pr.addresses.Count == 0)
                    {
                        presences.Remove(pr);
                        continue;
                    }

                    List<PresenceAddress> safe_addresses = new List<PresenceAddress>(pr.addresses);

                    foreach (PresenceAddress pa in safe_addresses)
                    {
                        // Don't remove self address from presence list
                        /*if(pa == curNodePresenceAddress)
                        {
                            continue;
                        }*/

                        try
                        {
                            // Check if timestamp is older than 300 seconds
                            if((currentTime - pa.lastSeenTime) > 300)
                            {
                                Logging.info(string.Format("Expired lastseen for {0} / {1}", pa.address, pa.device));
                                removeAddressEntry(pr.wallet, pa);
                            }
                            else if ((currentTime - pa.lastSeenTime) < -30) // future time + 30 seconds amortization
                            {
                                Logging.info(string.Format("Expired future lastseen for {0} / {1}", pa.address, pa.device));
                                removeAddressEntry(pr.wallet, pa);
                            }

                        }
                        catch(Exception e)
                        {
                            // Ignore this entry for now
                            Logging.error("Exception occured in PL performCleanup: " + e);
                            continue;
                        }
                    }

                    // Clear the safe list of addresses
                    safe_addresses.Clear();
                }

                // Clear the safe list of presences
                safe_presences.Clear();
            }

            return true;
        }


        // Returns the total number of presences in the current list
        public static long getTotalPresences()
        {
            long total = 0;
            lock (presences)
            {
                total = presences.LongCount();
            }
            return total;
        }

        // Clears all the presences
        public static void clear()
        {
            lock (presences)
            {
                presences.Clear();
            }
        }

        public static long countPresences(char type)
        {
            lock(presenceCount)
            {
                if (presenceCount.ContainsKey(type))
                {
                    return presenceCount[type];
                }
            }
            return 0;
        }

        public static Presence getPresenceByAddress(byte[] address)
        {
            lock(presences)
            {
                return presences.Find(x => x.wallet.SequenceEqual(address));
            }
        }

        public static PresenceOrderedEnumerator getElectedSignerList(byte[] rnd_bytes, int target_count)
        {
            lock (presences)
            {
                int address_len = 36; // This is set to the minimum wallet length
                byte[] selector = PresenceOrderedEnumerator.GenerateSelectorFromRandom(rnd_bytes.Take(address_len).ToArray());
                return new PresenceOrderedEnumerator(presences, address_len, selector, target_count);
            }
        }
    }
}
