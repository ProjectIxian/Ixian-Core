using DLT.Meta;
using DLT.Network;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace DLT
{
    class PresenceList
    {
        public static List<Presence> presences = new List<Presence> { }; // The presence list

        public static PresenceAddress curNodePresenceAddress = null;
        public static Presence curNodePresence = null;

        // Generate an initial presence list
        public static void generatePresenceList(string initial_ip)
        {
            Logging.info("Generating presence list.");
            // Initialize with the default presence state
            curNodePresenceAddress = new PresenceAddress(Config.device_id, string.Format("{0}:{1}", initial_ip, Config.serverPort), 'M', Config.version, 0, null);
            curNodePresence = new Presence(Node.walletStorage.address, Node.walletStorage.publicKey, null, curNodePresenceAddress);
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

        // Update a presence entry. If the wallet address is not found, it creates a new entry in the Presence List.
        // If the wallet address is found in the presence list, it adds any new addresses from the specified presence.
        public static Presence updateEntry(Presence presence, RemoteEndpoint skipEndpoint = null)
        {
            //Console.WriteLine("[PL] Received update entry for: {0}", presence.wallet);

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
                        long currentTime = Node.getCurrentTimestamp();
                        long lTimestamp = local_addr.lastSeenTime;
                        // Check for tampering. Includes a 200 second synchronization zone
                        if ((currentTime - lTimestamp) > 100 || (currentTime - lTimestamp) < -100)
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
                            //Console.WriteLine("[PL] Adding new address for {0}", presence.wallet);
                            pr.addresses.Add(local_addr);
                            entryUpdated = true;
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
                    
                    listEntry.addresses.RemoveAll(x => x.address == address.address);

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

        // Update a presence from a byte array
        public static bool updateFromBytes(byte[] bytes)
        {
            Presence presence = new Presence(bytes);

            if(presence.wallet.Length > 0)
            {
                updateEntry(presence);
                return true;
            }

            return false;
        }

        // Called when receiving a keepalive network message. The PresenceList will update the appropriate entry based on the timestamp.
        // Returns TRUE if it updated an entry in the PL
        public static bool receiveKeepAlive(byte[] bytes)
        {
            // Get the current timestamp
            long currentTime = Node.getCurrentTimestamp();

            try
            {
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        int keepAliveVersion = reader.ReadInt32();
                        int walletLen = reader.ReadInt32();
                        byte[] wallet = reader.ReadBytes(walletLen);
                        string deviceid = reader.ReadString();
                        long timestamp = reader.ReadInt64();
                        string hostname = reader.ReadString();
                        int sigLen = reader.ReadInt32();
                        byte[] signature = reader.ReadBytes(sigLen);
                        //Logging.info(String.Format("[PL] KEEPALIVE request from {0}", hostname));

                        lock (presences)
                        {
                            Presence listEntry = presences.Find(x => x.wallet.SequenceEqual(wallet));
                            if (listEntry == null && wallet.SequenceEqual(Node.walletStorage.address))
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

                                        ProtocolMessage.broadcastProtocolMessage(ProtocolMessageCode.getPresence, mw.ToArray());
                                    }
                                }
                                return false;
                            }

                            // Verify the signature
                            if (CryptoManager.lib.verifySignature(Encoding.UTF8.GetBytes(Config.ixianChecksumLockString + "-" + deviceid + "-" + timestamp + "-" + hostname), listEntry.pubkey, signature) == false)
                            {
                                Logging.warn(string.Format("[PL] KEEPALIVE tampering for {0} {1}, incorrect Sig.", Base58Check.Base58CheckEncoding.EncodePlain(listEntry.wallet), hostname));
                                return false;
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

                                    // Check for tampering. Includes a 100 second synchronization zone
                                    if ((currentTime - timestamp) > 100)
                                    {
                                        Logging.warn(string.Format("[PL] Potential KEEPALIVE tampering for {0} {1}. Timestamp {2}", Base58Check.Base58CheckEncoding.EncodePlain(listEntry.wallet), pa.address, timestamp));
                                        return false;
                                    }

                                    // Update the timestamp
                                    pa.lastSeenTime = timestamp;
                                    pa.signature = signature;

                                    if (pa.type == 'M')
                                    {
                                        PeerStorage.addPeerToPeerList(hostname, wallet);
                                    }

                                    //Console.WriteLine("[PL] LASTSEEN for {0} - {1} set to {2}", hostname, deviceid, pa.lastSeenTime);
                                    return true;
                                }
                            }
                            else
                            {
                                if (wallet.SequenceEqual(Node.walletStorage.address))
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

                                            ProtocolMessage.broadcastProtocolMessage(ProtocolMessageCode.getPresence, mw.ToArray());
                                        }
                                    }
                                    return false;
                                }
                            }
                        }
                    }
                }
            }
            catch(Exception)
            {
                return false;
            }

            return false;
        }

        // Perform routine PL cleanup
        public static bool performCleanup()
        {
            // Get the current timestamp
            long currentTime = Node.getCurrentTimestamp();
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
                            }else if ((currentTime - pa.lastSeenTime) < -20) // future time + 20 seconds amortization?
                            {
                                Logging.info(string.Format("Expired future lastseen for {0} / {1}", pa.address, pa.device));
                                removeAddressEntry(pr.wallet, pa);
                            }

                        }
                        catch(Exception)
                        {
                            // Ignore this entry for now
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


    }
}
