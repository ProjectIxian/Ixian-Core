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


        // Generate an initial presence list
        public static void generatePresenceList(string initial_ip)
        {
            Logging.info("Generating presence list.");
            // Initialize with the default presence state
            PresenceAddress this_address = new PresenceAddress(Config.device_id, string.Format("{0}:{1}", initial_ip, Config.serverPort), 'M');
            Presence this_node = new Presence(Node.walletStorage.address, Node.walletStorage.encPublicKey, Node.walletStorage.publicKey, this_address);
            updateEntry(this_node);

        }

        // Prototype specific function, used to retrieve the first valid master node address from the presence list
        public static string getFirstMasterNodeAddress()
        {
            foreach (Presence pr in presences)
            {
                foreach (PresenceAddress addr in pr.addresses)
                {
                    if (addr.type == 'M')
                    {
                        return addr.address;
                    }
                }
            }
            return "none";
        }

        // Update a presence entry. If the wallet address is not found, it creates a new entry in the Presence List.
        // If the wallet address is found in the presence list, it adds any new addresses from the specified presence.
        public static Presence updateEntry(Presence presence, Socket skipSocket = null)
        {
            bool entryUpdated = false;
            lock(presences)
            {
                foreach(Presence pr in presences)
                {
                    // Check if the wallet address is already in the presence list
                    if(pr.wallet.Equals(presence.wallet, StringComparison.Ordinal))
                    {
                        //pr.addresses.First().lastSeenTime = Clock.getTimestamp(DateTime.Now);
                        entryUpdated = true;


                        // Go through all addresses and add any missing ones
                        foreach (PresenceAddress local_addr in presence.addresses)
                        {
                            bool addressfound = false;

                            foreach (PresenceAddress addr in pr.addresses)
                            {
                                if (local_addr.device.Equals(addr.device, StringComparison.Ordinal))
                                {
                                    addressfound = true;
                                    return pr;
                                }
                            }

                            // Add the address if it's not found
                            if (addressfound == false)
                            {
                                pr.addresses.Add(local_addr);
                            }

                        }
                        Console.WriteLine("[PL] Updating presence for {0}", presence.wallet);

                        ProtocolMessage.broadcastProtocolMessage(ProtocolMessageCode.updatePresence, pr.getBytes(), skipSocket);

                        // Return the stored presence list entity
                        return pr;
                    }
                }

                // No entry found to update
                if(entryUpdated == false)
                {
                    // Insert a new entry
                    presences.Add(presence);
                    Console.WriteLine("[PL] Adding new entry for {0}", presence.wallet);

                    ProtocolMessage.broadcastProtocolMessage(ProtocolMessageCode.updatePresence, presence.getBytes(), skipSocket);
                    return presence;
                }
            }

            return null;
        }

        // Removes an entry from the presence list.
        public static bool removeEntry(Presence presence)
        {
            lock (presences)
            {
                Presence listEntry = null;
                foreach (Presence pr in presences)
                {
                    // Check if the wallet address is already in the presence list
                    if (pr.wallet.Equals(presence.wallet, StringComparison.Ordinal))
                    {
                        listEntry = pr;
                        break;
                    }
                }

                if(listEntry != null)
                {
                    ProtocolMessage.broadcastProtocolMessage(ProtocolMessageCode.removePresence, listEntry.getBytes());
                    presences.Remove(listEntry);
                    return true;                  
                }

            }

            return false;
        }

        public static bool removeAddressEntry(string wallet_address, PresenceAddress address, Socket skipSocket = null)
        {
            lock (presences)
            {
                Console.WriteLine("[PL] Received removal for {0} : {1}", wallet_address, address.address);
                Presence listEntry = null;
                foreach (Presence pr in presences)
                {
                    // Check if the wallet address is already in the presence list
                    if (pr.wallet.Equals(wallet_address, StringComparison.Ordinal))
                    {
                        listEntry = pr;
                        break;
                    }
                }

                // Check if there is such an entry in the presence list
                if (listEntry != null)
                {
                    listEntry.addresses.Remove(address);

                    int address_count = listEntry.addresses.Count;
                    Console.WriteLine("[PL] --->> Addresses: {0}", address_count);

                    if (address_count == 0)
                    {
                        // This means we'll have to remove the entry from the presence list
                        Console.WriteLine("[PL] REMOVING ENTRY FROM LIST {0}", listEntry.wallet);

                        // Broadcast the message first
                        // DEPRECATED in favor of KEEPALIVE
                       // ProtocolMessage.broadcastProtocolMessage(ProtocolMessageCode.removePresence, listEntry.getBytes(), skipSocket);

                        // Remove it from the list
                        presences.Remove(listEntry);
                    }
                    else
                    {
                        // This means we'll have to update the entry in the presence list
                        // DEPRECATED in favor of KEEPALIVE
                        //ProtocolMessage.broadcastProtocolMessage(ProtocolMessageCode.updatePresence, listEntry.getBytes(), skipSocket);
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
                                if (pa.address.Equals(relay_address, StringComparison.Ordinal))
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
            double currentTime = Convert.ToDouble(Clock.getTimestamp(DateTime.Now));

            try
            {
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {

                        string wallet = reader.ReadString();
                        string deviceid = reader.ReadString();
                        string hostname = reader.ReadString();
                        string timestamp = reader.ReadString();
                        string signature = reader.ReadString();
                        //Console.WriteLine("[PL] KEEPALIVE request from {0}", hostname);

                        lock (presences)
                        {
                            Presence listEntry = null;
                            foreach (Presence pr in presences)
                            {
                                // Check if the wallet address is already in the presence list
                                if (pr.wallet.Equals(wallet, StringComparison.Ordinal))
                                {
                                    listEntry = pr;
                                    break;
                                }
                            }
                            // Check if no such wallet found in presence list
                            if(listEntry == null)
                            {
                                return false;
                            }

                            // Go through every presence address for this entry
                            foreach (PresenceAddress pa in listEntry.addresses)
                            {
                                if (pa.device.Equals(deviceid, StringComparison.Ordinal))
                                {
                                    // Check the node type
                                    if(pa.lastSeenTime.Equals(timestamp, StringComparison.Ordinal) == false)
                                    {
                                        double d_timestamp = Convert.ToDouble(timestamp);

                                        // Check for tampering. Includes a 100 second synchronization zone
                                        if (currentTime + 100 < d_timestamp)
                                        {
                                            Logging.warn(string.Format("[PL] Potential KEEPALIVE tampering for {0} {1}. Timestamp {2}", listEntry.wallet, pa.address, timestamp));
                                            return false;
                                        }

                                        // Check for outdated timestamp
                                        double d_oldLastSeen = Convert.ToDouble(pa.lastSeenTime);
                                        if (d_timestamp < d_oldLastSeen)
                                        {
                                            // We already have a newer timestamp for this entry
                                            return false;
                                        }

                                        // Finally, check the signature
                                        // Verify the signature
                                        // Disabled for dev purposes
                                        if(CryptoManager.lib.verifySignature(timestamp, listEntry.metadata, signature) == false)
                                        {
                                            Logging.warn(string.Format("[PL] KEEPALIVE tampering for {0} {1}", listEntry.wallet, pa.address));
                                            return false;
                                        }

                                        // Update the timestamp
                                        pa.lastSeenTime = timestamp;

                                        // Console.WriteLine("[PL] LASTSEEN for {0} set to {1}", hostname, pa.lastSeenTime);
                                        return true;
                                    }
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
            double currentTime = Convert.ToDouble(Clock.getTimestamp(DateTime.Now));
            lock (presences)
            {
                // Store a copy of the presence list to allow safe modifications while enumerating
                List<Presence> safe_presences = new List<Presence>(presences);

                foreach (Presence pr in safe_presences)
                {
                    List<PresenceAddress> safe_addresses = new List<PresenceAddress>(pr.addresses);

                    foreach (PresenceAddress pa in safe_addresses)
                    {
                        // Skip self device from cleanup and apply current timestamp
                        if (pa.device.Equals(Config.device_id, StringComparison.Ordinal))
                        {
                            // Update the timestamp
                            pa.lastSeenTime = Clock.getTimestamp(DateTime.Now);
                            continue;
                        }


                        try
                        {
                            double paTime = Convert.ToDouble(pa.lastSeenTime);
                            // Check if timestamp is older than 300 seconds
                            if(currentTime - paTime > 300)
                            {
                                Console.WriteLine("[PL] Expired lastseen for {0} / {1}", pa.address, pa.device);

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
