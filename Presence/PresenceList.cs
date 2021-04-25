// Copyright (C) 2017-2020 Ixian OU
// This file is part of Ixian Core - www.github.com/ProjectIxian/Ixian-Core
//
// Ixian Core is free software: you can redistribute it and/or modify
// it under the terms of the MIT License as published
// by the Open Source Initiative.
//
// Ixian Core is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// MIT License for more details.

using IXICore.Meta;
using IXICore.Network;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace IXICore
{
    public class PresenceList
    {
        private static List<Presence> presences = new List<Presence> { }; // The presence list

        private static PresenceAddress curNodePresenceAddress = null;
        private static Presence curNodePresence = null;

        // private
        private static Dictionary<char, long> presenceCount = new Dictionary<char, long>();

        private static Thread keepAliveThread;
        private static bool autoKeepalive = false;
        public static ThreadLiveCheck TLC;

        public static bool forceSendKeepAlive = false;


        private static string _myPublicAddress = "";
        private static char _myPresenceType = 'C';

        private static bool running = false;

        // Generate an initial presence list
        public static void init(string initial_ip, int port, char type)
        {
            Logging.info("Generating presence list.");

            _myPublicAddress = string.Format("{0}:{1}", initial_ip, port);
            _myPresenceType = type;

            // Initialize with the default presence state
            curNodePresenceAddress = new PresenceAddress(CoreConfig.device_id, _myPublicAddress, type, CoreConfig.productVersion, 0, null);
            curNodePresence = new Presence(IxianHandler.getWalletStorage().getPrimaryAddress(), IxianHandler.getWalletStorage().getPrimaryPublicKey(), null, curNodePresenceAddress);
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
        public static Presence updateEntry(Presence presence, bool return_presence_only_if_updated = false)
        {
            if(presence == null)
            {
                return null;
            }

            bool updated = false;

            long currentTime = Clock.getNetworkTimestamp();

            lock (presences)
            {
                Presence pr = presences.Find(x => x.wallet.SequenceEqual(presence.wallet));
                if (pr != null)
                {
                    lock (pr)
                    {
                        // Go through all addresses and add any missing ones
                        foreach (PresenceAddress local_addr in presence.addresses)
                        {
                            long lTimestamp = local_addr.lastSeenTime;

                            int expiration_time = CoreConfig.serverPresenceExpiration;

                            if (local_addr.type == 'C')
                            {
                                expiration_time = CoreConfig.clientPresenceExpiration;
                            }

                            // Check for tampering. Includes a +300, -30 second synchronization zone
                            if ((currentTime - lTimestamp) > expiration_time)
                            {
                                Logging.warn(string.Format("[PL] Received expired presence for {0} {1}. Skipping; {2} - {3}", Crypto.hashToString(pr.wallet), local_addr.address, currentTime, lTimestamp));
                                continue;
                            }

                            if ((currentTime - lTimestamp) < -30)
                            {
                                Logging.warn(string.Format("[PL] Potential presence tampering for {0} {1}. Skipping; {2} - {3}", Crypto.hashToString(pr.wallet), local_addr.address, currentTime, lTimestamp));
                                continue;
                            }


                            PresenceAddress addr = pr.addresses.Find(x => x.device.SequenceEqual(local_addr.device));
                            if (addr != null)
                            {
                                if (addr.lastSeenTime < local_addr.lastSeenTime)
                                {
                                    if (local_addr.signature != null)
                                    {
                                        addr.version = local_addr.version;
                                        addr.address = local_addr.address;
                                        addr.lastSeenTime = local_addr.lastSeenTime;
                                        addr.signature = local_addr.signature;
                                        updated = true;
                                    }

                                    if (addr.type == 'M' || addr.type == 'H')
                                    {
                                        PeerStorage.addPeerToPeerList(addr.address, presence.wallet, Clock.getTimestamp(), 0, 0, 0);
                                    }

                                    //Console.WriteLine("[PL] Last time updated for {0}", addr.device);
                                }
                            }
                            else
                            {
                                // Add the address if it's not found
                                //Logging.info("[PL] Adding new address for {0}", presence.wallet);
                                pr.addresses.Add(local_addr);

                                if (local_addr.type == 'M' || local_addr.type == 'H')
                                {
                                    PeerStorage.addPeerToPeerList(local_addr.address, presence.wallet, Clock.getTimestamp(), 0, 0, 0);
                                }

                                lock (presenceCount)
                                {
                                    if (!presenceCount.ContainsKey(local_addr.type))
                                    {
                                        presenceCount.Add(local_addr.type, 0);
                                    }
                                    presenceCount[local_addr.type]++;
                                }

                                updated = true;
                            }
                        }

                        if (!updated && return_presence_only_if_updated)
                        {
                            return null;
                        }
                        else
                        {
                            return pr;
                        }
                    }
                }
                else
                {
                    // Insert a new entry
                    //Console.WriteLine("[PL] Adding new entry for {0}", presence.wallet);

                    foreach (PresenceAddress pa in presence.addresses)
                    {
                        if (pa.type == 'M' || pa.type == 'H')
                        {
                            PeerStorage.addPeerToPeerList(pa.address, presence.wallet, Clock.getTimestamp(), 0, 0, 0);
                        }

                        lock (presenceCount)
                        {
                            if (!presenceCount.ContainsKey(pa.type))
                            {
                                presenceCount.Add(pa.type, 0);
                            }
                            presenceCount[pa.type]++;
                        }

                        updated = true;
                    }

                    if (updated)
                    {
                        presences.Add(presence);
                    }

                    if (!updated && return_presence_only_if_updated)
                    {
                        return null;
                    }else
                    {
                        return presence;
                    }
                }
            }
        }

        public static bool removeAddressEntry(byte[] wallet_address, PresenceAddress address = null)
        {
            lock (presences)
            {
                //Console.WriteLine("[PL] Received removal for {0} : {1}", wallet_address, address.address);
                Presence listEntry = presences.Find(x => x.wallet.SequenceEqual(wallet_address));

                // Check if there is such an entry in the presence list
                if (listEntry != null)
                {
                    lock (listEntry)
                    {
                        List<PresenceAddress> addresses_to_remove = null;

                        if (address != null)
                        {
                            addresses_to_remove = listEntry.addresses.FindAll(x => x == address);
                        }else
                        {
                            addresses_to_remove = new List<PresenceAddress>(listEntry.addresses);
                        }

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
                        if (address != null && address.type == 'R')
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
#if TRACE_MEMSTREAM_SIZES
                        Logging.info(String.Format("PresenceList::getBytes: {0}", m.Length));
#endif
                    }
                    return m.ToArray();
                }
            }
        }

        /*public static bool syncFromBytes(byte[] bytes)
        {
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
        }*/

        // Update a presence from a byte array
        public static Presence updateFromBytes(byte[] bytes)
        {
            Presence presence = new Presence(bytes);

            if(presence.verify())
            {
                return updateEntry(presence, true);
            }


            return null;
        }

        public static void startKeepAlive()
        {
            if (running)
            {
                return;
            }

            running = true;


            TLC = new ThreadLiveCheck();
            // Start the keepalive thread
            autoKeepalive = true;
            keepAliveThread = new Thread(keepAlive);
            keepAliveThread.Name = "Presence_List_Keep_Alive_Thread";
            keepAliveThread.Start();
        }

        public static void stopKeepAlive()
        {
            if (!running)
            {
                return;
            }

            running = false;

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
            forceSendKeepAlive = true;
            while (autoKeepalive)
            {
                TLC.Report();

                int keepalive_interval = CoreConfig.serverKeepAliveInterval;

                if (curNodePresenceAddress.type == 'C')
                {
                    keepalive_interval = CoreConfig.clientKeepAliveInterval;
                }

                // Wait x seconds before rechecking
                for (int i = 0; i < keepalive_interval; i++)
                {
                    if (autoKeepalive == false)
                    {
                        return;
                    }
                    if (IxianHandler.publicIP == "")
                    {
                        // do not send KA
                        i = 0;
                    }
                    else
                    {
                        if (forceSendKeepAlive)
                        {
                            Thread.Sleep(1000);
                            forceSendKeepAlive = false;
                            break;
                        }
                    }
                    // Sleep for one second
                    Thread.Sleep(1000);
                }

                if (curNodePresenceAddress.type == 'W')
                {
                    continue; // no need to send PL for worker nodes
                }

                try
                {
                    KeepAlive ka = new KeepAlive() { 
                        deviceId = CoreConfig.device_id,
                        hostName = curNodePresenceAddress.address,
                        nodeType = curNodePresenceAddress.type,
                        timestamp = Clock.getNetworkTimestamp(),
                        walletAddress = IxianHandler.getWalletStorage().getPrimaryAddress()
                    };
                    ka.sign(IxianHandler.getWalletStorage().getPrimaryPrivateKey());

                    curNodePresenceAddress.lastSeenTime = ka.timestamp;
                    curNodePresenceAddress.signature = ka.signature;

                    byte[] ka_bytes = ka.getBytes();

                    byte[] address = null;
                    long last_seen = 0;
                    byte[] device_id = null;

                    // Update self presence
                    receiveKeepAlive(ka_bytes, out address, out last_seen, out device_id, null);

                    // Send this keepalive to all connected non-clients
                    CoreProtocolMessage.broadcastProtocolMessage(new char[] { 'M', 'H', 'W' }, ProtocolMessageCode.keepAlivePresence, ka_bytes, address);

                    // Send this keepalive message to all connected clients
                    CoreProtocolMessage.broadcastEventDataMessage(NetworkEvents.Type.keepAlive, address, ProtocolMessageCode.keepAlivePresence, ka_bytes, address);
                }
                catch (Exception e)
                {
                    Logging.error("Exception occured while generating keepalive: " + e);
                }
            }
        }

        // Called when receiving a keepalive network message. The PresenceList will update the appropriate entry based on the timestamp.
        // Returns TRUE if it updated an entry in the PL
        // Sets the out address parameter to be the KA wallet's address or null if an error occured
        public static bool receiveKeepAlive(byte[] bytes, out byte[] address, out long last_seen, out byte[] device_id, RemoteEndpoint endpoint)
        {
            address = null;
            last_seen = 0;
            device_id = null;

            // Get the current timestamp
            long currentTime = Clock.getNetworkTimestamp();

            try
            {
                KeepAlive ka = new KeepAlive(bytes);
                byte[] wallet = ka.walletAddress;

                if (ka.nodeType == 'C' || ka.nodeType == 'R')
                {
                    // all good, continue
                }
                else if (ka.nodeType == 'M' || ka.nodeType == 'H')
                {
                    if (ka.version == 1)
                    {
                        if (myPresenceType == 'M' || myPresenceType == 'H')
                        {
                            // check balance
                            if (IxianHandler.getWalletBalance(ka.walletAddress) < ConsensusConfig.minimumMasterNodeFunds)
                            {
                                return false;
                            }
                        }
                    }
                }
                else
                {
                    // reject everything else
                    return false;
                }

                lock (presences)
                {
                    Presence listEntry = presences.Find(x => x.wallet.SequenceEqual(wallet));
                    if (listEntry == null && wallet.SequenceEqual(IxianHandler.getWalletStorage().getPrimaryAddress()))
                    {
                        Logging.warn("My entry was removed from local PL, readding.");
                        curNodePresence.addresses.Clear();
                        curNodePresence.addresses.Add(curNodePresenceAddress);
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
                                writer.WriteIxiVarInt(wallet.Length);
                                writer.Write(wallet);

                                if (endpoint != null && endpoint.isConnected())
                                {
                                    endpoint.sendData(ProtocolMessageCode.getPresence2, mw.ToArray(), wallet);
                                }
                                else
                                {
                                    CoreProtocolMessage.broadcastProtocolMessageToSingleRandomNode(new char[] { 'M', 'R', 'H' }, ProtocolMessageCode.getPresence2, mw.ToArray(), 0, null);
                                }
                            }
                        }
                        return false;
                    }


                    if(!ka.verifySignature(listEntry.pubkey))
                    {
                        return false;
                    }

                    PresenceAddress pa = listEntry.addresses.Find(x => x.address == ka.hostName && x.device.SequenceEqual(ka.deviceId));

                    if(pa != null)
                    {
                        // Check the node type
                        if (pa.lastSeenTime != ka.timestamp)
                        {
                            // Check for outdated timestamp
                            if (ka.timestamp < pa.lastSeenTime)
                            {
                                // We already have a newer timestamp for this entry
                                return false;
                            }

                            int expiration_time = CoreConfig.serverPresenceExpiration;

                            if (pa.type == 'C')
                            {
                                expiration_time = CoreConfig.clientPresenceExpiration;
                            }

                            // Check for tampering. Includes a +300, -30 second synchronization zone
                            if ((currentTime - ka.timestamp) > expiration_time)
                            {
                                Logging.warn(string.Format("[PL] Received expired KEEPALIVE for {0} {1}. Timestamp {2}", Base58Check.Base58CheckEncoding.EncodePlain(listEntry.wallet), pa.address, ka.timestamp));
                                return false;
                            }

                            if ((currentTime - ka.timestamp) < -30)
                            {
                                Logging.warn(string.Format("[PL] Potential KEEPALIVE tampering for {0} {1}. Timestamp {2}", Base58Check.Base58CheckEncoding.EncodePlain(listEntry.wallet), pa.address, ka.timestamp));
                                return false;
                            }

                            // Update the timestamp
                            pa.lastSeenTime = ka.timestamp;
                            pa.signature = ka.signature;
                            pa.version = ka.version;
                            if (pa.type != ka.nodeType)
                            {
                                lock (presenceCount)
                                {
                                    presenceCount[pa.type]--;
                                    if (!presenceCount.ContainsKey(ka.nodeType))
                                    {
                                        presenceCount.Add(ka.nodeType, 0);
                                    }
                                    presenceCount[ka.nodeType]++;
                                }
                            }
                            pa.type = ka.nodeType;
                            //Console.WriteLine("[PL] LASTSEEN for {0} - {1} set to {2}", hostname, deviceid, pa.lastSeenTime);
                            return true;
                        }
                    }
                    else
                    {
                        if (wallet.SequenceEqual(IxianHandler.getWalletStorage().getPrimaryAddress()))
                        {
                            curNodePresence.addresses.Clear();
                            curNodePresence.addresses.Add(curNodePresenceAddress);
                            updateEntry(curNodePresence);
                            return true;
                        }
                        else
                        {
                            using (MemoryStream mw = new MemoryStream())
                            {
                                using (BinaryWriter writer = new BinaryWriter(mw))
                                {
                                    writer.WriteIxiVarInt(wallet.Length);
                                    writer.Write(wallet);

                                    if (endpoint != null && endpoint.isConnected())
                                    {
                                        endpoint.sendData(ProtocolMessageCode.getPresence2, mw.ToArray(), wallet);
                                    }else
                                    { 
                                        CoreProtocolMessage.broadcastProtocolMessageToSingleRandomNode(new char[] { 'M', 'R', 'H'}, ProtocolMessageCode.getPresence2, mw.ToArray(), 0, null);
                                    }
                                }
                            }
                            return false;
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
            long currentTime = Clock.getNetworkTimestamp();
            lock (presences)
            {
                // Store a copy of the presence list to allow safe modifications while enumerating
                List<Presence> safe_presences = new List<Presence>(presences);

                foreach (Presence pr in safe_presences)
                {
                    lock (pr)
                    {
                        if (pr.addresses.Count == 0)
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
                                int expiration_time = CoreConfig.serverPresenceExpiration;

                                if (pa.type == 'C')
                                {
                                    expiration_time = CoreConfig.clientPresenceExpiration;
                                }

                                // Check if timestamp is older than 300 seconds
                                if ((currentTime - pa.lastSeenTime) > expiration_time)
                                {
                                    Logging.info(string.Format("Expired lastseen for {0} / {1}", pa.address, Crypto.hashToString(pa.device)));
                                    removeAddressEntry(pr.wallet, pa);
                                }
                                else if ((currentTime - pa.lastSeenTime) < -30) // future time + 30 seconds amortization
                                {
                                    Logging.info(string.Format("Expired future lastseen for {0} / {1}", pa.address, Crypto.hashToString(pa.device)));
                                    removeAddressEntry(pr.wallet, pa);
                                }
                            }
                            catch (Exception e)
                            {
                                // Ignore this entry for now
                                Logging.error("Exception occured in PL performCleanup: " + e);
                                continue;
                            }
                        }

                        // Clear the safe list of addresses
                        safe_addresses.Clear();
                    }
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
                presenceCount = new Dictionary<char, long>();
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

        public static Presence getPresenceByAddress(byte[] address_or_pubkey)
        {
            if (address_or_pubkey == null)
                return null;

            try
            {
                byte[] address = (new Address(address_or_pubkey)).address;

                lock (presences)
                {
                    return presences.Find(x => x.wallet.SequenceEqual(address));
                }
            }
            catch(Exception e)
            {
                Logging.error("Exception occured in getPresenceByAddress: {0}", e);
                return null;
            }
        }

        public static Presence getPresenceByDeviceId(byte[] device_id)
        {
            if(device_id == null)
            {
                throw new Exception("Device id is null while getting presences by device id");
            }

            lock (presences)
            {
                return presences.Find(x => x.addresses.Find(y => y.device.SequenceEqual(device_id)) != null);
            }
        }

        public static List<Presence> getPresencesByType(char type)
        {
            lock (presences)
            {
                return presences.FindAll(x => x.addresses.Find(y => y.type == type) != null);
            }
        }

        // for debugging purposes only, do not use!
        public static List<Presence> getPresences()
        {
            return presences;
        }

        public static PresenceOrderedEnumerator getElectedSignerList(byte[] rnd_bytes, int target_count)
        {
            lock (presences)
            {
                int address_len = 36; // This is set to the minimum wallet length
                byte[] selector = PresenceOrderedEnumerator.GenerateSelectorFromRandom(rnd_bytes.Take(address_len).ToArray());
                var sorted_presences = presences.FindAll(x => x.addresses.Find(y => y.type == 'M' || y.type == 'H') != null).OrderBy(x => x.wallet, new ByteArrayComparer());
                return new PresenceOrderedEnumerator(sorted_presences, address_len, selector, target_count);
            }
        }

        public static string myPublicAddress
        {
            get { return _myPublicAddress; }
            set
            {
                _myPublicAddress = value;
                if (curNodePresenceAddress != null)
                {
                    curNodePresenceAddress.address = value;
                }
            }
        }

        public static char myPresenceType
        {
            get { return _myPresenceType; }
            set
            {
                _myPresenceType = value;
                if (curNodePresenceAddress != null)
                {
                    curNodePresenceAddress.type = value;
                }
            }
        }
    }
}
