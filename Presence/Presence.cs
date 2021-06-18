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
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.IO;

namespace IXICore
{
    // The actual presence object, which can contain multiple PresenceAddress objects
    public class Presence
    {
        public int version = 0;
        public byte[] wallet;
        public byte[] pubkey;
        public byte[] metadata; 
        public List<PresenceAddress> addresses;
        public SignerPowSolution powSolution;

        public Presence()
        {
            wallet = null;
            pubkey = null;
            metadata = null;
            addresses = new List<PresenceAddress> { };
        }

        public Presence(byte[] wallet_address, byte[] node_pubkey, byte[] node_meta, PresenceAddress node_address)
        {
            wallet = wallet_address;
            pubkey = node_pubkey;
            metadata = node_meta;
            addresses = new List<PresenceAddress> { };
            addresses.Add(node_address);
        }

        public Presence(byte[] bytes)
        {
            try
            {
                if (bytes.Length > 102400)
                {
                    throw new Exception("Presence size is bigger than 100kB.");
                }

                // Prepare addresses
                addresses = new List<PresenceAddress> { };

                wallet = null;
                pubkey = null;
                metadata = null;


                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        if(bytes[0] == 0)
                        {
                            // TODO remove this section after upgrade to Presence v1
                            version = reader.ReadInt32();

                            int walletLen = reader.ReadInt32();
                            if (walletLen > 0)
                            {
                                wallet = reader.ReadBytes(walletLen);
                            }
                            int pubkeyLen = reader.ReadInt32();
                            if (pubkeyLen > 0)
                            {
                                pubkey = reader.ReadBytes(pubkeyLen);
                            }
                            int mdLen = reader.ReadInt32();
                            if (mdLen > 0)
                            {
                                metadata = reader.ReadBytes(mdLen);
                            }


                            // Read number of addresses
                            UInt16 number_of_addresses = reader.ReadUInt16();

                            // Read addresses
                            for (UInt16 i = 0; i < number_of_addresses; i++)
                            {
                                int byte_count = reader.ReadInt32();
                                if (byte_count > 0)
                                {
                                    byte[] address_bytes = reader.ReadBytes(byte_count);

                                    addresses.Add(new PresenceAddress(address_bytes));
                                }
                            }
                        }else
                        {
                            version = (int)reader.ReadIxiVarInt();

                            int walletLen = (int)reader.ReadIxiVarUInt();
                            if (walletLen > 0)
                            {
                                wallet = reader.ReadBytes(walletLen);
                            }
                            int pubkeyLen = (int)reader.ReadIxiVarUInt();
                            if (pubkeyLen > 0)
                            {
                                pubkey = reader.ReadBytes(pubkeyLen);
                            }
                            int mdLen = (int)reader.ReadIxiVarUInt();
                            if (mdLen > 0)
                            {
                                metadata = reader.ReadBytes(mdLen);
                            }


                            // Read number of addresses
                            int number_of_addresses = (int)reader.ReadIxiVarUInt();

                            // Read addresses
                            for (int i = 0; i < number_of_addresses; i++)
                            {
                                int byte_count = (int)reader.ReadIxiVarUInt();
                                if (byte_count > 0)
                                {
                                    byte[] address_bytes = reader.ReadBytes(byte_count);

                                    addresses.Add(new PresenceAddress(address_bytes));
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Logging.error("Exception occured while trying to construct Presence from bytes: " + e);
                throw;
            }
        }

        public byte[] getBytes(ushort from_index = 0, ushort count = 0)
        {
            using (MemoryStream m = new MemoryStream(1280))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    if(version == 0)
                    {
                        // TODO remove this section after upgrade to Presence v1
                        writer.Write(version);

                        if (wallet != null)
                        {
                            writer.Write(wallet.Length);
                            writer.Write(wallet);
                        }
                        else
                        {
                            writer.Write(0);
                        }

                        if (pubkey != null)
                        {
                            writer.Write(pubkey.Length);
                            writer.Write(pubkey);
                        }
                        else
                        {
                            writer.Write(0);
                        }

                        if (metadata != null)
                        {
                            writer.Write(metadata.Length);
                            writer.Write(metadata);
                        }
                        else
                        {
                            writer.Write(0);
                        }

                        // Write the number of ips
                        UInt16 number_of_addresses = (ushort)((UInt16)addresses.Count - from_index);

                        if (count > 0 && number_of_addresses > count)
                        {
                            number_of_addresses = count;
                        }

                        writer.Write(number_of_addresses);

                        // Write all ips
                        for (UInt16 i = from_index; i < number_of_addresses; i++)
                        {
                            if (addresses[i] == null)
                            {
                                writer.Write(0);
                                continue;
                            }
                            byte[] address_data = addresses[i].getBytes();
                            if (address_data != null)
                            {
                                writer.Write(address_data.Length);
                                writer.Write(address_data);
                            }
                            else
                            {
                                writer.Write(0);
                            }
                        }
                    }else
                    {
                        writer.WriteIxiVarInt(version);

                        if (wallet != null)
                        {
                            writer.WriteIxiVarInt(wallet.Length);
                            writer.Write(wallet);
                        }
                        else
                        {
                            writer.WriteIxiVarInt(0);
                        }

                        if (pubkey != null)
                        {
                            writer.WriteIxiVarInt(pubkey.Length);
                            writer.Write(pubkey);
                        }
                        else
                        {
                            writer.WriteIxiVarInt(0);
                        }

                        if (metadata != null)
                        {
                            writer.WriteIxiVarInt(metadata.Length);
                            writer.Write(metadata);
                        }
                        else
                        {
                            writer.WriteIxiVarInt(0);
                        }

                        // Write the number of ips
                        int number_of_addresses = addresses.Count - from_index;

                        if (count > 0 && number_of_addresses > count)
                        {
                            number_of_addresses = count;
                        }

                        writer.WriteIxiVarInt(number_of_addresses);

                        // Write all ips
                        for (int i = from_index; i < number_of_addresses; i++)
                        {
                            if (addresses[i] == null)
                            {
                                writer.WriteIxiVarInt(0);
                                continue;
                            }
                            byte[] address_data = addresses[i].getBytes();
                            if (address_data != null)
                            {
                                writer.WriteIxiVarInt(address_data.Length);
                                writer.Write(address_data);
                            }
                            else
                            {
                                writer.WriteIxiVarInt(0);
                            }
                        }
                    }

#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("Presence::getBytes: {0}", m.Length));
#endif
                }
                return m.ToArray();
            }
        }

        public byte[][] getByteChunks()
        {
            ushort chunk_count = (ushort)Math.Ceiling((decimal)addresses.Count / 10);
            byte[][] presence_chunks = new byte[chunk_count][];
            for(ushort i = 0; i < chunk_count; i++)
            {
                presence_chunks[i] = getBytes((ushort)(i * 10), 10);
            }
            return presence_chunks;
        }

        public bool verify()
        {
            if (wallet.Length > 128 && wallet.Length < 4)
            {
                return false;
            }

            if (pubkey == null || pubkey.Length < 32 || pubkey.Length > 2500)
            {
                return false;
            }

            List<PresenceAddress> valid_addresses = new List<PresenceAddress>();

            long currentTime = Clock.getNetworkTimestamp();

            foreach (var entry in addresses)
            {
                if (entry.device.Length > 64)
                {
                    continue;
                }

                if (entry.nodeVersion.Length > 64)
                {
                    continue;
                }

                if (entry.address.Length > 24 && entry.address.Length < 9)
                {
                    continue;
                }

                long lTimestamp = entry.lastSeenTime;

                int expiration_time = CoreConfig.serverPresenceExpiration;

                if (entry.type == 'C')
                {
                    expiration_time = CoreConfig.clientPresenceExpiration;
                }

                // Check for tampering. Includes a +300, -30 second synchronization zone
                if ((currentTime - lTimestamp) > expiration_time)
                {
                    Logging.warn(string.Format("[PL] Received expired presence for {0} {1}. Skipping; {2} - {3}", Crypto.hashToString(wallet), entry.address, currentTime, lTimestamp));
                    continue;
                }

                if ((currentTime - lTimestamp) < -30)
                {
                    Logging.warn(string.Format("[PL] Potential presence tampering for {0} {1}. Skipping; {2} - {3}", Crypto.hashToString(wallet), entry.address, currentTime, lTimestamp));
                    continue;
                }

                if (!entry.verifySignature(wallet, pubkey))
                {
                    Logging.warn("Invalid presence address received in verifyPresence, signature verification failed for {0}.", Base58Check.Base58CheckEncoding.EncodePlain(wallet));
                    continue;
                }

                if(version == 1 && (entry.type == 'M' || entry.type == 'H'))
                {
                    if(powSolution == null)
                    {
                        Logging.warn("Invalid or empty pow solution received in verifyPresence, verification failed for {0}.", Base58Check.Base58CheckEncoding.EncodePlain(wallet));
                        continue;
                    }else if(PresenceList.myPresenceType == 'M' || PresenceList.myPresenceType == 'H' || PresenceList.myPresenceType == 'W')
                    {
                        if(IxianHandler.getLastBlockHeight() - powSolution.blockNum > ConsensusConfig.plPowBlocksValidity)
                        {
                            Logging.warn("Expired pow solution received in verifyPresence, verification failed for {0}.", Base58Check.Base58CheckEncoding.EncodePlain(wallet));
                            powSolution = null;
                            continue;
                        }
                        Block plPowBlock = IxianHandler.getBlock(powSolution.blockNum);
                        if (plPowBlock == null)
                        {
                            Logging.warn("No block for PL pow solution found in verifyPresence, verification failed for {0}.", Base58Check.Base58CheckEncoding.EncodePlain(wallet));
                            powSolution = null;
                            continue;
                        }

                        byte[] blockHash = plPowBlock.blockChecksum;
                        ulong difficulty = plPowBlock.signerDifficulty;
                        if(!powSolution.verifySignature(pubkey))
                        {
                            Logging.warn("Invalid pow solution received in verifyPresence, verification failed for {0}.", Base58Check.Base58CheckEncoding.EncodePlain(wallet));
                            powSolution = null;
                            continue;
                        }
                        if (!SignerPowSolution.verifyNonce(powSolution.solution, blockHash, wallet, difficulty))
                        {
                            Logging.warn("Invalid or empty pow solution received in verifyPresence, verification failed for {0}.", Base58Check.Base58CheckEncoding.EncodePlain(wallet));
                            powSolution = null;
                            continue;
                        }
                    }
                }

                valid_addresses.Add(entry);
            }

            if (valid_addresses.Count > 0)
            {
                addresses = valid_addresses;
                return true;
            }

            return false;
        }
    }
}
