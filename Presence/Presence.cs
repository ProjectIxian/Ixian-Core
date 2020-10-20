using IXICore.Meta;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace IXICore
{
    // TODO TODO TODO add sigs to PresenceAddress; when syncing with other nodes,
    // we can't rely on them sending the correct data, we have to verify with the originators sigs otherwise the entry is invalid
    // An object class that describes how to contact the specific node/client
    public class PresenceAddress
    {
        public int version = 1;
        public byte[] device; // Device id
        public string address; // IP and port
        public char type;   // M for MasterNode, R for RelayNode, D for Direct ip client, C for normal client
        public string nodeVersion; // Version
        public long lastSeenTime;
        public byte[] signature;

        public PresenceAddress(byte[] node_device, string node_address, char node_type, string node_version, long node_lastSeenTime, byte[] node_signature)
        {
            device = node_device;
            address = node_address;
            type = node_type;
            nodeVersion = node_version;
            lastSeenTime = node_lastSeenTime;
            signature = node_signature;
        }

        public PresenceAddress(byte[] bytes)
        {
            try
            {
                if (bytes.Length > 1024)
                {
                    throw new Exception("PresenceAddress size is bigger than 1kB.");
                }
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        if(bytes[0] == 1)
                        {
                            version = reader.ReadInt32();
                        }else
                        {
                            version = (int)reader.ReadIxiVarInt();
                        }
                        if(version == 1)
                        {
                            // TODO remove this after upgrade
                            device = System.Guid.Parse(reader.ReadString()).ToByteArray();
                            address = reader.ReadString();
                            type = reader.ReadChar();
                            nodeVersion = reader.ReadString();
                            lastSeenTime = reader.ReadInt64();
                            int sigLen = reader.ReadInt32();
                            if (sigLen > 0)
                            {
                                signature = reader.ReadBytes(sigLen);
                            }
                        }
                        else
                        {
                            int device_len = (int)reader.ReadIxiVarUInt();
                            device = reader.ReadBytes(device_len);
                            address = reader.ReadString();
                            type = reader.ReadChar();
                            nodeVersion = reader.ReadString();
                            lastSeenTime = reader.ReadIxiVarInt();
                            int sigLen = (int)reader.ReadIxiVarUInt();
                            if (sigLen > 0)
                            {
                                signature = reader.ReadBytes(sigLen);
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Logging.error("Exception occured while trying to construct PresenceAddress from bytes: " + e);
                throw;
            }
        }

        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream(640))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    if(version == 1)
                    {
                        // TODO remove this after upgrade
                        writer.Write(version);
                        writer.Write(new System.Guid(device).ToString());
                        writer.Write(address);
                        writer.Write(type);
                        writer.Write(nodeVersion);
                        writer.Write(lastSeenTime);
                        if (signature != null)
                        {
                            writer.Write(signature.Length);
                            writer.Write(signature);
                        }
                        else
                        {
                            writer.Write(0);
                        }
                    }
                    else
                    {
                        writer.WriteIxiVarInt(version);
                        writer.WriteIxiVarInt(device.Length);
                        writer.Write(device);

                        writer.Write(address);
                        writer.Write(type);
                        writer.Write(nodeVersion);
                        writer.WriteIxiVarInt(lastSeenTime);
                        if (signature != null)
                        {
                            writer.WriteIxiVarInt(signature.Length);
                            writer.Write(signature);
                        }
                        else
                        {
                            writer.Write(0);
                        }
                    }
#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("PresenceAddress::getBytes: {0}", m.Length));
#endif
                }
                return m.ToArray();
            }
        }

        public byte[] getKeepAliveBytes(byte[] wallet_address)
        {
            if(version == 1)
            {
                // TODO remove this section after upgrade to Presence v1
                using (MemoryStream m = new MemoryStream(640))
                {
                    using (BinaryWriter writer = new BinaryWriter(m))
                    {
                        writer.Write(version); // version

                        writer.Write(wallet_address.Length);
                        writer.Write(wallet_address);

                        writer.Write(new System.Guid(device).ToString());

                        writer.Write(lastSeenTime);

                        writer.Write(address);
                        writer.Write(type);

                        writer.Write(signature.Length);
                        writer.Write(signature);

#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("PresenceAddress::getKeepAliveBytes: {0}", m.Length));
#endif
                    }
                    return m.ToArray();
                }
            }else
            {
                return getKeepAliveBytes_v2(wallet_address);
            }
        }
        public byte[] getKeepAliveBytes_v2(byte[] wallet_address)
        {
            using (MemoryStream m = new MemoryStream(640))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.WriteIxiVarInt(2); // version

                    writer.WriteIxiVarInt(wallet_address.Length);
                    writer.Write(wallet_address);

                    writer.WriteIxiVarInt(device.Length);
                    writer.Write(device);

                    writer.WriteIxiVarInt(lastSeenTime);

                    writer.Write(address);
                    writer.Write(type);

                    writer.WriteIxiVarInt(signature.Length);
                    writer.Write(signature);

#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("PresenceAddress::getKeepAliveBytes: {0}", m.Length));
#endif
                }
                return m.ToArray();
            }
        }

        public bool verifySignature(byte[] wallet, byte[] pub_key)
        {
            if (signature != null)
            {
                using (MemoryStream m = new MemoryStream())
                {
                    using (BinaryWriter writer = new BinaryWriter(m))
                    {
                        if(version == 1)
                        {
                            // TODO remove this section after upgrade to Presence v1
                            writer.Write(version);
                            writer.Write(wallet.Length);
                            writer.Write(wallet);
                            writer.Write(new System.Guid(device).ToString());
                            writer.Write(lastSeenTime);
                            writer.Write(address);
                            writer.Write(type);
                        }
                        else
                        {
                            writer.WriteIxiVarInt(version);
                            writer.WriteIxiVarInt(wallet.Length);
                            writer.Write(wallet);
                            writer.WriteIxiVarInt(device.Length);
                            writer.Write(device);
                            writer.WriteIxiVarInt(lastSeenTime);
                            writer.Write(address);
                            writer.Write(type);
                        }
                    }

                    byte[] bytes = m.ToArray();
                    // Verify the signature
                    if (CryptoManager.lib.verifySignature(bytes, pub_key, signature))
                    {
                        return true;
                    }
                }
            }


            return false;
        }

        public override bool Equals(object obj)
        {
            var item = obj as PresenceAddress;

            if (item == null)
            {
                return false;
            }

            if (item.address.SequenceEqual(address) == false)
            {
                return false;
            }

            if (item.device.SequenceEqual(device) == false)
            {
                return false;
            }

            if (item.type != type)
            {
                return false;
            }

            if (item.nodeVersion.Equals(nodeVersion, StringComparison.Ordinal) == false)
            {
                return false;
            }

            return true;
        }

        public override int GetHashCode()
        {
            return device.GetHashCode() ^ address.GetHashCode();
        }


    }

    // The actual presence object, which can contain multiple PresenceAddress objects
    public class Presence
    {
        public int version = 0;
        public byte[] wallet;
        public byte[] pubkey;
        public byte[] metadata; 
        public List<PresenceAddress> addresses;

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
    }
}
