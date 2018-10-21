using DLT.Meta;
using DLT.Network;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace DLT
{
    // TODO TODO TODO add sigs to PresenceAddress; when syncing with other nodes,
    // we can't rely on them sending the correct data, we have to verify with the originators sigs otherwise the entry is invalid
    // An object class that describes how to contact the specific node/client
    public class PresenceAddress
    {
        public string device; // Device id
        public string address; // IP and port
        public char type;   // M for MasterNode, R for RelayNode, D for Direct ip client, C for normal client
        public string version; // Version
        public long lastSeenTime;
        public byte[] signature;

        public PresenceAddress()
        {
            device = Config.device_id;
            address = string.Format("{0}:{1}", CoreNetworkUtils.GetLocalIPAddress(), Config.serverPort);
            type = 'M';
            version = Config.version;
            lastSeenTime = Node.getCurrentTimestamp();
            signature = null;
        }

        public PresenceAddress(string node_device, string node_address, char node_type, string node_version, long node_lastSeenTime, byte[] node_signature)
        {
            device = node_device;
            address = node_address;
            type = node_type;
            version = node_version;
            lastSeenTime = node_lastSeenTime;
            signature = node_signature;
        }

        public PresenceAddress(byte[] bytes)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    device = reader.ReadString();
                    address = reader.ReadString();
                    type = reader.ReadChar();
                    version = reader.ReadString();
                    lastSeenTime = reader.ReadInt64();
                    int sigLen = reader.ReadInt32();
                    if (sigLen > 0)
                    {
                        signature = reader.ReadBytes(sigLen);
                    }
                }
            }
        }

        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(device);
                    writer.Write(address);
                    writer.Write(type);
                    writer.Write(version);
                    writer.Write(lastSeenTime);
                    if (signature != null)
                    {
                        writer.Write(signature.Length);
                        writer.Write(signature);
                    }else
                    {
                        writer.Write(0);
                    }
                }
                return m.ToArray();
            }
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

            if (item.device.Equals(device, StringComparison.Ordinal) == false)
            {
                return false;
            }

            if (item.type != type)
            {
                return false;
            }

            if (item.version.Equals(version, StringComparison.Ordinal) == false)
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
        public byte[] wallet;
        public byte[] pubkey;
        public byte[] metadata; 
        public List<PresenceAddress> addresses;
        public string owner; // Represents the node that can perform changes for this presence (usually a master or relay node)

        public Presence()
        {
            wallet = null;
            pubkey = null;
            metadata = null;
            addresses = new List<PresenceAddress> { };
            //owner = PresenceList.getFirstMasterNodeAddress();
            owner = " ";
        }

        public Presence(byte[] wallet_address, byte[] node_pubkey, string node_ip, char node_type, string node_version)
        {
            wallet = wallet_address;
            pubkey = node_pubkey;
            metadata = null;
            addresses = new List<PresenceAddress> { };
            
            // Generate a device id
            string deviceId = Guid.NewGuid().ToString();
            PresenceAddress address = new PresenceAddress(deviceId, node_ip, node_type, node_version, 0, null);
            addresses.Add(address);
            owner = " ";

        }

        public Presence(byte[] wallet_address, byte[] node_pubkey, byte[] node_meta, PresenceAddress node_address)
        {
            wallet = wallet_address;
            pubkey = node_pubkey;
            metadata = node_meta;
            addresses = new List<PresenceAddress> { };
            addresses.Add(node_address);
            owner = " ";
        }

        public Presence(byte[] bytes)
        {
            // Prepare addresses
            addresses = new List<PresenceAddress> { };

            wallet = null;
            pubkey = null;
            metadata = null;
            owner = string.Empty;


            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
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
                    for(UInt16 i = 0; i < number_of_addresses; i++)
                    {
                        int byte_count = reader.ReadInt32();
                        if (byte_count > 0)
                        {
                            byte[] address_bytes = reader.ReadBytes(byte_count);

                            addresses.Add(new PresenceAddress(address_bytes));
                        }
                    }

                    owner = reader.ReadString();
                }
            }
        }

        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    if (wallet != null)
                    {
                        writer.Write(wallet.Length);
                        writer.Write(wallet);
                    }else
                    {
                        writer.Write(0);
                    }

                    if (pubkey != null)
                    {
                        writer.Write(pubkey.Length);
                        writer.Write(pubkey);
                    }else
                    {
                        writer.Write(0);
                    }

                    if (metadata != null)
                    {
                        writer.Write(metadata.Length);
                        writer.Write(metadata);
                    }else
                    {
                        writer.Write(0);
                    }

                    // Write the number of ips
                    UInt16 number_of_addresses = (UInt16) addresses.Count;
                    writer.Write(number_of_addresses);

                    // Write all ips
                    for (UInt16 i = 0; i < number_of_addresses; i++)
                    {
                        if (addresses[i] == null)
                        {
                            writer.Write(0);
                            continue;
                        }
                        byte[] address_data = addresses[i].getBytes();
                        if(address_data != null)
                        {
                            writer.Write(address_data.Length);
                            writer.Write(address_data);
                        }else
                        {
                            writer.Write(0);
                        }
                    }

                    writer.Write(owner);
                }
                return m.ToArray();
            }
        }
    }
}
