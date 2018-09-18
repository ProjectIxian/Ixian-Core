using DLT.Meta;
using DLT.Network;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DLT
{
    // An object class that describes how to contact the specific node/client
    public class PresenceAddress
    {
        public string device; // Device id
        public string address; // IP and port
        public char type;   // M for MasterNode, R for RelayNode, D for Direct ip client, C for normal client
        public string version; // Version
        public string lastSeenTime;

        public PresenceAddress()
        {
            device = Config.device_id;
            address = string.Format("{0}:{1}", CoreNetworkUtils.GetLocalIPAddress(), Config.serverPort);
            type = 'M';
            version = Config.version;
            lastSeenTime = Clock.getTimestamp(DateTime.Now);
        }

        public PresenceAddress(string node_device, string node_address, char node_type, string node_version)
        {
            device = node_device;
            address = node_address;
            type = node_type;
            version = node_version;
            lastSeenTime = Clock.getTimestamp(DateTime.Now);
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
                    lastSeenTime = reader.ReadString();
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

            if (item.address.Equals(address, StringComparison.Ordinal) == false)
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
        public string wallet;
        public string pubkey;
        public string metadata; 
        public List<PresenceAddress> addresses;
        public string owner; // Represents the node that can perform changes for this presence (usually a master or relay node)

        public Presence()
        {
            wallet = " ";
            pubkey = " ";
            metadata = " ";
            addresses = new List<PresenceAddress> { };
            //owner = PresenceList.getFirstMasterNodeAddress();
            owner = " ";
        }

        public Presence(string wallet_address, string node_pubkey, string node_ip, char node_type, string node_version)
        {
            wallet = wallet_address;
            pubkey = node_pubkey;
            metadata = " ";
            addresses = new List<PresenceAddress> { };
            
            // Generate a device id
            string deviceId = Guid.NewGuid().ToString();
            PresenceAddress address = new PresenceAddress(deviceId, node_ip, node_type, node_version);
            addresses.Add(address);
            owner = " ";

        }

        public Presence(string wallet_address, string node_pubkey, string node_meta, PresenceAddress node_address)
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

            wallet = string.Empty;
            pubkey = string.Empty;
            metadata = string.Empty;
            owner = string.Empty;


            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    wallet = reader.ReadString();
                    pubkey = reader.ReadString();
                    metadata = reader.ReadString();


                    // Read number of addresses
                    UInt16 number_of_addresses = reader.ReadUInt16();

                    // Read addresses
                    for(UInt16 i = 0; i < number_of_addresses; i++)
                    {
                        int byte_count = reader.ReadInt32();
                        byte[] address_bytes = reader.ReadBytes(byte_count);

                        addresses.Add(new PresenceAddress(address_bytes));
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
                    writer.Write(wallet);
                    writer.Write(pubkey);
                    writer.Write(metadata);

                    // Write the number of ips
                    UInt16 number_of_addresses = (UInt16) addresses.Count;
                    writer.Write(number_of_addresses);

                    // Write all ips
                    for (UInt16 i = 0; i < number_of_addresses; i++)
                    {
                        byte[] address_data = addresses[i].getBytes();
                        int address_data_size = address_data.Length;
                        writer.Write(address_data_size);
                        writer.Write(address_data);
                    }

                    writer.Write(owner);
                }
                return m.ToArray();
            }
        }

        // Adds an address to the presence. If the address is already found, returns false.
        // If forceUpdate is true, it will overwrite the address if it's found.
        public bool addAddress(PresenceAddress address, bool forceUpdate = false)
        {
            foreach(PresenceAddress addr in addresses)
            {
                if(address.device.Equals(addr.device, StringComparison.Ordinal))
                {
                    return false;
                }
            }

            return true;
        }

    }
}
