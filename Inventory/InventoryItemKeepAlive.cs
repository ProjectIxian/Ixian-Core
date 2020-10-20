
using IXICore.Utils;
using System.IO;

namespace IXICore.Inventory
{
    public class InventoryItemKeepAlive : InventoryItem
    {
        public long lastSeen;
        public byte[] address;
        public byte[] deviceId;

        public InventoryItemKeepAlive(byte[] hash, long lastSeen, byte[] address, byte[] deviceId)
        {
            type = InventoryItemTypes.keepAlive;
            this.hash = hash;
            this.lastSeen = lastSeen;
            this.address = address;
            this.deviceId = deviceId;
        }

        public InventoryItemKeepAlive(byte[] bytes)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    type = (InventoryItemTypes)reader.ReadIxiVarInt();

                    int hash_len = (int)reader.ReadIxiVarUInt();
                    hash = reader.ReadBytes(hash_len);

                    lastSeen = reader.ReadIxiVarInt();

                    int address_len = (int)reader.ReadIxiVarUInt();
                    address = reader.ReadBytes(address_len);

                    int device_id_len = (int)reader.ReadIxiVarUInt();
                    deviceId = reader.ReadBytes(device_id_len);
                }
            }
        }

        override public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.WriteIxiVarInt((int)type);

                    writer.WriteIxiVarInt(hash.Length);
                    writer.Write(hash);

                    writer.WriteIxiVarInt(lastSeen);

                    writer.WriteIxiVarInt(address.Length);
                    writer.Write(address);

                    writer.WriteIxiVarInt(deviceId.Length);
                    writer.Write(deviceId);
                }
                return m.ToArray();
            }
        }
    }
}
