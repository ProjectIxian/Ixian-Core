using IXICore.Utils;
using System.IO;

namespace IXICore.Inventory
{
    public enum InventoryItemTypes
    {
        transaction = 0,
        block = 1,
        blockSignature = 2,
        keepAlive = 3
    }

    public class InventoryItem
    {
        public InventoryItemTypes type;
        public byte[] hash;

        public InventoryItem()
        {

        }

        public InventoryItem(InventoryItemTypes type, byte[] hash)
        {
            this.type = type;
            this.hash = hash;
        }

        public InventoryItem(byte[] bytes)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    type = (InventoryItemTypes)reader.ReadIxiVarInt();

                    int hash_len = (int)reader.ReadIxiVarUInt();
                    hash = reader.ReadBytes(hash_len);
                }
            }
        }

        virtual public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.WriteIxiVarInt((int)type);

                    writer.WriteIxiVarInt(hash.Length);
                    writer.Write(hash);
                }
                return m.ToArray();
            }
        }
    }
}