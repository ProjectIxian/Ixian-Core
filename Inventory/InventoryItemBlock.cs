using IXICore.Utils;
using System.IO;

namespace IXICore.Inventory
{
    public class InventoryItemBlock : InventoryItem
    {
        public ulong blockNum;

        public InventoryItemBlock(byte[] hash, ulong blockNum)
        {
            type = InventoryItemTypes.block;
            this.hash = hash;
            this.blockNum = blockNum;
        }

        public InventoryItemBlock(byte[] bytes)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    type = (InventoryItemTypes)reader.ReadVarInt();

                    int hash_len = (int)reader.ReadVarUInt();
                    hash = reader.ReadBytes(hash_len);

                    blockNum = reader.ReadVarUInt();
                }
            }
        }

        override public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.WriteVarInt((int)type);

                    writer.WriteVarInt(hash.Length);
                    writer.Write(hash);

                    writer.WriteVarInt(blockNum);
                }
                return m.ToArray();
            }
        }
    }
}
