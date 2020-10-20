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
                    type = (InventoryItemTypes)reader.ReadIxiVarInt();

                    int hash_len = (int)reader.ReadIxiVarUInt();
                    hash = reader.ReadBytes(hash_len);

                    blockNum = reader.ReadIxiVarUInt();
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

                    writer.WriteIxiVarInt(blockNum);
                }
                return m.ToArray();
            }
        }
    }
}
