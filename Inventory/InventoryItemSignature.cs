using IXICore.Utils;
using System;
using System.IO;

namespace IXICore.Inventory
{
    public class InventoryItemSignature : InventoryItem
    {
        public ulong blockNum;
        public byte[] blockHash;
        public byte[] address;

        public InventoryItemSignature(byte[] address, ulong blockNum, byte[] blockHash)
        {
            type = InventoryItemTypes.blockSignature;
            this.address = address;
            this.blockNum = blockNum;
            this.blockHash = blockHash;

            hash = getHash(address, blockHash);
        }

        public InventoryItemSignature(byte[] bytes)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    type = (InventoryItemTypes)reader.ReadIxiVarInt();

                    int address_len = (int)reader.ReadIxiVarUInt();
                    address = reader.ReadBytes(address_len);

                    blockNum = reader.ReadIxiVarUInt();

                    int block_hash_len = (int)reader.ReadIxiVarUInt();
                    blockHash = reader.ReadBytes(block_hash_len);

                    byte[] address_block_hash = new byte[address_len + block_hash_len];
                    Array.Copy(address, address_block_hash, address_len);
                    Array.Copy(blockHash, 0, address_block_hash, address_len, block_hash_len);
                    hash = Crypto.sha512sqTrunc(address_block_hash);
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

                    writer.WriteIxiVarInt(address.Length);
                    writer.Write(address);

                    writer.WriteIxiVarInt(blockNum);

                    writer.WriteIxiVarInt(blockHash.Length);
                    writer.Write(blockHash);
                }
                return m.ToArray();
            }
        }

        static public byte[] getHash(byte[] address, byte[] block_hash)
        {
            byte[] address_block_hash = new byte[address.Length + block_hash.Length];
            Array.Copy(address, address_block_hash, address.Length);
            Array.Copy(block_hash, 0, address_block_hash, address.Length, block_hash.Length);
            return Crypto.sha512sqTrunc(address_block_hash);
        }
    }
}
