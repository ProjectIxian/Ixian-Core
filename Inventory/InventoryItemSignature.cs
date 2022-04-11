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

using IXICore.Utils;
using System;
using System.IO;

namespace IXICore.Inventory
{
    public class InventoryItemSignature : InventoryItem
    {
        public ulong blockNum;
        public byte[] blockHash;
        public Address address;

        public InventoryItemSignature(Address address, ulong blockNum, byte[] blockHash)
        {
            type = InventoryItemTypes.blockSignature;
            this.address = address;
            this.blockNum = blockNum;
            this.blockHash = blockHash;

            hash = getHash(address.addressNoChecksum, blockHash);
        }

        public InventoryItemSignature(byte[] bytes)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    type = (InventoryItemTypes)reader.ReadIxiVarInt();

                    int address_len = (int)reader.ReadIxiVarUInt();
                    address = new Address(reader.ReadBytes(address_len));

                    blockNum = reader.ReadIxiVarUInt();

                    int block_hash_len = (int)reader.ReadIxiVarUInt();
                    blockHash = reader.ReadBytes(block_hash_len);

                    hash = getHash(address.addressNoChecksum, blockHash);
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

                    writer.WriteIxiVarInt(address.addressNoChecksum.Length);
                    writer.Write(address.addressNoChecksum);

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
            return CryptoManager.lib.sha3_512sqTrunc(address_block_hash);
        }
    }
}
