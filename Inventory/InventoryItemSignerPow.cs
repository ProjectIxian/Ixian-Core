﻿// Copyright (C) 2017-2020 Ixian OU
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
    public class InventoryItemSignerPow : InventoryItem
    {
        public byte[] address;
        public ulong blockNum;

        public InventoryItemSignerPow(byte[] address, ulong blockNum)
        {
            type = InventoryItemTypes.signerPow;
            this.address = address;
            this.blockNum = blockNum;

            hash = getHash(address, blockNum);
        }

        public InventoryItemSignerPow(byte[] bytes)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    type = (InventoryItemTypes)reader.ReadIxiVarInt();

                    int address_len = (int)reader.ReadIxiVarUInt();
                    address = reader.ReadBytes(address_len);

                    blockNum = reader.ReadIxiVarUInt();

                    hash = getHash(address, blockNum);
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
                }
                return m.ToArray();
            }
        }

        static public byte[] getHash(byte[] address, ulong blockNum)
        {
            byte[] blockNumBytes = BitConverter.GetBytes(blockNum);
            byte[] addressBlockNum = new byte[address.Length + blockNumBytes.Length];
            Array.Copy(address, addressBlockNum, address.Length);
            Array.Copy(blockNumBytes, 0, addressBlockNum, address.Length, blockNumBytes.Length);
            return Crypto.sha512sqTrunc(addressBlockNum);
        }
    }
}