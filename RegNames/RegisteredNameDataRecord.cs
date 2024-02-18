// Copyright (C) 2017-2024 Ixian OU
// This file is part of Ixian Core - www.github.com/ProjectIxian/Ixian-Core
//
// Ixian Core is free software: you can redistribute it and/or modify
// it under the terms of the MIT License as published
// by the Open Source Initiative.
//
// Ixian Core is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// MIT License for more details.
//

using IXICore.Utils;
using System;

namespace IXICore.RegNames
{

    public class RegisteredNameDataRecord
    {
        public byte[] name { get; private set; }
        public int ttl { get; private set; }
        public byte[] data { get; private set; }
        public byte[] checksum { get; private set; }

        public int recordSize { get; private set; }

        public RegisteredNameDataRecord(byte[] name, int ttl, byte[] data, byte[] checksum = null)
        {
            this.name = name;
            this.ttl = ttl;
            this.data = data;
            this.checksum = checksum;
            recordSize = toBytes(false).Length;
        }

        public RegisteredNameDataRecord(RegisteredNameDataRecord other)
        {
            name = IxiUtils.copy(other.name);
            ttl = other.ttl;
            data = IxiUtils.copy(other.data);
            checksum = IxiUtils.copy(other.checksum);
            recordSize = other.recordSize;
        }

        public RegisteredNameDataRecord(byte[] bytes, bool includeChecksum)
        {
            fromBytes(bytes, includeChecksum);
        }

        public void recalculateChecksum()
        {
            byte[] bytes = toBytes(false);
            checksum = CryptoManager.lib.sha3_512sq(bytes);
        }

        private void fromBytes(byte[] bytes, bool includeChecksum)
        {
            // Read the name length field
            int offset = 0;
            var nameLength = bytes.GetIxiVarInt(offset);
            if (nameLength.num < 1)
            {
                throw new Exception("Data Record Name must be at least 1 byte long");
            }
            if (nameLength.num > ConsensusConfig.rnMaxRecordKeyLength)
            {
                throw new Exception("Data Record Name too long");
            }
            offset += nameLength.bytesRead;

            // Read the name field
            name = new byte[nameLength.num];
            Array.Copy(bytes, offset, name, 0, nameLength.num);
            offset += name.Length;

            // Read the TTL field
            var ttlRet = bytes.GetIxiVarInt(offset);
            ttl = (int) ttlRet.num;
            offset += ttlRet.bytesRead;

            // Read the data length field
            var dataLengthRet = bytes.GetIxiVarInt(offset);
            int dataLength = (int)dataLengthRet.num;
            offset += dataLengthRet.bytesRead;

            // Read the data field
            if (dataLength > 0)
            {
                data = new byte[dataLength];
                Array.Copy(bytes, offset, data, 0, dataLength);
                offset += dataLength;
            }

            recordSize = offset;

            if (includeChecksum)
            {
                var checksumWithLength = bytes.ReadIxiBytes(offset);
                checksum = checksumWithLength.bytes;
                offset += checksumWithLength.bytesRead;
            }
        }

        public byte[] toBytes(bool includeChecksum)
        {
            byte[] nameLengthBytes = name.Length.GetIxiVarIntBytes();
            byte[] ttlBytes = ttl.GetIxiVarIntBytes();
            byte[] dataBytes = new byte[1] { 0 };
            if (data != null)
            {
                dataBytes = data.GetIxiBytes();
            }
            int maxLength = nameLengthBytes.Length + name.Length + ttlBytes.Length + dataBytes.Length;

            byte[] checksumBytes = null;
            if (includeChecksum)
            {
                checksumBytes = IxiUtils.GetIxiBytes(checksum);
                maxLength += checksumBytes.Length;
            }

            byte[] result = new byte[maxLength];

            int pos = 0;

            Array.Copy(nameLengthBytes, 0, result, pos, nameLengthBytes.Length);
            pos += nameLengthBytes.Length;

            Array.Copy(name, 0, result, pos, name.Length);
            pos += name.Length;

            Array.Copy(ttlBytes, 0, result, pos, ttlBytes.Length);
            pos += ttlBytes.Length;

            Array.Copy(dataBytes, 0, result, pos, dataBytes.Length);
            pos += dataBytes.Length;

            if (includeChecksum)
            {
                Array.Copy(checksumBytes, 0, result, pos, checksumBytes.Length);
                pos += checksumBytes.Length;
            }

            return result;
        }
    }
}
