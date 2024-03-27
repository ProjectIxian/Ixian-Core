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
using System.Collections.Generic;
using System.Linq;

namespace IXICore.RegNames
{
    public enum RegNameRecordByteTypes
    {
        full,
        forSignature,
        forMerkle
    }

    public class RegisteredNameRecord
    {
        public int version = 1;
        public byte[] name { get; private set; }
        public ulong registrationBlockHeight { get; private set; }
        public uint capacity { get; private set; }

        public Address nextPkHash { get; private set; }
        public Address recoveryHash { get; private set; }
        public ulong sequence { get; private set; }

        public bool allowSubnames { get; private set; }
        public IxiNumber subnamePrice { get; private set; } = new IxiNumber(0);
        public Address subnameFeeRecipient { get; private set; }

        public List<RegisteredNameDataRecord> dataRecords { get; private set; } = new List<RegisteredNameDataRecord>();
        public byte[] dataMerkleRoot { get; private set; }

        public byte[] signaturePk { get; set; }
        public byte[] signature { get; set; }
       
        public ulong expirationBlockHeight { get; set; } = 0;
        public ulong updatedBlockHeight { get; private set; }
        public RegisteredNameRecord(byte[] name, ulong registrationBlockHeight, uint capacity, ulong expirationBlockHeight, Address nextPkHash, Address recoveryHash)
        {
            this.name = name;
            this.registrationBlockHeight = registrationBlockHeight;
            this.capacity = capacity;
            this.expirationBlockHeight = expirationBlockHeight;
            this.nextPkHash = nextPkHash;
            this.recoveryHash = recoveryHash;
            this.sequence = 0;
        }

        public RegisteredNameRecord(RegisteredNameRecord other)
        {
            version = other.version;
            name = IxiUtils.copy(other.name);
            registrationBlockHeight = other.registrationBlockHeight;
            capacity = other.capacity;
            nextPkHash = IxiUtils.copy(other.nextPkHash);
            recoveryHash = IxiUtils.copy(other.recoveryHash);
            sequence = other.sequence;
            allowSubnames = other.allowSubnames;
            subnamePrice = new IxiNumber(other.subnamePrice);
            subnameFeeRecipient = IxiUtils.copy(other.subnameFeeRecipient);
            dataRecords = new();
            foreach (var dataRecord in other.dataRecords)
            {
                dataRecords.Add(new RegisteredNameDataRecord(dataRecord));
            }
            dataMerkleRoot = IxiUtils.copy(other.dataMerkleRoot);
            signaturePk = IxiUtils.copy(other.signaturePk);
            signature = IxiUtils.copy(other.signature);
            expirationBlockHeight = other.expirationBlockHeight;
            updatedBlockHeight = other.updatedBlockHeight;
        }

        public RegisteredNameRecord(byte[] bytes)
        {
            fromBytes(bytes);
        }

        public void recalculateDataMerkleRoot()
        {
            List<byte[]> hashes = new();
            foreach (var dataRecord in dataRecords)
            {
                hashes.Add(dataRecord.checksum);
            }
            dataMerkleRoot = IxiUtils.calculateMerkleRoot(hashes);
        }

        public byte[] calculateChecksum(RegNameRecordByteTypes type = RegNameRecordByteTypes.forSignature)
        {
            byte[] bytes = toBytes(type);
            return CryptoManager.lib.sha3_512sq(bytes);
        }

        public int getTotalRecordSize()
        {
            int total = 0;
            foreach (var dataRecord in dataRecords)
            {
                total += dataRecord.recordSize;
            }
            return total;
        }

        public void fromBytes(byte[] bytes)
        {
            int offset = 0;
            var versionRet = bytes.GetIxiVarInt(offset);
            version = (int)versionRet.num;
            offset += versionRet.bytesRead;

            var nameLength = bytes.GetIxiVarInt(offset);
            if (nameLength.num < 1)
            {
                throw new Exception("Name must be at least 1 byte long");
            }
            if (nameLength.num > ConsensusConfig.rnMaxNameLength)
            {
                throw new Exception("Name too long");
            }
            offset += nameLength.bytesRead;

            name = new byte[nameLength.num];
            Array.Copy(bytes, offset, name, 0, nameLength.num);
            offset += name.Length;

            var registrationBlockHeightRet = bytes.GetIxiVarUInt(offset);
            registrationBlockHeight = registrationBlockHeightRet.num;
            offset += registrationBlockHeightRet.bytesRead;

            var capacityRet = bytes.GetIxiVarUInt(offset);
            capacity = (uint)capacityRet.num;
            offset += capacityRet.bytesRead;

            var nextPkHashLen = bytes.GetIxiVarInt(offset);
            offset += nextPkHashLen.bytesRead;

            byte[] nextPkHashBytes = new byte[nextPkHashLen.num];
            Array.Copy(bytes, offset, nextPkHashBytes, 0, nextPkHashLen.num);
            offset += (int)nextPkHashLen.num;
            nextPkHash = new Address(nextPkHashBytes);

            var recoveryHashLen = bytes.GetIxiVarInt(offset);
            offset += recoveryHashLen.bytesRead;

            byte[] recoveryHashBytes = new byte[recoveryHashLen.num];
            Array.Copy(bytes, offset, recoveryHashBytes, 0, recoveryHashLen.num);
            offset += (int)recoveryHashLen.num;
            recoveryHash = new Address(recoveryHashBytes);

            var sequenceRet = bytes.GetIxiVarUInt(offset);
            sequence = sequenceRet.num;
            offset += sequenceRet.bytesRead;

            allowSubnames = bytes[offset] == 1 ? true : false;
            offset += 1;

            var subnamePriceLen = bytes.GetIxiVarInt(offset);
            offset += subnamePriceLen.bytesRead;

            byte[] subnamePriceBytes = new byte[subnamePriceLen.num];
            Array.Copy(bytes, offset, subnamePriceBytes, 0, subnamePriceLen.num);
            offset += (int)subnamePriceLen.num;
            subnamePrice = new IxiNumber(subnamePriceBytes);

            var subnameFeeRecipientLen = bytes.GetIxiVarInt(offset);
            offset += subnameFeeRecipientLen.bytesRead;

            if (subnameFeeRecipientLen.num > 0)
            {
                byte[] subnameFeeRecipientBytes = new byte[subnameFeeRecipientLen.num];
                Array.Copy(bytes, offset, subnameFeeRecipientBytes, 0, subnameFeeRecipientLen.num);
                offset += (int)subnameFeeRecipientLen.num;
                subnameFeeRecipient = new Address(subnameFeeRecipientBytes);
            }

            var dataMerkleRootLength = bytes.GetIxiVarInt(offset);
            offset += dataMerkleRootLength.bytesRead;

            if (dataMerkleRootLength.num > 0)
            {
                dataMerkleRoot = new byte[dataMerkleRootLength.num];
                Array.Copy(bytes, offset, dataMerkleRoot, 0, dataMerkleRootLength.num);
                offset += (int)dataMerkleRootLength.num;
            }

            var signaturePkLen = bytes.GetIxiVarInt(offset);
            offset += signaturePkLen.bytesRead;

            if (signaturePkLen.num > 0)
            {
                signaturePk = new byte[signaturePkLen.num];
                Array.Copy(bytes, offset, signaturePk, 0, signaturePkLen.num);
                offset += (int)signaturePkLen.num;
            }

            var signatureLen = bytes.GetIxiVarInt(offset);
            offset += signatureLen.bytesRead;

            if (signatureLen.num > 0)
            {
                signature = new byte[signatureLen.num];
                Array.Copy(bytes, offset, signature, 0, signatureLen.num);
                offset += (int)signatureLen.num;
            }

            var expirationBlockHeightRet = bytes.GetIxiVarUInt(offset);
            expirationBlockHeight = expirationBlockHeightRet.num;
            offset += expirationBlockHeightRet.bytesRead;

            var updatedBlockHeightRet = bytes.GetIxiVarUInt(offset);
            updatedBlockHeight = updatedBlockHeightRet.num;
            offset += updatedBlockHeightRet.bytesRead;
        }

        public byte[] toBytes(RegNameRecordByteTypes type)
        {
            byte[] nameLenBytes = name.Length.GetIxiVarIntBytes();
            byte[] registrationBlockHeightBytes = registrationBlockHeight.GetIxiVarIntBytes();
            byte[] capacityBytes = ((ulong)capacity).GetIxiVarIntBytes();
            byte[] nextPkHashLenBytes = nextPkHash.addressNoChecksum.Length.GetIxiVarIntBytes();
            byte[] recoveryHashLenBytes = recoveryHash.addressNoChecksum.Length.GetIxiVarIntBytes();
            byte[] sequenceBytes = sequence.GetIxiVarIntBytes();
            byte[] subnamePriceLenBytes = subnamePrice.getBytes().Length.GetIxiVarIntBytes();

            int subnameFeeRecipientLen = 0;
            if (subnameFeeRecipient != null)
            {
                subnameFeeRecipientLen = subnameFeeRecipient.addressNoChecksum.Length;
            }
            byte[] subnameFeeRecipientLenBytes = subnameFeeRecipientLen.GetIxiVarIntBytes();

            int dataMerkleRootLen = 0;
            if (dataMerkleRoot != null)
            {
                dataMerkleRootLen = dataMerkleRoot.Length;
            }
            byte[] dataMerkleRootLenBytes = dataMerkleRootLen.GetIxiVarIntBytes();

            int signaturePkLen = 0;
            if (type == RegNameRecordByteTypes.full && signaturePk != null)
            {
                signaturePkLen = signaturePk.Length;
            }
            byte[] signaturePkLenBytes = signaturePkLen.GetIxiVarIntBytes();

            int sigLen = 0;
            if (type == RegNameRecordByteTypes.full && signature != null)
            {
                sigLen = signature.Length;
            }
            byte[] sigLenBytes = sigLen.GetIxiVarIntBytes();

            int expirationBlockHeightLen = 0;
            byte[] expirationBlockHeightBytes = null;
            int updatedBlockHeightLen = 0;
            byte[] updatedBlockHeightBytes = null;
            if (type == RegNameRecordByteTypes.full || type == RegNameRecordByteTypes.forMerkle)
            {
                expirationBlockHeightBytes = expirationBlockHeight.GetIxiVarIntBytes();
                expirationBlockHeightLen = expirationBlockHeightBytes.Length;
                updatedBlockHeightBytes = updatedBlockHeight.GetIxiVarIntBytes();
                updatedBlockHeightLen = updatedBlockHeightBytes.Length;
            }


            byte[] bytes = new byte[
                1 // version
                + nameLenBytes.Length
                + name.Length
                + registrationBlockHeightBytes.Length
                + capacityBytes.Length
                + nextPkHashLenBytes.Length
                + nextPkHash.addressNoChecksum.Length
                + recoveryHashLenBytes.Length
                + recoveryHash.addressNoChecksum.Length
                + sequenceBytes.Length
                + 1 // bool allowSubnames
                + subnamePriceLenBytes.Length
                + subnamePrice.getBytes().Length
                + subnameFeeRecipientLenBytes.Length
                + subnameFeeRecipientLen
                + dataMerkleRootLenBytes.Length
                + dataMerkleRootLen
                + signaturePkLenBytes.Length
                + signaturePkLen
                + sigLenBytes.Length
                + sigLen
                + expirationBlockHeightLen
                + updatedBlockHeightLen
                ];

            int pos = 0;
            Array.Copy(version.GetIxiVarIntBytes(), 0, bytes, pos, 1);
            pos += 1;

            Array.Copy(nameLenBytes, 0, bytes, pos, nameLenBytes.Length);
            pos += nameLenBytes.Length;

            Array.Copy(name, 0, bytes, pos, name.Length);
            pos += name.Length;

            Array.Copy(registrationBlockHeightBytes, 0, bytes, pos, registrationBlockHeightBytes.Length);
            pos += registrationBlockHeightBytes.Length;

            Array.Copy(capacityBytes, 0, bytes, pos, capacityBytes.Length);
            pos += capacityBytes.Length;

            Array.Copy(nextPkHashLenBytes, 0, bytes, pos, nextPkHashLenBytes.Length);
            pos += nextPkHashLenBytes.Length;

            Array.Copy(nextPkHash.addressNoChecksum, 0, bytes, pos, nextPkHash.addressNoChecksum.Length);
            pos += nextPkHash.addressNoChecksum.Length;

            Array.Copy(recoveryHashLenBytes, 0, bytes, pos, recoveryHashLenBytes.Length);
            pos += recoveryHashLenBytes.Length;

            Array.Copy(recoveryHash.addressNoChecksum, 0, bytes, pos, recoveryHash.addressNoChecksum.Length);
            pos += recoveryHash.addressNoChecksum.Length;

            Array.Copy(sequenceBytes, 0, bytes, pos, sequenceBytes.Length);
            pos += sequenceBytes.Length;

            bytes[pos] = Convert.ToByte(allowSubnames);
            pos += 1;

            Array.Copy(subnamePriceLenBytes, 0, bytes, pos, subnamePriceLenBytes.Length);
            pos += subnamePriceLenBytes.Length;

            Array.Copy(subnamePrice.getBytes(), 0, bytes, pos, subnamePrice.getBytes().Length);
            pos += subnamePrice.getBytes().Length;

            Array.Copy(subnameFeeRecipientLenBytes, 0, bytes, pos, subnameFeeRecipientLenBytes.Length);
            pos += subnameFeeRecipientLenBytes.Length;

            if (subnameFeeRecipientLen > 0)
            {
                Array.Copy(subnameFeeRecipient.addressNoChecksum, 0, bytes, pos, subnameFeeRecipient.addressNoChecksum.Length);
                pos += subnameFeeRecipient.addressNoChecksum.Length;
            }

            Array.Copy(dataMerkleRootLenBytes, 0, bytes, pos, dataMerkleRootLenBytes.Length);
            pos += dataMerkleRootLenBytes.Length;

            if (dataMerkleRootLen > 0)
            {
                Array.Copy(dataMerkleRoot, 0, bytes, pos, dataMerkleRoot.Length);
                pos += dataMerkleRoot.Length;
            }

            if (type == RegNameRecordByteTypes.full)
            {
                Array.Copy(signaturePkLenBytes, 0, bytes, pos, signaturePkLenBytes.Length);
                pos += signaturePkLenBytes.Length;

                if (signaturePkLen > 0)
                {
                    Array.Copy(signaturePk, 0, bytes, pos, signaturePk.Length);
                    pos += signaturePk.Length;
                }

                Array.Copy(sigLenBytes, 0, bytes, pos, sigLenBytes.Length);
                pos += sigLenBytes.Length;

                if (sigLen > 0)
                {
                    Array.Copy(signature, 0, bytes, pos, signature.Length);
                    pos += signature.Length;
                }
            }

            if (type == RegNameRecordByteTypes.full || type == RegNameRecordByteTypes.forMerkle)
            {
                Array.Copy(expirationBlockHeightBytes, 0, bytes, pos, expirationBlockHeightBytes.Length);
                pos += expirationBlockHeightBytes.Length;

                Array.Copy(updatedBlockHeightBytes, 0, bytes, pos, updatedBlockHeightBytes.Length);
                pos += updatedBlockHeightBytes.Length;
            }

            return bytes;
        }

        public List<RegisteredNameDataRecord> getDataRecords(byte[] name)
        {
            if (name != null)
            {
                return dataRecords.FindAll(x => x.name.SequenceEqual(name));
            }

            return dataRecords;
        }

        public void setCapacity(uint newCapacity, ulong sequence, Address pkHash, byte[] sigPk, byte[] sig)
        {
            capacity = newCapacity;
            this.sequence = sequence;
            nextPkHash = pkHash;
            signaturePk = sigPk;
            signature = sig;
        }

        public void setRecords(List<RegisteredNameDataRecord> records, ulong sequence, Address pkHash, byte[] sigPk, byte[] sig)
        {
            dataRecords = records;
            // TODO Data Merkle Root can be cached for revert operations
            recalculateDataMerkleRoot();
            this.sequence = sequence;
            nextPkHash = pkHash;
            signaturePk = sigPk;
            signature = sig;
        }

        public void setRecoveryHash(Address recoveryHash, ulong sequence, Address pkHash, byte[] sigPk, byte[] sig)
        {
            this.recoveryHash = recoveryHash;
            this.sequence = sequence;
            nextPkHash = pkHash;
            signaturePk = sigPk;
            signature = sig;
        }

        public void setAllowSubnames(bool allowSubnames, IxiNumber subnamePrice, Address subnameFeeRecipient, ulong sequence, Address pkHash, byte[] sigPk, byte[] sig)
        {
            // Reset data records if enabling subnames
            if (allowSubnames && !this.allowSubnames)
            {
                dataRecords = new();
                capacity = ConsensusConfig.rnMinCapacity;
            }
            this.allowSubnames = allowSubnames;
            this.subnamePrice = subnamePrice;
            this.subnameFeeRecipient = subnameFeeRecipient;
            // TODO Data Merkle Root can be cached for revert operations
            recalculateDataMerkleRoot();
            this.sequence = sequence;
            nextPkHash = pkHash;
            signaturePk = sigPk;
            signature = sig;
        }

    }
}
