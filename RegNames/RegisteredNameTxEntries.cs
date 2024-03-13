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

using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.IO;

namespace IXICore.RegNames
{
    public enum RegNameInstruction : byte
    {
        register = 1,
        updateRecord = 2,
        extend = 3,
        changeCapacity = 4,
        recover = 5,
        toggleAllowSubnames = 6
    }

    public class RegNameTxEntryBase
    {
        public RegNameInstruction instruction { get; protected set; }
        public byte[] name { get; protected set; }
        public Address nextPkHash { get; protected set; }
        public byte[] signaturePk { get; protected set; }
        public byte[] signature { get; protected set; }
        public RegNameTxEntryBase(RegNameInstruction instruction, byte[] name, Address nextPkHash, byte[] signaturePk, byte[] signature)
        {
            this.instruction = instruction;
            this.name = name;
            this.nextPkHash = nextPkHash;
            this.signaturePk = signaturePk;
            this.signature = signature;
        }

        protected RegNameTxEntryBase() { }
    }

    public class RegNameRegister : RegNameTxEntryBase
    {
        public uint registrationTimeInBlocks { get; private set; }
        public Address recoveryHash { get; private set; }
        public uint capacity { get; private set; }
        public RegNameRegister(byte[] name, uint registrationTimeInBlocks, uint capacity, Address nextPkHash, Address recoveryHash)
            : base(RegNameInstruction.register, name, nextPkHash, null, null)
        {
            this.registrationTimeInBlocks = registrationTimeInBlocks;
            this.capacity = capacity;
            this.recoveryHash = recoveryHash;
        }

        public RegNameRegister(byte[] bytes)
        {
            fromBytes(bytes);
        }

        private void fromBytes(byte[] bytes)
        {
            instruction = (RegNameInstruction)bytes[0];
            if (instruction != RegNameInstruction.register)
            {
                throw new Exception("Invalid instruction " + instruction + ", expecting: " + RegNameInstruction.register);
            }
            int offset = 1;

            var nameBytesAndOffset = bytes.ReadIxiBytes(offset);
            name = nameBytesAndOffset.bytes;
            if (name.Length > ConsensusConfig.rnMaxNameLength)
            {
                throw new Exception("Name too long");
            }
            offset += nameBytesAndOffset.bytesRead;

            var monthsLength = bytes.GetIxiVarUInt(offset);
            registrationTimeInBlocks = (uint)monthsLength.num;
            offset += monthsLength.bytesRead;

            var capacityLength = bytes.GetIxiVarUInt(offset);
            capacity = (uint)capacityLength.num;
            offset += capacityLength.bytesRead;

            var recoveryHashBytesAndOffset = bytes.ReadIxiBytes(offset);
            recoveryHash = new Address(recoveryHashBytesAndOffset.bytes);
            offset += recoveryHashBytesAndOffset.bytesRead;

            var nextPkHashBytesAndOffset = bytes.ReadIxiBytes(offset);
            nextPkHash = new Address(nextPkHashBytesAndOffset.bytes);
            offset += nextPkHashBytesAndOffset.bytesRead;
        }

        public byte[] toBytes()
        {
            byte[] nameBytes = name.GetIxiBytes();
            byte[] monthsBytes = ((long)registrationTimeInBlocks).GetIxiVarIntBytes();
            byte[] capacityBytes = ((long)capacity).GetIxiVarIntBytes();

            byte[] nextPkHashBytes = nextPkHash.addressNoChecksum.GetIxiBytes();
            byte[] recoveryHashBytes = recoveryHash.addressNoChecksum.GetIxiBytes();

            byte[] bytes = new byte[1 + nameBytes.Length + recoveryHashBytes.Length + nextPkHashBytes.Length + monthsBytes.Length + capacityBytes.Length];

            bytes[0] = (byte)instruction;
            int offset = 1;

            Array.Copy(nameBytes, 0, bytes, offset, nameBytes.Length);
            offset += nameBytes.Length;

            Array.Copy(monthsBytes, 0, bytes, offset, monthsBytes.Length);
            offset += monthsBytes.Length;

            Array.Copy(capacityBytes, 0, bytes, offset, capacityBytes.Length);
            offset += capacityBytes.Length;

            Array.Copy(recoveryHashBytes, 0, bytes, offset, recoveryHashBytes.Length);
            offset += recoveryHashBytes.Length;

            Array.Copy(nextPkHashBytes, 0, bytes, offset, nextPkHashBytes.Length);
            offset += nextPkHashBytes.Length;

            return bytes;
        }
    }

    public class RegNameExtend : RegNameTxEntryBase
    {
        public uint extensionTimeInBlocks { get; private set; }
        public RegNameExtend(byte[] name, uint extensionTimeInBlocks)
            : base(RegNameInstruction.extend, name, null, null, null)
        {
            this.extensionTimeInBlocks = extensionTimeInBlocks;
        }

        public RegNameExtend(byte[] bytes)
        {
            fromBytes(bytes);
        }

        private void fromBytes(byte[] bytes)
        {
            instruction = (RegNameInstruction)bytes[0];
            if (instruction != RegNameInstruction.extend)
            {
                throw new Exception("Invalid instruction " + instruction + ", expecting: " + RegNameInstruction.extend);
            }
            int offset = 1;

            var nameBytesAndOffset = bytes.ReadIxiBytes(offset);
            name = nameBytesAndOffset.bytes;
            if (name.Length > ConsensusConfig.rnMaxNameLength)
            {
                throw new Exception("Name too long");
            }
            offset += nameBytesAndOffset.bytesRead;

            var monthsLength = bytes.GetIxiVarUInt(offset);
            extensionTimeInBlocks = (uint)monthsLength.num;
            offset += monthsLength.bytesRead;
        }

        public byte[] toBytes()
        {
            byte[] nameBytes = name.GetIxiBytes();
            byte[] monthsBytes = ((int)extensionTimeInBlocks).GetIxiVarIntBytes();

            byte[] bytes = new byte[1 + nameBytes.Length + monthsBytes.Length];

            bytes[0] = (byte)instruction;
            int offset = 1;

            Array.Copy(nameBytes, 0, bytes, offset, nameBytes.Length);
            offset += nameBytes.Length;

            Array.Copy(monthsBytes, 0, bytes, offset, monthsBytes.Length);
            offset += monthsBytes.Length;

            return bytes;
        }
    }

    public class RegNameChangeCapacity : RegNameTxEntryBase
    {
        public uint newCapacity { get; private set; }
        public ulong sequence { get; private set; }

        public RegNameChangeCapacity(byte[] name, uint newCapacity, ulong sequence, Address nextPkHash, Address sigPk, byte[] signature)
            : base(RegNameInstruction.changeCapacity, name, nextPkHash, sigPk.pubKey, signature)
        {
            this.newCapacity = newCapacity;
            this.sequence = sequence;
        }

        public RegNameChangeCapacity(byte[] bytes)
        {
            fromBytes(bytes);
        }

        private void fromBytes(byte[] bytes)
        {
            instruction = (RegNameInstruction)bytes[0];
            if (instruction != RegNameInstruction.changeCapacity)
            {
                throw new Exception("Invalid instruction " + instruction + ", expecting: " + RegNameInstruction.changeCapacity);
            }
            int offset = 1;

            var nameBytesAndOffset = bytes.ReadIxiBytes(offset);
            name = nameBytesAndOffset.bytes;
            offset += nameBytesAndOffset.bytesRead;

            var newCapacityLength = bytes.GetIxiVarUInt(offset);
            newCapacity = (uint)newCapacityLength.num;
            offset += newCapacityLength.bytesRead;

            var sequenceLength = bytes.GetIxiVarUInt(offset);
            sequence = sequenceLength.num;
            offset += sequenceLength.bytesRead;

            var nextPkHashBytesAndOffset = bytes.ReadIxiBytes(offset);
            nextPkHash = new Address(nextPkHashBytesAndOffset.bytes);
            offset += nextPkHashBytesAndOffset.bytesRead;

            var pkSigBytesAndOffset = bytes.ReadIxiBytes(offset);
            signaturePk = pkSigBytesAndOffset.bytes;
            offset += pkSigBytesAndOffset.bytesRead;

            var sigBytesAndOffset = bytes.ReadIxiBytes(offset);
            signature = sigBytesAndOffset.bytes;
            offset += sigBytesAndOffset.bytesRead;
        }

        public byte[] toBytes()
        {
            byte[] nameBytes = name.GetIxiBytes();
            byte[] newCapacityBytes = ((ulong)newCapacity).GetIxiVarIntBytes();
            byte[] sequenceBytes = sequence.GetIxiVarIntBytes();
            byte[] nextPkHashBytes = nextPkHash.addressNoChecksum.GetIxiBytes();
            byte[] pkSigBytes = signaturePk.GetIxiBytes();
            byte[] sigBytes = signature.GetIxiBytes();

            byte[] bytes = new byte[1 + nameBytes.Length + newCapacityBytes.Length + sequenceBytes.Length + nextPkHashBytes.Length + pkSigBytes.Length + sigBytes.Length];

            bytes[0] = (byte)instruction;
            int offset = 1;

            Array.Copy(nameBytes, 0, bytes, offset, nameBytes.Length);
            offset += nameBytes.Length;

            Array.Copy(newCapacityBytes, 0, bytes, offset, newCapacityBytes.Length);
            offset += newCapacityBytes.Length;

            Array.Copy(sequenceBytes, 0, bytes, offset, sequenceBytes.Length);
            offset += sequenceBytes.Length;

            Array.Copy(nextPkHashBytes, 0, bytes, offset, nextPkHashBytes.Length);
            offset += nextPkHashBytes.Length;

            Array.Copy(pkSigBytes, 0, bytes, offset, pkSigBytes.Length);
            offset += pkSigBytes.Length;

            Array.Copy(sigBytes, 0, bytes, offset, sigBytes.Length);
            offset += sigBytes.Length;

            return bytes;
        }
    }

    public class RegNameRecover : RegNameTxEntryBase
    {
        public Address newRecoveryHash { get; private set; }
        public ulong sequence { get; private set; }
        public RegNameRecover(byte[] name, ulong sequence, Address nextPkHash, Address newRecoveryHash, Address recoveryPk, byte[] recoverySig)
            : base(RegNameInstruction.recover, name, nextPkHash, recoveryPk.pubKey, recoverySig)
        {
            this.newRecoveryHash = newRecoveryHash;
            this.sequence = sequence;
        }

        public RegNameRecover(byte[] bytes)
        {
            fromBytes(bytes);
        }

        private void fromBytes(byte[] bytes)
        {
            instruction = (RegNameInstruction)bytes[0];
            if (instruction != RegNameInstruction.recover)
            {
                throw new Exception("Invalid instruction " + instruction + ", expecting: " + RegNameInstruction.recover);
            }
            int offset = 1;

            var nameBytesAndOffset = bytes.ReadIxiBytes(offset);
            name = nameBytesAndOffset.bytes;
            offset += nameBytesAndOffset.bytesRead;

            var newRecoveryHashBytesAndOffset = bytes.ReadIxiBytes(offset);
            newRecoveryHash = new Address(newRecoveryHashBytesAndOffset.bytes);
            offset += newRecoveryHashBytesAndOffset.bytesRead;

            var sequenceLength = bytes.GetIxiVarUInt(offset);
            sequence = sequenceLength.num;
            offset += sequenceLength.bytesRead;

            var nextPkHashBytesAndOffset = bytes.ReadIxiBytes(offset);
            nextPkHash = new Address(nextPkHashBytesAndOffset.bytes);
            offset += nextPkHashBytesAndOffset.bytesRead;

            var pkSigBytesAndOffset = bytes.ReadIxiBytes(offset);
            signaturePk = pkSigBytesAndOffset.bytes;
            offset += pkSigBytesAndOffset.bytesRead;

            var sigBytesAndOffset = bytes.ReadIxiBytes(offset);
            signature = sigBytesAndOffset.bytes;
            offset += sigBytesAndOffset.bytesRead;
        }

        public byte[] toBytes()
        {
            byte[] nameBytes = name.GetIxiBytes();
            byte[] newRecoveryHashBytes = newRecoveryHash.addressNoChecksum.GetIxiBytes();
            byte[] sequenceBytes = sequence.GetIxiVarIntBytes();
            byte[] nextPkHashBytes = nextPkHash.addressNoChecksum.GetIxiBytes();
            byte[] pkSigBytes = signaturePk.GetIxiBytes();
            byte[] sigBytes = signature.GetIxiBytes();

            byte[] bytes = new byte[1 + nameBytes.Length + nextPkHashBytes.Length + newRecoveryHashBytes.Length + sequenceBytes.Length + pkSigBytes.Length + sigBytes.Length];

            bytes[0] = (byte)instruction;
            int offset = 1;

            Array.Copy(nameBytes, 0, bytes, offset, nameBytes.Length);
            offset += nameBytes.Length;

            Array.Copy(newRecoveryHashBytes, 0, bytes, offset, newRecoveryHashBytes.Length);
            offset += newRecoveryHashBytes.Length;

            Array.Copy(sequenceBytes, 0, bytes, offset, sequenceBytes.Length);
            offset += sequenceBytes.Length;

            Array.Copy(nextPkHashBytes, 0, bytes, offset, nextPkHashBytes.Length);
            offset += nextPkHashBytes.Length;

            Array.Copy(pkSigBytes, 0, bytes, offset, pkSigBytes.Length);
            offset += pkSigBytes.Length;

            Array.Copy(sigBytes, 0, bytes, offset, sigBytes.Length);
            offset += sigBytes.Length;

            return bytes;
        }
    }

    public class RegNameUpdateRecord : RegNameTxEntryBase
    {
        public List<RegisteredNameDataRecord> records { get; private set; }
        public ulong sequence { get; private set; }
        public RegNameUpdateRecord(byte[] name, List<RegisteredNameDataRecord> records, ulong sequence, Address nextPkHash, Address pkSig, byte[] signature)
            : base(RegNameInstruction.updateRecord, name, nextPkHash, pkSig.pubKey, signature)
        {
            this.records = records;
            this.sequence = sequence;
        }

        public RegNameUpdateRecord(byte[] bytes)
        {
            fromBytes(bytes);
        }

        private void fromBytes(byte[] bytes)
        {
            instruction = (RegNameInstruction)bytes[0];
            if (instruction != RegNameInstruction.updateRecord)
            {
                throw new Exception("Invalid instruction " + instruction + ", expecting: " + RegNameInstruction.updateRecord);
            }
            int offset = 1;

            var nameBytesAndOffset = bytes.ReadIxiBytes(offset);
            name = nameBytesAndOffset.bytes;
            offset += nameBytesAndOffset.bytesRead;

            var recordCountAndOffset = bytes.GetIxiVarUInt(offset);
            offset += recordCountAndOffset.bytesRead;
            records = new List<RegisteredNameDataRecord>();
            for (uint i = 0; i < recordCountAndOffset.num; i++)
            {
                var recordBytesAndOffset = bytes.ReadIxiBytes(offset);
                var record = new RegisteredNameDataRecord(recordBytesAndOffset.bytes, true);
                records.Add(record);
                offset += recordBytesAndOffset.bytesRead;
            }

            var sequenceLength = bytes.GetIxiVarUInt(offset);
            sequence = sequenceLength.num;
            offset += sequenceLength.bytesRead;

            var nextPkHashBytesAndOffset = bytes.ReadIxiBytes(offset);
            nextPkHash = new Address(nextPkHashBytesAndOffset.bytes);
            offset += nextPkHashBytesAndOffset.bytesRead;

            var pkSigBytesAndOffset = bytes.ReadIxiBytes(offset);
            signaturePk = pkSigBytesAndOffset.bytes;
            offset += pkSigBytesAndOffset.bytesRead;

            var sigBytesAndOffset = bytes.ReadIxiBytes(offset);
            signature = sigBytesAndOffset.bytes;
            offset += sigBytesAndOffset.bytesRead;
        }

        public byte[] toBytes()
        {
            byte[] nameBytes = name.GetIxiBytes();

            byte[] recordBytes = null;
            using (MemoryStream m = new MemoryStream(records.Count * 200))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(records.Count.GetIxiVarIntBytes());
                    foreach (var record in records)
                    {
                        writer.Write(record.toBytes(true).GetIxiBytes());
                    }
                }
                recordBytes = m.ToArray();
            }

            byte[] sequenceBytes = sequence.GetIxiVarIntBytes();

            byte[] nextPkHashBytes = nextPkHash.addressNoChecksum.GetIxiBytes();
            byte[] pkSigBytes = signaturePk.GetIxiBytes();
            byte[] sigBytes = signature.GetIxiBytes();

            byte[] bytes = new byte[1 + nameBytes.Length + recordBytes.Length + sequenceBytes.Length + nextPkHashBytes.Length + pkSigBytes.Length + sigBytes.Length];

            bytes[0] = (byte)instruction;
            int offset = 1;

            Array.Copy(nameBytes, 0, bytes, offset, nameBytes.Length);
            offset += nameBytes.Length;

            Array.Copy(recordBytes, 0, bytes, offset, recordBytes.Length);
            offset += recordBytes.Length;

            Array.Copy(sequenceBytes, 0, bytes, offset, sequenceBytes.Length);
            offset += sequenceBytes.Length;

            Array.Copy(nextPkHashBytes, 0, bytes, offset, nextPkHashBytes.Length);
            offset += nextPkHashBytes.Length;

            Array.Copy(pkSigBytes, 0, bytes, offset, pkSigBytes.Length);
            offset += pkSigBytes.Length;

            Array.Copy(sigBytes, 0, bytes, offset, sigBytes.Length);
            offset += sigBytes.Length;

            return bytes;
        }
    }

    public class RegNameToggleAllowSubnames : RegNameTxEntryBase
    {
        public bool allowSubnames { get; private set; }
        public IxiNumber fee { get; private set; }
        public Address feeRecipientAddress { get; private set; }
        public ulong sequence { get; private set; }

        public RegNameToggleAllowSubnames(byte[] name, bool allowSubnames, IxiNumber fee, Address feeRecipientAddress, ulong sequence, Address nextPkHash, Address pkSig, byte[] signature)
            : base(RegNameInstruction.toggleAllowSubnames, name, nextPkHash, pkSig.pubKey, signature)
        {
            this.allowSubnames = allowSubnames;
            this.fee = fee;
            this.feeRecipientAddress = feeRecipientAddress;
            this.sequence = sequence;
        }

        public RegNameToggleAllowSubnames(byte[] bytes)
        {
            fromBytes(bytes);
        }

        private void fromBytes(byte[] bytes)
        {
            instruction = (RegNameInstruction)bytes[0];
            if (instruction != RegNameInstruction.toggleAllowSubnames)
            {
                throw new Exception("Invalid instruction " + instruction + ", expecting: " + RegNameInstruction.updateRecord);
            }
            int offset = 1;

            var nameBytesAndOffset = bytes.ReadIxiBytes(offset);
            name = nameBytesAndOffset.bytes;
            offset += nameBytesAndOffset.bytesRead;

            allowSubnames = BitConverter.ToBoolean(bytes, offset);
            offset += 1;

            var feeBytesAndOffset = bytes.ReadIxiBytes(offset);
            fee = new IxiNumber(feeBytesAndOffset.bytes);
            offset += feeBytesAndOffset.bytesRead;

            var feeRecipientBytesAndOffset = bytes.ReadIxiBytes(offset);
            feeRecipientAddress = new Address(feeRecipientBytesAndOffset.bytes);
            offset += feeRecipientBytesAndOffset.bytesRead;

            var sequenceLength = bytes.GetIxiVarUInt(offset);
            sequence = sequenceLength.num;
            offset += sequenceLength.bytesRead;

            var nextPkHashBytesAndOffset = bytes.ReadIxiBytes(offset);
            nextPkHash = new Address(nextPkHashBytesAndOffset.bytes);
            offset += nextPkHashBytesAndOffset.bytesRead;

            var pkSigBytesAndOffset = bytes.ReadIxiBytes(offset);
            signaturePk = pkSigBytesAndOffset.bytes;
            offset += pkSigBytesAndOffset.bytesRead;

            var sigBytesAndOffset = bytes.ReadIxiBytes(offset);
            signature = sigBytesAndOffset.bytes;
            offset += sigBytesAndOffset.bytesRead;
        }

        public byte[] toBytes()
        {
            byte[] nameBytes = name.GetIxiBytes();

            byte[] feeBytes = fee.getBytes().GetIxiBytes();
            byte[] feeRecipientAddressBytes = IxiUtils.GetIxiBytes(feeRecipientAddress.addressNoChecksum);
            byte[] sequenceBytes = sequence.GetIxiVarIntBytes();

            byte[] nextPkHashBytes = nextPkHash.addressNoChecksum.GetIxiBytes();
            byte[] pkSigBytes = signaturePk.GetIxiBytes();
            byte[] sigBytes = signature.GetIxiBytes();

            byte[] bytes = new byte[1 + nameBytes.Length + 1 + feeBytes.Length + feeRecipientAddressBytes.Length + sequenceBytes.Length + nextPkHashBytes.Length + pkSigBytes.Length + sigBytes.Length];

            bytes[0] = (byte)instruction;
            int offset = 1;

            Array.Copy(nameBytes, 0, bytes, offset, nameBytes.Length);
            offset += nameBytes.Length;

            Array.Copy(BitConverter.GetBytes(allowSubnames), 0, bytes, offset, 1);
            offset += 1;

            Array.Copy(feeBytes, 0, bytes, offset, feeBytes.Length);
            offset += feeBytes.Length;

            Array.Copy(feeRecipientAddressBytes, 0, bytes, offset, feeRecipientAddressBytes.Length);
            offset += feeRecipientAddressBytes.Length;

            Array.Copy(sequenceBytes, 0, bytes, offset, sequenceBytes.Length);
            offset += sequenceBytes.Length;

            Array.Copy(nextPkHashBytes, 0, bytes, offset, nextPkHashBytes.Length);
            offset += nextPkHashBytes.Length;

            Array.Copy(pkSigBytes, 0, bytes, offset, pkSigBytes.Length);
            offset += pkSigBytes.Length;

            Array.Copy(sigBytes, 0, bytes, offset, sigBytes.Length);
            offset += sigBytes.Length;

            return bytes;
        }
    }
}
