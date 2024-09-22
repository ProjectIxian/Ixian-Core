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


using IXICore.Meta;
using System.Collections.Generic;
using System.Linq;
using static IXICore.Transaction;

namespace IXICore.RegNames
{
    public static class RegisteredNamesTransactions
    {
        public static ToEntry createRegisterToEntry(byte[] nameToRegister, uint registrationTimeInBlocks, uint capacity, Address nextPkHash, Address recoveryHash, IxiNumber fee)
        {
            RegNameRegister rnr = new RegNameRegister(nameToRegister, registrationTimeInBlocks, capacity, nextPkHash, recoveryHash);

            byte[] data = rnr.toBytes();

            var toEntry = new ToEntry(Transaction.maxVersion, fee, data);
            return toEntry;
        }

        public static ToEntry createExtendToEntry(byte[] nameToExtend, uint registrationTimeInBlocks, IxiNumber fee)
        {
            RegNameExtend rne = new RegNameExtend(nameToExtend, registrationTimeInBlocks);

            byte[] data = rne.toBytes();

            var toEntry = new ToEntry(Transaction.maxVersion, fee, data);
            return toEntry;
        }

        public static ToEntry createRecoverToEntry(byte[] nameToRecover, ulong sequence, Address nextPkHash, Address nextRecoveryHash, Address recoveryPk, byte[] recoverySig)
        {
            RegNameRecover rnr = new RegNameRecover(nameToRecover, sequence, nextPkHash, nextRecoveryHash, recoveryPk, recoverySig);

            byte[] data = rnr.toBytes();

            var toEntry = new ToEntry(Transaction.maxVersion, 0, data);
            return toEntry;
        }

        public static ToEntry createChangeCapacityToEntry(byte[] nameToChangeCapacityFor, uint newCapacity, ulong sequence, Address nextPkHash, Address sigPk, byte[] signature, IxiNumber fee)
        {
            RegNameChangeCapacity rncc = new RegNameChangeCapacity(nameToChangeCapacityFor, newCapacity, sequence, nextPkHash, sigPk, signature);

            byte[] data = rncc.toBytes();

            var toEntry = new ToEntry(Transaction.maxVersion, fee, data);
            return toEntry;
        }

        public static ToEntry createUpdateRecordToEntry(byte[] nameToUpdateEntryFor, List<RegisteredNameDataRecord> records, ulong sequence, Address nextPkHash, Address sigPk, byte[] signature)
        {
            RegNameUpdateRecord rnu = new RegNameUpdateRecord(nameToUpdateEntryFor, records, sequence, nextPkHash, sigPk, signature);

            byte[] data = rnu.toBytes();

            var toEntry = new ToEntry(Transaction.maxVersion, 0, data);
            return toEntry;
        }

        public static ToEntry createToggleAllowSubnamesToEntry(byte[] nameToToggleSubnameFor, bool allowSubnames, IxiNumber fee, Address feeRecipientAddress, ulong sequence, Address nextPkHash, Address sigPk, byte[] signature)
        {
            RegNameToggleAllowSubnames rnSub = new RegNameToggleAllowSubnames(nameToToggleSubnameFor, allowSubnames, fee, feeRecipientAddress, sequence, nextPkHash, sigPk, signature);

            byte[] data = rnSub.toBytes();

            var toEntry = new ToEntry(Transaction.maxVersion, 0, data);
            return toEntry;
        }

        public static List<RegisteredNameDataRecord> mergeDataRecords(byte[] id, List<RegisteredNameDataRecord> curRecords, List<RegisteredNameDataRecord> updateRecords, bool allowSubnames)
        {
            foreach (var record in updateRecords)
            {
                if (record.checksum != null) // update or delete
                {
                    var index = curRecords.FindIndex(x => x.checksum.SequenceEqual(record.checksum));
                    if (index == -1)
                    {
                        Logging.error("Cannot update/delete record, existing record with checksum {0} doesn't exist for registered name {1}.", Crypto.hashToString(record.checksum), Crypto.hashToString(id));
                        return null;
                    }

                    if (record.data == null) // delete
                    {
                        curRecords.RemoveAt(index);
                    }
                    else  // update
                    {
                        // checksum received was for a previous record, so recalculate
                        var newRecord = new RegisteredNameDataRecord(record);
                        newRecord.recalculateChecksum();

                        if (curRecords.FindIndex(x => x.checksum.SequenceEqual(newRecord.checksum)) > -1)
                        {
                            Logging.error("Cannot update record, record with checksum {0} already exists for registered name {1}.", Crypto.hashToString(newRecord.checksum), Crypto.hashToString(id));
                            return null;
                        }

                        curRecords[index] = newRecord;
                    }
                }
                else // new
                {
                    // no checksum on the record yet, so recalculate
                    var newRecord = new RegisteredNameDataRecord(record);
                    if (newRecord.data == null)
                    {
                        Logging.error("Cannot add record {0} because data is null for registered name {1}.", Crypto.hashToString(record.name), Crypto.hashToString(id));
                        return null;
                    }

                    if (allowSubnames && (newRecord.name.Length != 1 || newRecord.name[0] != '@'))
                    {
                        Logging.error("Cannot add record {0} because data is null for registered name {1}.", Crypto.hashToString(record.name), Crypto.hashToString(id));
                        return null;
                    }

                    newRecord.recalculateChecksum();

                    if (curRecords.FindIndex(x => x.checksum.SequenceEqual(newRecord.checksum)) > -1)
                    {
                        Logging.error("Cannot Add record, record with checksum {0} already exists for registered name {1}.", Crypto.hashToString(newRecord.checksum), Crypto.hashToString(id));
                        return null;
                    }

                    curRecords.Add(newRecord);
                }
            }
            return curRecords;
        }

        public static IxiNumber calculateExpectedRegistrationFee(ulong extensionTimeInBlocks, uint capacity, IxiNumber pricePerUnit = null)
        {
            if (pricePerUnit == null)
            {
                pricePerUnit = ConsensusConfig.rnPricePerUnit;
            }
            return (extensionTimeInBlocks / ConsensusConfig.rnMonthInBlocks) * capacity * pricePerUnit;
        }

        public static byte[] calculateRegNameChecksumFromUpdatedDataRecords(RegisteredNameRecord regNameRecord, byte[] id, List<RegisteredNameDataRecord> dataRecords, ulong sequence, Address nextPkHash)
        {
            var rnr = regNameRecord;
            if (rnr == null)
            {
                return null;
            }

            var mergedRecords = mergeDataRecords(id, rnr.getDataRecords(null), dataRecords, rnr.allowSubnames);
            if (mergedRecords == null)
            {
                return null;
            }

            rnr.setRecords(mergedRecords, sequence, nextPkHash, null, null, 0);
            return rnr.calculateChecksum(RegNameRecordByteTypes.forSignature);
        }

        public static byte[] calculateRegNameChecksumForRecovery(RegisteredNameRecord regNameRecord, byte[] id, Address recoveryHash, ulong sequence, Address nextPkHash)
        {
            var rnr = regNameRecord;
            if (rnr == null)
            {
                return null;
            }

            rnr.setRecoveryHash(recoveryHash, sequence, nextPkHash, null, null, 0);
            return rnr.calculateChecksum(RegNameRecordByteTypes.forSignature);
        }
    }
}
