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


using System.Collections.Generic;
using static IXICore.Transaction;

namespace IXICore.RegNames
{
    public class RegisteredNamesTransactions
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
    }
}
