﻿// Copyright (C) 2017-2024 Ixian OU
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

using IXICore.Meta;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace IXICore.RegNames
{
    public static class IxiNameUtils
    {
        public static byte[] encodeAndHashIxiName(string name)
        {
            // Check if name is valid; throws an exception if not
            IdnMapping idn = new IdnMapping();
            name = idn.GetAscii(name.ToLower());

            // Split names by '.' and reverse order, so that top domain is first
            var splitNames = name.Split('.').Reverse();
            using (MemoryStream m = new MemoryStream(65 * splitNames.Count()))
            {
                using (BinaryWriter bw = new BinaryWriter(m))
                {
                    foreach (var nameSection in splitNames)
                    {
                        byte[] nameSectionBytes = UTF8Encoding.UTF8.GetBytes(nameSection);
                        byte[] nameSectionWithPrefixBytes = new byte[ConsensusConfig.ixianChecksumLock.Length + nameSectionBytes.Length];
                        Array.Copy(ConsensusConfig.ixianChecksumLock, 0, nameSectionWithPrefixBytes, 0, ConsensusConfig.ixianChecksumLock.Length);
                        Array.Copy(nameSectionBytes, 0, nameSectionWithPrefixBytes, ConsensusConfig.ixianChecksumLock.Length, nameSectionBytes.Length);

                        // double SHA-3 512 hash
                        byte[] hashedNameSectionBytes = CryptoManager.lib.sha3_512sq(nameSectionWithPrefixBytes);
                        bw.Write(hashedNameSectionBytes.GetIxiBytes());
                    }
                }
                return m.ToArray();
            }
        }

        public static byte[] hashIxiNameRecordKey(byte[] encodedName, byte[] encodedRecordKey)
        {
            byte[] nameAndKeyBytes = new byte[encodedName.Length + encodedRecordKey.Length];
            Array.Copy(encodedName, 0, nameAndKeyBytes, 0, encodedName.Length);
            Array.Copy(encodedRecordKey, 0, nameAndKeyBytes, encodedName.Length, encodedRecordKey.Length);

            // double SHA-3 512 hash
            return CryptoManager.lib.sha3_512sq(nameAndKeyBytes);
        }

        public static byte[] encodeAndHashIxiNameRecordKey(byte[] encodedName, string recordKey)
        {
            return hashIxiNameRecordKey(encodedName, encodeAndHashIxiName(recordKey));
        }

        public static List<byte[]> splitIxiNameBytes(byte[] id)
        {
            List<byte[]> splitName = new();

            int offset = 0;
            while (offset < id.Length)
            {
                var nameWithBytesRead = id.ReadIxiBytes(offset);
                if (nameWithBytesRead.bytes == null)
                {
                    throw new Exception("Name section is null.");
                }
                splitName.Add(nameWithBytesRead.bytes.GetIxiBytes());
                offset += nameWithBytesRead.bytesRead;
            }

            return splitName;
        }

        public static byte[] buildEncryptionKey(byte[] unhashedNameBytes, byte[] unhashedRecordKey)
        {
            byte[] key = new byte[unhashedNameBytes.Length + unhashedRecordKey.Length];
            Array.Copy(unhashedNameBytes, 0, key, 0, unhashedNameBytes.Length);
            Array.Copy(unhashedRecordKey, 0, key, unhashedNameBytes.Length, unhashedRecordKey.Length);
            key = CryptoManager.lib.sha3_512sqTrunc(key, 0, 0, 16);
            return key;
        }

        public static byte[] encryptRecord(byte[] unhashedNameBytes, byte[] unhashedRecordKey, byte[] recordData)
        {
            byte[] key = buildEncryptionKey(unhashedNameBytes, unhashedRecordKey);
            return CryptoManager.lib.encryptWithAES(recordData, key, true);
        }

        public static byte[] decryptRecord(byte[] unhashedNameBytes, byte[] unhashedRecordKey, byte[] recordData)
        {
            byte[] key = buildEncryptionKey(unhashedNameBytes, unhashedRecordKey);
            return CryptoManager.lib.decryptWithAES(recordData, key, true);
        }

        public static RegNameTxEntryBase decodeNameData(byte[] txOutData)
        {
            RegNameInstruction rni = (RegNameInstruction)txOutData[0];
            switch (rni)
            {
                case RegNameInstruction.register:
                    RegNameRegister rnReg = new RegNameRegister(txOutData);
                    return rnReg;
                case RegNameInstruction.extend:
                    RegNameExtend rnExt = new RegNameExtend(txOutData);
                    return rnExt;
                case RegNameInstruction.recover:
                    RegNameRecover rnRec = new RegNameRecover(txOutData);
                    return rnRec;
                case RegNameInstruction.changeCapacity:
                    RegNameChangeCapacity rnCap = new RegNameChangeCapacity(txOutData);
                    return rnCap;
                case RegNameInstruction.toggleAllowSubnames:
                    RegNameToggleAllowSubnames rnSub = new RegNameToggleAllowSubnames(txOutData);
                    return rnSub;
                case RegNameInstruction.updateRecord:
                    RegNameUpdateRecord rnUpd;
                    try
                    {
                        rnUpd = new RegNameUpdateRecord(txOutData);
                    }
                    catch (Exception e)
                    {
                        Logging.error("Exception occured while parsing RegName data: {0}", e);
                        return null;
                    }
                    return rnUpd;
            }
            return null;
        }
    }
}
