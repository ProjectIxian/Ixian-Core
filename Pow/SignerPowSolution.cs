// Copyright (C) Ixian OU
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

using IXICore.Meta;
using IXICore.Utils;
using System;
using System.IO;
using System.Runtime.InteropServices;

namespace IXICore
{
    public class SignerPowSolution
    {
        [ThreadStatic] private static byte[] dummyExpandedNonce = null;

        public int version = 1;
        public ulong blockNum;
        public byte[] solution;
        public byte[] signature;
        public byte[] checksum; // checksum is not trasmitted over the network
        public ulong difficulty; // difficulty is not transmitted over the network

        public SignerPowSolution()
        {

        }

        public SignerPowSolution(SignerPowSolution src)
        {
            version = src.version;
            blockNum = src.blockNum;

            solution = new byte[src.solution.Length];
            Array.Copy(src.solution, solution, solution.Length);

            signature = new byte[src.signature.Length];
            Array.Copy(src.signature, signature, signature.Length);

            checksum = new byte[src.checksum.Length];
            Array.Copy(src.checksum, checksum, checksum.Length);

            difficulty = src.difficulty;
        }

        public SignerPowSolution(byte[] bytes)
        {
            try
            {
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        version = (int)reader.ReadIxiVarInt();

                        blockNum = reader.ReadIxiVarUInt();

                        int solutionLen = (int)reader.ReadIxiVarUInt();
                        solution = reader.ReadBytes(solutionLen);

                        if (m.Position < m.Length)
                        {
                            int sigLen = (int)reader.ReadIxiVarUInt();
                            signature = reader.ReadBytes(sigLen);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Logging.warn("Cannot create PoW Solution from bytes: {0}", e.ToString());
                throw;
            }
        }
        // TODO Omega a blockHash should be included so that clients can verify PoW
        public byte[] getBytes(bool includeSig)
        {
            using (MemoryStream m = new MemoryStream(640))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.WriteIxiVarInt(version);

                    writer.WriteIxiVarInt(blockNum);

                    writer.WriteIxiVarInt(solution.Length);
                    writer.Write(solution);

                    if(includeSig)
                    {
                        writer.WriteIxiVarInt(signature.Length);
                        writer.Write(signature);
                    }

#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("SignerPowSolution::getBytes: {0}", m.Length));
#endif
                }

                return m.ToArray();
            }
        }


        public void calculateChecksum()
        {
            if (checksum != null)
            {
                return;
            }

            checksum = Crypto.sha512sqTrunc(getBytes(false));
        }

        public void sign(byte[] privateKey)
        {
            if(signature != null)
            {
                return;
            }
            calculateChecksum();

            signature = CryptoManager.lib.getSignature(checksum, privateKey);
        }

        public bool verifySignature(byte[] pubKey)
        {
            if (signature == null)
            {
                return false;
            }
            calculateChecksum();
            // Verify the signature
            if (CryptoManager.lib.verifySignature(checksum, pubKey, signature) == false)
            {
                return false;
            }
            return true;
        }


        // Expand a provided nonce up to expand_length bytes by repeating the provided nonce
        public static byte[] expandNonce(byte[] nonce, int expandLength)
        {
            if (dummyExpandedNonce == null)
            {
                dummyExpandedNonce = new byte[expandLength];
            }

            int nonceLength = nonce.Length;
            int dummyExpandedNonceLength = dummyExpandedNonce.Length;

            // set dummy with nonce
            for (int i = 0; i < dummyExpandedNonceLength; i++)
            {
                dummyExpandedNonce[i] = nonce[i % nonceLength];
            }

            return dummyExpandedNonce;
        }


        // block hash = 44 bytes
        // FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF
        // difficulty 8 bytes - first byte number of bytes, other 7 bytes should contain MSB
        public static byte[] difficultyToHash(ulong target, int hashLength = 44)
        {
            byte[] targetBytes = BitConverter.GetBytes(target);
            int targetLen = targetBytes[7];
            byte[] hash = new byte[hashLength];
            for (int i = 0; i < 7; i++)
            {
                hash[targetLen + i] = targetBytes[6 - i];
            }
            return hash;
        }

        public static ulong hashToDifficulty(byte[] hashBytes)
        {
            int len = hashBytes.Length;
            int i = 0;
            while (i < len - 7)
            {
                if (hashBytes[i] != 0)
                {
                    break;
                }
                i++;
            }
            byte[] targetBytes = new byte[8];
            for(int j = 0; j < 7; j++)
            {
                targetBytes[6 - j] = hashBytes[i + j];
            }
            targetBytes[7] = (byte)(i);
            return BitConverter.ToUInt64(targetBytes, 0);
        }

        public static bool validateHash(byte[] hash, ulong expectedDifficulty)
        {
            if(hashToDifficulty(hash) >= expectedDifficulty)
            {
                return true;
            }
            return false;
        }

        // Verify nonce
        public static bool verifyNonce(byte[] nonce, byte[] blockHash, byte[] solverAddress, ulong difficulty)
        {
            byte[] hash = nonceToHash(nonce, blockHash, solverAddress);
            if(hash == null)
            {
                return false;
            }

            if (validateHash(hash, difficulty) == true)
            {
                // Hash is valid
                return true;
            }

            return false;
        }

        public static byte[] nonceToHash(byte[] nonce, byte[] blockHash, byte[] solverAddress)
        {
            if (nonce == null || nonce.Length < 1 || nonce.Length > 128)
            {
                return null;
            }

            // TODO protect against spamming with invalid nonce/block_num
            byte[] p1 = new byte[blockHash.Length + solverAddress.Length];
            System.Buffer.BlockCopy(blockHash, 0, p1, 0, blockHash.Length);
            System.Buffer.BlockCopy(solverAddress, 0, p1, blockHash.Length, solverAddress.Length);

            byte[] fullnonce = expandNonce(nonce, 234234);
            byte[] hash = Argon2id.getHash(p1, fullnonce, 2, 2048, 2);

            return hash;
        }

        
    }
}
