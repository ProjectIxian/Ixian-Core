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

using DLT;
using IXICore.Meta;
using IXICore.Utils;
using System;
using System.IO;
using System.Numerics;
using System.Runtime.InteropServices;

namespace IXICore
{
    public class SignerPowSolution
    {
        public static ulong maxDifficulty = 0x2C00000000000000;
        [ThreadStatic] private static byte[] dummyExpandedNonce = null;

        public int version = 1;
        public ulong blockNum;
        public byte[] solution;
        public byte[] signature;
        public byte[] checksum; // checksum is not trasmitted over the network
        public ulong difficulty; // difficulty is not transmitted over the network

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

                        blockNum = reader.ReadUInt64();

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

        public byte[] getBytes(bool includeSig)
        {
            using (MemoryStream m = new MemoryStream(640))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.WriteIxiVarInt(version);

                    writer.Write(blockNum);

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
            if (signature != null)
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
        public static byte[] targetToHash(ulong target, int hashLength = 44)
        {
            byte[] targetBytes = BitConverter.GetBytes(target);
            int targetLen = targetBytes[0];
            if (targetLen < 7)
            {
                throw new Exception("Difficulty length is smaller than 7 bytes.");
            }
            byte[] hash = new byte[hashLength];
            Array.Copy(targetBytes, 1, hash, hashLength - targetLen, 7);
            return hash;
        }

        public static ulong hashToTarget(byte[] hashBytes)
        {
            int len = hashBytes.Length;
            int i;
            for (i = 0; i < len - 7; i++)
            {
                if (hashBytes[i] != 0)
                {
                    break;
                }
            }
            if (i == len)
            {
                return 0;
            }
            byte[] targetBytes = new byte[8];
            for(int j = 0; j < 7; j++)
            {
                targetBytes[j] = hashBytes[i + 7 - j];
                Array.Copy(hashBytes, i, targetBytes, 1, 7);
            }
            targetBytes[7] = (byte)(len - i);
            return BitConverter.ToUInt64(targetBytes, 0);
        }

        public static byte[] difficultyToHash(ulong difficulty)
        {
            return  targetToHash(maxDifficulty / difficulty);
        }

        public static ulong hashToDifficulty(byte[] hashBytes)
        {
            return maxDifficulty * hashToTarget(hashBytes);
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
            if (nonce == null || nonce.Length < 1 || nonce.Length > 128)
            {
                return false;
            }

            // TODO protect against spamming with invalid nonce/block_num
            byte[] p1 = new byte[blockHash.Length + solverAddress.Length];
            System.Buffer.BlockCopy(blockHash, 0, p1, 0, blockHash.Length);
            System.Buffer.BlockCopy(solverAddress, 0, p1, blockHash.Length, solverAddress.Length);

            byte[] fullnonce = expandNonce(nonce, 234234);
            byte[] hash = getArgon2idHash(p1, fullnonce);

            if (validateHash(hash, difficulty) == true)
            {
                // Hash is valid
                return true;
            }

            return false;
        }

        public static byte[] getArgon2idHash(byte[] data, byte[] salt)
        {
            try
            {
                byte[] hash = new byte[32];
                IntPtr data_ptr = Marshal.AllocHGlobal(data.Length);
                IntPtr salt_ptr = Marshal.AllocHGlobal(salt.Length);
                Marshal.Copy(data, 0, data_ptr, data.Length);
                Marshal.Copy(salt, 0, salt_ptr, salt.Length);
                UIntPtr data_len = (UIntPtr)data.Length;
                UIntPtr salt_len = (UIntPtr)salt.Length;
                IntPtr result_ptr = Marshal.AllocHGlobal(32);
                int result = NativeMethods.argon2id_hash_raw((UInt32)2, (UInt32)2048, (UInt32)2, data_ptr, data_len, salt_ptr, salt_len, result_ptr, (UIntPtr)32);
                Marshal.Copy(result_ptr, hash, 0, 32);
                Marshal.FreeHGlobal(data_ptr);
                Marshal.FreeHGlobal(result_ptr);
                Marshal.FreeHGlobal(salt_ptr);
                return hash;
            }
            catch (Exception e)
            {
                Logging.error("Error during presence list mining: {0}", e.Message);
                return null;
            }
        }
    }
}
