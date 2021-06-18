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
        // the value below is the easiest way to get maximum hash value into a BigInteger (2^256 -1). Ixian shifts the integer 8 places to the right to get 8 decimal places.
        static BigInteger maxHashValue = new IxiNumber("1157920892373161954235709850086879078532699846656405640394575840079131.29639935").getAmount();
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

        public ulong calculateDifficulty(byte[] blockChecksum, byte[] solverAddress)
        {
            if(difficulty > 0)
            {
                return difficulty;
            }

            byte[] challenge = new byte[blockChecksum.Length + solverAddress.Length];
            System.Buffer.BlockCopy(blockChecksum, 0, challenge, 0, blockChecksum.Length);
            System.Buffer.BlockCopy(solverAddress, 0, challenge, blockChecksum.Length, solverAddress.Length);
            byte[] hash = getArgon2idHash(challenge, solution);
            
            difficulty = get

            return difficulty;
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

        public static byte[] getHashCeilFromDifficulty(ulong difficulty)
        {
            /*
             * difficulty is an 8-byte number from 0 to 2^64-1, which represents how hard it is to find a hash for a certain block
             * the dificulty is converted into a 'ceiling value', which specifies the maximum value a hash can have to be considered valid under that difficulty
             * to do this, follow the attached algorithm:
             *  1. calculate a bit-inverse value of the difficulty
             *  2. create a comparison byte array with the ceiling value of length 10 bytes
             *  3. set the first two bytes to zero
             *  4. insert the inverse difficulty as the next 8 bytes (mind the byte order!)
             *  5. the remaining 22 bytes are assumed to be 'FF'
             */
            byte[] hash_ceil = new byte[10];
            hash_ceil[0] = 0x00;
            hash_ceil[1] = 0x00;
            for (int i = 0; i < 8; i++)
            {
                int shift = 8 * (7 - i);
                ulong mask = ((ulong)0xff) << shift;
                byte cb = (byte)((difficulty & mask) >> shift);
                hash_ceil[i + 2] = (byte)~cb;
            }
            return hash_ceil;
        }

        public static BigInteger getTargetHashcount(ulong difficulty)
        {
            // For difficulty calculations see accompanying TXT document in the IxianDLT folder.
            // I am sorry for this - Zagar
            // What it does:
            // internally (in Miner.cs), we use little-endian byte arrays to represent hashes and solution ceilings, because it is slightly more efficient memory-allocation-wise.
            // in this place, we are using BigInteger's division function, so we don't have to write our own.
            // BigInteger uses a big-endian byte-array, so we have to reverse our ceiling, which looks like this:
            // little endian: 0000 XXXX XXXX XXXX XXXX FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF ; X represents where we set the difficulty
            // big endian: FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF YYYY YYYY YYYY YYYY 0000 ; Y represents the difficulty, but the bytes are reversed
            // 9 -(i-22) transforms the index in the big-endian byte array into an index in our 'hash_ceil'. Please also note that due to effciency we only return the
            // "interesting part" of the hash_ceil (first 10 bytes) and assume the others to be FF when doing comparisons internally. The first part of the 'if' in the loop
            // fills in those bytes as well, because BigInteger needs them to reconstruct the number.
            byte[] hash_ceil = getHashCeilFromDifficulty(difficulty);
            byte[] full_ceil = new byte[32];
            // BigInteger requires bytes in big-endian order
            for (int i = 0; i < 32; i++)
            {
                if (i < 22)
                {
                    full_ceil[i] = 0xff;
                }
                else
                {
                    full_ceil[i] = hash_ceil[9 - (i - 22)];
                }
            }

            BigInteger ceil = new BigInteger(full_ceil);
            return maxHashValue / ceil;
        }

        public static ulong calculateTargetDifficulty(BigInteger current_hashes_per_block)
        {
            // Sorry :-)
            // Target difficulty is calculated as such:
            // We input the number of hashes that have been generated to solve a block (Network hash rate * 60 - we want that solving a block should take 60 seconds, if the entire network hash power was focused on one block, thus achieving
            // an approximate 50% solve rate).
            // We are using BigInteger for its division function, so that we don't have to write out own.
            // Dividing the max hash number with the hashrate will give us an appropriate ceiling, which would result in approximately one solution per "current_hashes_per_block" hash attempts.
            // This target ceiling contains our target difficulty, in the format:
            // big endian: FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF YYYY YYYY YYYY YYYY 0000; Y represents the difficulty, but the bytes are reversed
            // the bytes being reversed is actually okay, because we are using BitConverter.ToUInt64, which takes a big-endian byte array to return a ulong number.
            if (current_hashes_per_block == 0)
            {
                current_hashes_per_block = 1000; // avoid divide by zero
            }
            BigInteger target_ceil = maxHashValue / current_hashes_per_block;
            byte[] temp = target_ceil.ToByteArray();
            int temp_len = temp.Length;
            if (temp_len > 32)
            {
                temp_len = 32;
            }
            // we get the bytes in the reverse order, so the padding should go at the end
            byte[] target_ceil_bytes = new byte[32];
            Array.Copy(temp, target_ceil_bytes, temp_len);
            for (int i = temp_len; i < 32; i++)
            {
                target_ceil_bytes[i] = 0;
            }
            //
            byte[] difficulty = new byte[8];
            Array.Copy(target_ceil_bytes, 22, difficulty, 0, 8);
            for (int i = 0; i < 8; i++)
            {
                difficulty[i] = (byte)~difficulty[i];
            }
            return BitConverter.ToUInt64(difficulty, 0);
        }

        public static bool validateHash(byte[] hash, byte[] hashCeil)
        {
            int hashLength = hash.Length;
            int hashCeilLength = hashCeil.Length;
            if (hash == null || hashLength < 32)
            {
                return false;
            }
            for (int i = 0; i < hashLength; i++)
            {
                byte cb = i < hashCeilLength ? hashCeil[i] : (byte)0xff;
                if (cb > hash[i]) return true;
                if (cb < hash[i]) return false;
            }
            // if we reach this point, the hash is exactly equal to the ceiling we consider this a 'passing hash'
            return true;
        }

        public static bool validateHash(byte[] hash, ulong difficulty)
        {
            return validateHash(hash, getHashCeilFromDifficulty(difficulty));
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
