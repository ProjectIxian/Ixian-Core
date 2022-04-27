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
using System.Numerics;

namespace IXICore
{
    public class SignerPowSolution
    {
        public static readonly ulong minTargetBits = 0x0200000000000000;
        public static readonly ulong maxTargetBits = 0x39FFFFFFFFFFFFFE;

        private static readonly BigInteger minDifficultyTarget = new BigInteger(Crypto.stringToHash("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000"));

        public ulong blockNum;
        public byte[] solution;

        private Address solverAddress = null; // solverAddress is not trasmitted over the network
        private byte[] _checksum = null;
        public byte[] checksum { get {
                if(_checksum == null)
                {
                    var targetHeader = IxianHandler.getBlockHeader(blockNum);
                    _checksum = solutionToHash(solution, blockNum, targetHeader.blockChecksum, solverAddress);
                }
                return _checksum;
            } } // checksum is not trasmitted over the network

        private BigInteger _difficulty = 0;
        public BigInteger difficulty
        {
            get
            {
                if (_difficulty == 0)
                {
                    _difficulty = hashToDifficulty(checksum);
                }
                return _difficulty;
            }
        }  // difficulty is not transmitted over the network

        private ulong _bits = 0;
        public ulong bits
        {
            get
            {
                if (_bits == 0)
                {
                    _bits = hashToBits(checksum);
                }
                return _bits;
            }
        }  // bits are not transmitted over the network

        public SignerPowSolution(Address solverAddress)
        {
            this.solverAddress = solverAddress;
        }

        public SignerPowSolution(SignerPowSolution src)
        {
            blockNum = src.blockNum;

            solution = new byte[src.solution.Length];
            Array.Copy(src.solution, solution, solution.Length);

            byte[] solverAddressBytes = new byte[src.solverAddress.addressNoChecksum.Length];
            Array.Copy(src.solverAddress.addressNoChecksum, solverAddressBytes, solverAddressBytes.Length);
            solverAddress = new Address(solverAddressBytes);
        }

        public SignerPowSolution(byte[] bytes, Address solverAddress)
        {
            try
            {
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        blockNum = reader.ReadIxiVarUInt();

                        int solutionLen = (int)reader.ReadIxiVarUInt();
                        solution = reader.ReadBytes(solutionLen);

                        this.solverAddress = solverAddress;
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
        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream(640))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.WriteIxiVarInt(blockNum);

                    writer.WriteIxiVarInt(solution.Length);
                    writer.Write(solution);

#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("SignerPowSolution::getBytes: {0}", m.Length));
#endif
                }

                return m.ToArray();
            }
        }


        public static byte[] bitsToHash(ulong bits, int hashLength = 64)
        {
            if (bits < minTargetBits)
            {
                throw new ArgumentOutOfRangeException(String.Format("bits can't be lower than minTargetBits: {0} < {1}", bits, minTargetBits));
            }
            if (bits > maxTargetBits)
            {
                throw new ArgumentOutOfRangeException(String.Format("bits can't be higher than maxTargetBits: {0} < {1}", bits, maxTargetBits));
            }
            byte[] targetBytes = BitConverter.GetBytes(bits);
            int firstZeroPos = hashLength - targetBytes[7];
            byte[] hash = new byte[hashLength];
            for(int i = 0; i < firstZeroPos; i++)
            {
                hash[i] = 0xFF;
            }
            hash[firstZeroPos - 7] = (byte)(0xFF - targetBytes[0]);
            hash[firstZeroPos - 6] = (byte)(0xFF - targetBytes[1]);
            hash[firstZeroPos - 5] = (byte)(0xFF - targetBytes[2]);
            hash[firstZeroPos - 4] = (byte)(0xFF - targetBytes[3]);
            hash[firstZeroPos - 3] = (byte)(0xFF - targetBytes[4]);
            hash[firstZeroPos - 2] = (byte)(0xFF - targetBytes[5]);
            hash[firstZeroPos - 1] = (byte)(0xFF - targetBytes[6]);
            return hash;
        }

        public static ulong hashToBits(byte[] hashBytes, int hashLength = 64)
        {
            int len = hashBytes.Length;
            int zeroes = 0;
            while (zeroes < len - 7)
            {
                if (hashBytes[len - 1 - zeroes] != 0)
                {
                    break;
                }
                zeroes++;
            }
            int firstZeroPos = len - zeroes;
            if(len < hashLength)
            {
                zeroes += hashLength - len;
            }
            byte[] targetBytes = new byte[8];
            targetBytes[0] = (byte)(0xFF - hashBytes[firstZeroPos - 7]);
            targetBytes[1] = (byte)(0xFF - hashBytes[firstZeroPos - 6]);
            targetBytes[2] = (byte)(0xFF - hashBytes[firstZeroPos - 5]);
            targetBytes[3] = (byte)(0xFF - hashBytes[firstZeroPos - 4]);
            targetBytes[4] = (byte)(0xFF - hashBytes[firstZeroPos - 3]);
            targetBytes[5] = (byte)(0xFF - hashBytes[firstZeroPos - 2]);
            targetBytes[6] = (byte)(0xFF - hashBytes[firstZeroPos - 1]);
            targetBytes[7] = (byte)zeroes;
            return BitConverter.ToUInt64(targetBytes, 0);
        }

        // Returns hash in Little Endian
        public static byte[] difficultyToHash(BigInteger difficulty, int hashLength = 64)
        {
            if (difficulty < 0)
            {
                throw new ArgumentOutOfRangeException(String.Format("Difficulty can't be negative: {0}", difficulty));
            }
            if (difficulty < 1)
            {
                difficulty = 1;
            }
            BigInteger biHash = minDifficultyTarget / difficulty;
            return biHash.ToByteArray();
        }

        // Accepts hash in little endian
        public static BigInteger hashToDifficulty(byte[] hashBytes, int hashLength = 64)
        {
            if (hashBytes.Length > hashLength)
            {
                throw new OverflowException(String.Format("Hash can't have more than {0} bytes", hashLength));
            }
            BigInteger biHashBytes = new BigInteger(hashBytes);
            if (biHashBytes < 0)
            {
                return 0;
            }
            if (biHashBytes > minDifficultyTarget)
            {
                throw new OverflowException("Hash too large");
            }
            BigInteger difficulty = minDifficultyTarget / biHashBytes;
            return difficulty;
        }

        public static ulong difficultyToBits(BigInteger difficulty, int hashLength = 64)
        {
            return hashToBits(difficultyToHash(difficulty, hashLength));
        }

        public static BigInteger bitsToDifficulty(ulong bits, int hashLength = 64)
        {
            byte[] hash = bitsToHash(bits, hashLength);
            return hashToDifficulty(hash);
        }

        public bool verifySolution(BigInteger minimumDifficulty)
        {
            if(difficulty >= minimumDifficulty)
            {
                return true;
            }
            return false;
        }

        public static bool validateHash(byte[] hash, BigInteger minimumDifficulty)
        {
            if(hashToDifficulty(hash) >= minimumDifficulty)
            {
                return true;
            }
            return false;
        }

        // Verify nonce
        public static bool verifySolution(byte[] solution, ulong blockNum, byte[] blockHash, Address solverAddress, BigInteger difficulty)
        {
            byte[] hash = solutionToHash(solution, blockNum, blockHash, solverAddress);
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

        public static byte[] solutionToHash(byte[] solution, ulong blockNum, byte[] blockHash, Address solverAddress)
        {
            if (solution == null || solution.Length < 1 || solution.Length > 64)
            {
                return null;
            }
            // TODO protect against spamming with invalid nonce/block_num
            byte[] blockNumBytes = blockNum.GetIxiVarIntBytes();
            byte[] challengeData = new byte[blockNumBytes.Length + blockHash.Length + solverAddress.addressNoChecksum.Length + solution.Length];

            System.Buffer.BlockCopy(blockNumBytes, 0, challengeData, 0, blockNumBytes.Length);
            System.Buffer.BlockCopy(blockHash, 0, challengeData, blockNumBytes.Length, blockHash.Length);
            System.Buffer.BlockCopy(solverAddress.addressNoChecksum, 0, challengeData, blockNumBytes.Length + blockHash.Length, solverAddress.addressNoChecksum.Length);
            System.Buffer.BlockCopy(solution, 0, challengeData, blockNumBytes.Length + blockHash.Length + solverAddress.addressNoChecksum.Length, solution.Length);

            return CryptoManager.lib.sha3_512sq(challengeData);
        }
    }
}
