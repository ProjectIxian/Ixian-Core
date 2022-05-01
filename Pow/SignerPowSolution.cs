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
        public static readonly ulong maxTargetBits = 0x39FFFFFFFFFFFFFF; // Highest possible value for target bits with 64 byte hashes -> lowest difficulty
        private static readonly IxiNumber maxTargetHash = new IxiNumber(Crypto.stringToHash("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000FFFFFFFFFFFFFF00"));

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

        private IxiNumber _difficulty = 0;
        public IxiNumber difficulty
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


        public static byte[] bitsToHash(ulong bits)
        {
            if (bits > maxTargetBits)
            {
                throw new ArgumentOutOfRangeException(String.Format("bits can't be higher than minTargetBits: {0} < {1}", bits, maxTargetBits));
            }
            byte[] targetBytes = BitConverter.GetBytes(bits);
            int firstPos = targetBytes[7];

            byte[] hash = new byte[firstPos + 8];
            Array.Copy(targetBytes, 0, hash, firstPos, 7);
            return hash;
        }

        public static ulong hashToBits(byte[] hashBytes)
        {
            int len = hashBytes.Length;
            if (len < 8)
            {
                byte[] tmpHash = new byte[8];
                Array.Copy(hashBytes, tmpHash, len);
                hashBytes = tmpHash;
                len = tmpHash.Length;
            }

            int zeroes = 0;
            while (zeroes < len - 7)
            {
                if (hashBytes[len - 1 - zeroes] != 0)
                {
                    break;
                }
                zeroes++;
            }
            int firstPos = len - zeroes - 7;

            byte[] targetBytes = new byte[8];
            Array.Copy(hashBytes, firstPos, targetBytes, 0, 7);
            targetBytes[7] = (byte)firstPos;

            return BitConverter.ToUInt64(targetBytes, 0);
        }

        // Returns hash in Little Endian
        public static byte[] difficultyToHash(IxiNumber difficulty)
        {
            if (difficulty < 0)
            {
                throw new ArgumentOutOfRangeException(String.Format("Difficulty can't be negative: {0}", difficulty));
            }
            if (difficulty.getAmount() < 1)
            {
                difficulty = new IxiNumber(new System.Numerics.BigInteger(1));
            }
            IxiNumber biHash = maxTargetHash / difficulty;
            return biHash.getBytes();
        }

        // Accepts hash in little endian
        public static IxiNumber hashToDifficulty(byte[] hashBytes)
        {
            IxiNumber biHashBytes = new IxiNumber(hashBytes);
            if (biHashBytes < 0)
            {
                return 0;
            }
            if (biHashBytes > maxTargetHash)
            {
                throw new OverflowException("Hash too large");
            }
            IxiNumber difficulty = maxTargetHash / biHashBytes;
            return difficulty;
        }

        public static ulong difficultyToBits(IxiNumber difficulty)
        {
            return hashToBits(difficultyToHash(difficulty));
        }

        public static IxiNumber bitsToDifficulty(ulong bits)
        {
            byte[] hash = bitsToHash(bits);
            return hashToDifficulty(hash);
        }

        public bool verifySolution(IxiNumber minimumDifficulty)
        {
            if(difficulty >= minimumDifficulty)
            {
                return true;
            }
            return false;
        }

        public static bool validateHash(byte[] hash, IxiNumber minimumDifficulty)
        {
            if(hashToDifficulty(hash) >= minimumDifficulty)
            {
                return true;
            }
            return false;
        }

        // Verify nonce
        public static bool verifySolution(byte[] solution, ulong blockNum, byte[] blockHash, Address solverAddress, IxiNumber difficulty)
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
