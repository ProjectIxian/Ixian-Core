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

namespace IXICore
{
    public class SignerPowSolution
    {
        public ulong blockNum;
        public byte[] solution;

        private byte[] solverAddress = null; // solverAddress is not trasmitted over the network
        private byte[] _checksum = null;
        public byte[] checksum { get {
                if(_checksum == null)
                {
                    var targetHeader = IxianHandler.getBlockHeader(blockNum);
                    _checksum = nonceToHash(solution, targetHeader.blockChecksum, solverAddress);
                }
                return _checksum;
            } } // checksum is not trasmitted over the network

        private ulong _difficulty = 0;
        public ulong difficulty { get
            {
                if(_difficulty == 0)
                {
                    _difficulty = hashToDifficulty(checksum);
                }
                return _difficulty;
            } }  // difficulty is not transmitted over the network

        public SignerPowSolution(byte[] solverAddress)
        {
            this.solverAddress = solverAddress;
        }

        public SignerPowSolution(SignerPowSolution src)
        {
            blockNum = src.blockNum;

            solution = new byte[src.solution.Length];
            Array.Copy(src.solution, solution, solution.Length);

            solverAddress = new byte[src.solverAddress.Length];
            Array.Copy(src.solverAddress, solverAddress, solverAddress.Length);
        }

        public SignerPowSolution(byte[] bytes, byte[] solverAddress)
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
            byte[] nonceData = new byte[blockHash.Length + solverAddress.Length + nonce.Length];
            System.Buffer.BlockCopy(blockHash, 0, nonceData, 0, blockHash.Length);
            System.Buffer.BlockCopy(solverAddress, 0, nonceData, blockHash.Length, solverAddress.Length);
            System.Buffer.BlockCopy(nonce, 0, nonceData, blockHash.Length + solverAddress.Length, nonce.Length);

            return Crypto.sha512sq(nonceData, 0, 0);
        }
    }
}
