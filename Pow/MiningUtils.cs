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

using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace IXICore
{
    class MiningUtils
    {
        // The value below is the easiest way to get maximum hash value into a BigInteger (2^256 -1).
        // Ixian shifts the integer 8 places to the right to get 8 decimal places.
        static BigInteger maxHashValue = new IxiNumber("1157920892373161954235709850086879078532699846656405640394575840079131.29639935").getAmount();

        public static byte[] getHashCeilFromDifficulty(ulong difficulty)
        {
            // Difficulty is an 8-byte number from 0 to 2^64-1, which represents how hard it is to find a hash for a certain block
            // the dificulty is converted into a 'ceiling value', which specifies the maximum value a hash can have to be considered valid under that difficulty
            // to do this, follow the attached algorithm:
            //  1. calculate a bit-inverse value of the difficulty
            //  2. create a comparison byte array with the ceiling value of length 10 bytes
            //  3. set the first two bytes to zero
            //  4. insert the inverse difficulty as the next 8 bytes (mind the byte order!)
            //  5. the remaining 22 bytes are assumed to be 'FF'

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

        public static BigInteger getTargetHashcountPerBlock(ulong difficulty)
        {
            // We use little-endian byte arrays to represent hashes and solution ceilings, because it is slightly more efficient memory-allocation-wise.
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

            // Get the bytes in the reverse order, so the padding should go at the end
            byte[] target_ceil_bytes = new byte[32];
            Array.Copy(temp, target_ceil_bytes, temp_len);
            for (int i = temp_len; i < 32; i++)
            {
                target_ceil_bytes[i] = 0;
            }

            byte[] difficulty = new byte[8];
            Array.Copy(target_ceil_bytes, 22, difficulty, 0, 8);
            for (int i = 0; i < 8; i++)
            {
                difficulty[i] = (byte)~difficulty[i];
            }

            return BitConverter.ToUInt64(difficulty, 0);
        }

    }
}
