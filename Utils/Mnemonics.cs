// Copyright (C) 2017-2020 Ixian OU
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
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace IXICore.Utils
{
    public interface IRandom
    {
        void GetBytes(byte[] output);
    }


    public class RNGCryptoServiceProviderRandom : IRandom
    {
        readonly RNGCryptoServiceProvider _Instance;
        public RNGCryptoServiceProviderRandom()
        {
            _Instance = new RNGCryptoServiceProvider();
        }
        #region IRandom Members

        public void GetBytes(byte[] output)
        {
            _Instance.GetBytes(output);
        }

        #endregion
    }

    public partial class RandomUtils
    {

        static RandomUtils()
        {
            // Thread safe http://msdn.microsoft.com/en-us/library/system.security.cryptography.rngcryptoserviceprovider(v=vs.110).aspx
            Random = new RNGCryptoServiceProviderRandom();
            AddEntropy(Guid.NewGuid().ToByteArray());
        }

        public static IRandom Random
        {
            get;
            set;
        }

        public static byte[] GetBytes(int length)
        {
            byte[] data = new byte[length];
            if (Random == null)
                throw new InvalidOperationException("You must set the RNG (RandomUtils.Random) before generating random numbers");
            Random.GetBytes(data);
            PushEntropy(data);
            return data;
        }

        private static void PushEntropy(byte[] data)
        {
            if (additionalEntropy == null || data.Length == 0)
                return;
            int pos = entropyIndex;
            var entropy = additionalEntropy;
            for (int i = 0; i < data.Length; i++)
            {
                data[i] ^= entropy[pos % 32];
                pos++;
            }
            entropy = Crypto.sha512sqTrunc(data);
            for (int i = 0; i < data.Length; i++)
            {
                data[i] ^= entropy[pos % 32];
                pos++;
            }
            entropyIndex = pos % 32;
        }

        static volatile byte[] additionalEntropy = null;
        static volatile int entropyIndex = 0;

        public static void AddEntropy(string data)
        {
            if (data == null)
                throw new ArgumentNullException("data");
            AddEntropy(Encoding.UTF8.GetBytes(data));
        }

        public static void AddEntropy(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");
            var entropy = Crypto.sha512sqTrunc(data);
            if (additionalEntropy == null)
                additionalEntropy = entropy;
            else
            {
                for (int i = 0; i < 32; i++)
                {
                    additionalEntropy[i] ^= entropy[i];
                }
                additionalEntropy = Crypto.sha512sqTrunc(additionalEntropy);
            }
        }

        public static uint GetUInt32()
        {
            return BitConverter.ToUInt32(GetBytes(sizeof(uint)), 0);
        }

        public static int GetInt32()
        {
            return BitConverter.ToInt32(GetBytes(sizeof(int)), 0);
        }
        public static ulong GetUInt64()
        {
            return BitConverter.ToUInt64(GetBytes(sizeof(ulong)), 0);
        }

        public static long GetInt64()
        {
            return BitConverter.ToInt64(GetBytes(sizeof(long)), 0);
        }

        public static void GetBytes(byte[] output)
        {
            if (Random == null)
                throw new InvalidOperationException("You must set the RNG (RandomUtils.Random) before generating random numbers");
            Random.GetBytes(output);
            PushEntropy(output);
        }
    }

    /// <summary>
    /// A .NET implementation of the Bitcoin Improvement Proposal - 39 (BIP39)
    /// BIP39 specification used as reference located here: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
    /// Made by thashiznets@yahoo.com.au
    /// v1.0.1.1
    /// I ♥ Bitcoin :)
    /// Bitcoin:1ETQjMkR1NNh4jwLuN5LxY7bMsHC9PUPSV
    /// </summary>
    public class Mnemonic
    {
        public Mnemonic(string mnemonic, Wordlist wordlist = null)
        {
            if (mnemonic == null)
                throw new ArgumentNullException("mnemonic");
            _Mnemonic = mnemonic.Trim();

            if (wordlist == null)
                wordlist = Wordlist.AutoDetect(mnemonic) ?? Wordlist.English;

            var words = mnemonic.Split(new char[] { ' ', '　' }, StringSplitOptions.RemoveEmptyEntries);
            //if the sentence is not at least 12 characters or cleanly divisible by 3, it is bad!
            if (!CorrectWordCount(words.Length))
            {
                throw new FormatException("Word count should be equals to 12,15,18,21 or 24");
            }
            _Words = words;
            _WordList = wordlist;
            _Indices = wordlist.ToIndices(words);
        }

        /// <summary>
        /// Generate a mnemonic
        /// </summary>
        /// <param name="wordList"></param>
        /// <param name="entropy"></param>
        public Mnemonic(Wordlist wordList, byte[] entropy = null)
        {
            wordList = wordList ?? Wordlist.English;
            _WordList = wordList;
            if (entropy == null)
                entropy = RandomUtils.GetBytes(64);

            var i = Array.IndexOf(entArray, entropy.Length * 2);
            if (i == -1)
                throw new ArgumentException("The length for entropy should be : " + String.Join(",", entArray), "entropy");

            int cs = csArray[i];
            byte[] checksum = Crypto.sha512sqTrunc(entropy);
            BitWriter entcsResult = new BitWriter();

            entcsResult.Write(entropy);
            entcsResult.Write(checksum, cs);
            _Indices = entcsResult.ToIntegers();
            _Words = _WordList.GetWords(_Indices);
            _Mnemonic = _WordList.GetSentence(_Indices);
        }

        public Mnemonic(Wordlist wordList, WordCount wordCount)
            : this(wordList, GenerateEntropy(wordCount))
        {

        }

        private static byte[] GenerateEntropy(WordCount wordCount)
        {
            var ms = (int)wordCount;
            if (!CorrectWordCount(ms))
                throw new ArgumentException("Word count should be equal to 12,15,18,21 or 24", "wordCount");
            int i = Array.IndexOf(msArray, (int)wordCount);
            return RandomUtils.GetBytes(entArray[i] / 8);
        }

        static readonly int[] msArray = new[] { 12, 15, 18, 21, 24 };
        static readonly int[] csArray = new[] { 4, 5, 6, 7, 8 };
        static readonly int[] entArray = new[] { 128, 160, 192, 224, 256 };

        bool? _IsValidChecksum;
        public bool IsValidChecksum
        {
            get
            {
                if (_IsValidChecksum == null)
                {
                    int i = Array.IndexOf(msArray, _Indices.Length);
                    int cs = csArray[i];
                    int ent = entArray[i];

                    BitWriter writer = new BitWriter();
                    var bits = Wordlist.ToBits(_Indices);
                    writer.Write(bits, ent);
                    var entropy = writer.ToBytes();
                    var checksum = Crypto.sha512sqTrunc(entropy);

                    writer.Write(checksum, cs);
                    var expectedIndices = writer.ToIntegers();
                    _IsValidChecksum = expectedIndices.SequenceEqual(_Indices);
                }
                return _IsValidChecksum.Value;
            }
        }

        private static bool CorrectWordCount(int ms)
        {
            return msArray.Any(_ => _ == ms);
        }

        private readonly Wordlist _WordList;
        public Wordlist WordList
        {
            get
            {
                return _WordList;
            }
        }

        private readonly int[] _Indices;
        public int[] Indices
        {
            get
            {
                return _Indices;
            }
        }
        private readonly string[] _Words;
        public string[] Words
        {
            get
            {
                return _Words;
            }
        }

        internal static byte[] Normalize(string str)
        {
            return Encoding.UTF8.GetBytes(NormalizeString(str));
        }

        internal static string NormalizeString(string word)
        {
#if !NOSTRNORMALIZE
            if (IsRunningOnMono())
            {
                return KDTable.NormalizeKD(word);
            }
            else
            {
                try
                {
                    return word.Normalize(NormalizationForm.FormKD);
                }
                catch (NotImplementedException)
                {
                    return KDTable.NormalizeKD(word);
                }
            }
#else
			return KDTable.NormalizeKD(word);
#endif
        }

        static bool? _IsRunningOnMono;
        internal static bool IsRunningOnMono()
        {
            if (_IsRunningOnMono == null)
                _IsRunningOnMono = Type.GetType("Mono.Runtime") != null;
            return _IsRunningOnMono.Value;
        }

        static Byte[] Concat(Byte[] source1, Byte[] source2)
        {
            //Most efficient way to merge two arrays this according to http://stackoverflow.com/questions/415291/best-way-to-combine-two-or-more-byte-arrays-in-c-sharp
            Byte[] buffer = new Byte[source1.Length + source2.Length];
            System.Buffer.BlockCopy(source1, 0, buffer, 0, source1.Length);
            System.Buffer.BlockCopy(source2, 0, buffer, source1.Length, source2.Length);

            return buffer;
        }


        string _Mnemonic;
        public override string ToString()
        {
            return _Mnemonic;
        }


    }
    public enum WordCount : int
    {
        Twelve = 12,
        Fifteen = 15,
        Eighteen = 18,
        TwentyOne = 21,
        TwentyFour = 24
    }
}
