using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace IXICore.CryptoKey
{

    class AsnKeyParser
    {
        private AsnParser parser;

        internal AsnKeyParser(byte[] blob)
        {
            parser = new AsnParser(blob);
        }

        internal static byte[] TrimLeadingZero(byte[] values)
        {
            byte[] r = null;
            if ((0x00 == values[0]) && (values.Length > 1))
            {
                r = new byte[values.Length - 1];
                Array.Copy(values, 1, r, 0, values.Length - 1);
            }
            else
            {
                r = new byte[values.Length];
                Array.Copy(values, r, values.Length);
            }

            return r;
        }

        internal static bool EqualOid(byte[] first, byte[] second)
        {
            if (first.Length != second.Length)
            { return false; }

            for (int i = 0; i < first.Length; i++)
            {
                if (first[i] != second[i])
                { return false; }
            }

            return true;
        }

        internal RSAParameters ParseRSAPrivateKey()
        {
            RSAParameters parameters = new RSAParameters();

            // Current value
            byte[] value = null;

            // Checkpoint
            int position = parser.CurrentPosition();

            // Sanity Check
            int length = 0;

            // Ignore Sequence - PrivateKeyInfo
            length = parser.NextSequence();
            if (length != parser.RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect Sequence Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                  length.ToString(CultureInfo.InvariantCulture), parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new Exception(sb.ToString());
            }

            // Checkpoint
            position = parser.CurrentPosition();
            // Version
            value = parser.NextInteger();
            if (0x00 != value[0])
            {
                StringBuilder sb = new StringBuilder("Incorrect PrivateKeyInfo Version. ");
                BigInteger v = new BigInteger(value);
                sb.AppendFormat("Expected: 0, Specified: {0}", v.ToString(10));
                throw new Exception(sb.ToString());
            }

            // Checkpoint
            position = parser.CurrentPosition();

            // Ignore Sequence - AlgorithmIdentifier
            /*length = parser.NextSequence();
            if (length > parser.RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect AlgorithmIdentifier Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                  length.ToString(CultureInfo.InvariantCulture),
                  parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new Exception(sb.ToString());
            }

            // Checkpoint
            position = parser.CurrentPosition();

            // Grab the OID
            value = parser.NextOID();
            byte[] oid = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
            if (!EqualOid(value, oid))
            { throw new Exception("Expected OID 1.2.840.113549.1.1.1"); }

            // Optional Parameters
            if (parser.IsNextNull())
            {
                parser.NextNull();
                // Also OK: value = parser.Next();
            }
            else
            {
                // Gracefully skip the optional data
                value = parser.Next();
            }
            
            // Checkpoint
            position = parser.CurrentPosition();
            
            // Ignore OctetString - PrivateKey
            length = parser.NextOctetString();
            if (length > parser.RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect PrivateKey Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                  length.ToString(CultureInfo.InvariantCulture),
                  parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new Exception(sb.ToString());
            }

            // Checkpoint
            position = parser.CurrentPosition();

            // Ignore Sequence - RSAPrivateKey
            length = parser.NextSequence();
            if (length < parser.RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect RSAPrivateKey Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                  length.ToString(CultureInfo.InvariantCulture),
                  parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new Exception(sb.ToString());
            }

            // Checkpoint
            position = parser.CurrentPosition();
            
            // Version
            value = parser.NextInteger();
            if (0x00 != value[0])
            {
                StringBuilder sb = new StringBuilder("Incorrect RSAPrivateKey Version. ");
                BigInteger v = new BigInteger(value);
                sb.AppendFormat("Expected: 0, Specified: {0}", v.ToString(10));
                throw new Exception(sb.ToString());
            }
            */
            parameters.Modulus = TrimLeadingZero(parser.NextInteger());
            parameters.Exponent = TrimLeadingZero(parser.NextInteger());
            parameters.D = TrimLeadingZero(parser.NextInteger());
            parameters.P = TrimLeadingZero(parser.NextInteger());
            parameters.Q = TrimLeadingZero(parser.NextInteger());
            parameters.DP = TrimLeadingZero(parser.NextInteger());
            parameters.DQ = TrimLeadingZero(parser.NextInteger());
            parameters.InverseQ = TrimLeadingZero(parser.NextInteger());

            Debug.Assert(0 == parser.RemainingBytes());

            return parameters;
        }
    }

    class AsnParser
    {
        private List<byte> octets;
        private int initialCount;

        internal AsnParser(byte[] values)
        {
            octets = new List<byte>(values.Length);
            octets.AddRange(values);

            initialCount = octets.Count;
        }

        internal int CurrentPosition()
        {
            return initialCount - octets.Count;
        }

        internal int RemainingBytes()
        {
            return octets.Count;
        }

        private int GetLength()
        {
            int length = 0;

            // Checkpoint
            int position = CurrentPosition();

            try
            {
                byte b = GetNextOctet();

                if (b == (b & 0x7f)) { return b; }
                int i = b & 0x7f;

                if (i > 4)
                {
                    StringBuilder sb = new StringBuilder("Invalid Length Encoding. ");
                    sb.AppendFormat("Length uses {0} octets",
                      i.ToString(CultureInfo.InvariantCulture));
                    throw new Exception(sb.ToString());
                }

                while (0 != i--)
                {
                    // shift left
                    length <<= 8;

                    length |= GetNextOctet();
                }
            }
            catch (ArgumentOutOfRangeException)
            { throw new Exception("Error Parsing Key"); }

            return length;
        }

        internal byte[] Next()
        {
            int position = CurrentPosition();

            try
            {
                byte b = GetNextOctet();

                int length = GetLength();
                if (length > RemainingBytes())
                {
                    StringBuilder sb = new StringBuilder("Incorrect Size. ");
                    sb.AppendFormat("Specified: {0}, Remaining: {1}",
                      length.ToString(CultureInfo.InvariantCulture),
                      RemainingBytes().ToString(CultureInfo.InvariantCulture));
                    throw new Exception(sb.ToString());
                }

                return GetOctets(length);
            }

            catch (ArgumentOutOfRangeException)
            { throw new Exception("Error Parsing Key"); }
        }

        internal byte GetNextOctet()
        {
            int position = CurrentPosition();

            if (0 == RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                  1.ToString(CultureInfo.InvariantCulture),
                  RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new Exception(sb.ToString());
            }

            byte b = GetOctets(1)[0];

            return b;
        }

        internal byte[] GetOctets(int octetCount)
        {
            int position = CurrentPosition();

            if (octetCount > RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                  octetCount.ToString(CultureInfo.InvariantCulture),
                  RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new Exception(sb.ToString());
            }

            byte[] values = new byte[octetCount];

            try
            {
                octets.CopyTo(0, values, 0, octetCount);
                octets.RemoveRange(0, octetCount);
            }

            catch (ArgumentOutOfRangeException)
            { throw new Exception("Error Parsing Key"); }

            return values;
        }

        internal bool IsNextNull()
        {
            return 0x05 == octets[0];
        }

        internal int NextNull()
        {
            int position = CurrentPosition();

            try
            {
                byte b = GetNextOctet();
                if (0x05 != b)
                {
                    StringBuilder sb = new StringBuilder("Expected Null. ");
                    sb.AppendFormat("Specified Identifier: {0}", b.ToString(CultureInfo.InvariantCulture));
                    throw new Exception(sb.ToString());
                }

                // Next octet must be 0
                b = GetNextOctet();
                if (0x00 != b)
                {
                    StringBuilder sb = new StringBuilder("Null has non-zero size. ");
                    sb.AppendFormat("Size: {0}", b.ToString(CultureInfo.InvariantCulture));
                    throw new Exception(sb.ToString());
                }

                return 0;
            }

            catch (ArgumentOutOfRangeException)
            { throw new Exception("Error Parsing Key"); }
        }

        internal bool IsNextSequence()
        {
            return 0x30 == octets[0];
        }

        internal int NextSequence()
        {
            int position = CurrentPosition();

            try
            {
                byte b = GetNextOctet();
                if (0x30 != b)
                {
                    StringBuilder sb = new StringBuilder("Expected Sequence. ");
                    sb.AppendFormat("Specified Identifier: {0}",
                      b.ToString(CultureInfo.InvariantCulture));
                    throw new Exception(sb.ToString());
                }

                int length = GetLength();
                if (length > RemainingBytes())
                {
                    StringBuilder sb = new StringBuilder("Incorrect Sequence Size. ");
                    sb.AppendFormat("Specified: {0}, Remaining: {1}",
                      length.ToString(CultureInfo.InvariantCulture),
                      RemainingBytes().ToString(CultureInfo.InvariantCulture));
                    throw new Exception(sb.ToString());
                }

                return length;
            }

            catch (ArgumentOutOfRangeException)
            { throw new Exception("Error Parsing Key"); }
        }

        internal bool IsNextOctetString()
        {
            return 0x04 == octets[0];
        }

        internal int NextOctetString()
        {
            int position = CurrentPosition();

            try
            {
                byte b = GetNextOctet();
                if (0x04 != b)
                {
                    StringBuilder sb = new StringBuilder("Expected Octet String. ");
                    sb.AppendFormat("Specified Identifier: {0}", b.ToString(CultureInfo.InvariantCulture));
                    throw new Exception(sb.ToString());
                }

                int length = GetLength();
                if (length > RemainingBytes())
                {
                    StringBuilder sb = new StringBuilder("Incorrect Octet String Size. ");
                    sb.AppendFormat("Specified: {0}, Remaining: {1}",
                      length.ToString(CultureInfo.InvariantCulture),
                      RemainingBytes().ToString(CultureInfo.InvariantCulture));
                    throw new Exception(sb.ToString());
                }

                return length;
            }

            catch (ArgumentOutOfRangeException)
            { throw new Exception("Error Parsing Key"); }
        }

        internal bool IsNextBitString()
        {
            return 0x03 == octets[0];
        }

        internal int NextBitString()
        {
            int position = CurrentPosition();

            try
            {
                byte b = GetNextOctet();
                if (0x03 != b)
                {
                    StringBuilder sb = new StringBuilder("Expected Bit String. ");
                    sb.AppendFormat("Specified Identifier: {0}", b.ToString(CultureInfo.InvariantCulture));
                    throw new Exception(sb.ToString());
                }

                int length = GetLength();

                // We need to consume unused bits, which is the first
                //   octet of the remaing values
                b = octets[0];
                octets.RemoveAt(0);
                length--;

                if (0x00 != b)
                { throw new Exception("The first octet of BitString must be 0"); }

                return length;
            }

            catch (ArgumentOutOfRangeException)
            { throw new Exception("Error Parsing Key"); }
        }

        internal bool IsNextInteger()
        {
            return 0x02 == octets[0];
        }

        internal byte[] NextInteger()
        {
            int position = CurrentPosition();

            try
            {
                byte b = GetNextOctet();
                if (0x02 != b)
                {
                    StringBuilder sb = new StringBuilder("Expected Integer. ");
                    sb.AppendFormat("Specified Identifier: {0}", b.ToString(CultureInfo.InvariantCulture));
                    throw new Exception(sb.ToString());
                }

                int length = GetLength();
                if (length > RemainingBytes())
                {
                    StringBuilder sb = new StringBuilder("Incorrect Integer Size. ");
                    sb.AppendFormat("Specified: {0}, Remaining: {1}",
                      length.ToString(CultureInfo.InvariantCulture),
                      RemainingBytes().ToString(CultureInfo.InvariantCulture));
                    throw new Exception(sb.ToString());
                }

                return GetOctets(length);
            }

            catch (ArgumentOutOfRangeException)
            { throw new Exception("Error Parsing Key"); }
        }

        internal byte[] NextOID()
        {
            int position = CurrentPosition();

            try
            {
                byte b = GetNextOctet();
                if (0x06 != b)
                {
                    StringBuilder sb = new StringBuilder("Expected Object Identifier. ");
                    sb.AppendFormat("Specified Identifier: {0}",
                      b.ToString(CultureInfo.InvariantCulture));
                    throw new Exception(sb.ToString());
                }

                int length = GetLength();
                if (length > RemainingBytes())
                {
                    StringBuilder sb = new StringBuilder("Incorrect Object Identifier Size. ");
                    sb.AppendFormat("Specified: {0}, Remaining: {1}",
                      length.ToString(CultureInfo.InvariantCulture),
                      RemainingBytes().ToString(CultureInfo.InvariantCulture));
                    throw new Exception(sb.ToString());
                }

                byte[] values = new byte[length];

                for (int i = 0; i < length; i++)
                {
                    values[i] = octets[0];
                    octets.RemoveAt(0);
                }

                return values;
            }

            catch (ArgumentOutOfRangeException)
            { throw new Exception("Error Parsing Key"); }
        }
    }
}