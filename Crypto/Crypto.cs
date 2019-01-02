using System;
using System.Security.Cryptography;
using System.Text;

namespace DLT
{

    public class Crypto
    {

        public static string hashToString(byte[] data)
        {
            if(data == null)
            {
                return "null";
            }
            StringBuilder hash = new StringBuilder();
            foreach (byte theByte in data)
            {
                hash.Append(theByte.ToString("x2"));
            }
            return hash.ToString();
        }

        public static byte[] stringToHash(string data)
        {
            int NumberChars = data.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(data.Substring(i, 2), 16);
            return bytes;
        }

        public static byte[] sha256(byte[] data, int offset = 0, int count = 0)
        {
            using (var sha = new SHA256Managed())
            {
                if (count == 0)
                {
                    count = data.Length - offset;
                }
                var h = sha.ComputeHash(data, offset, count);
                return sha.ComputeHash(h, 0, h.Length);
            }
        }

        public static byte[] sha512(byte[] data, int offset = 0, int count = 0)
        {
#if USEBC || WINDOWS_UWP || NETCORE
			Sha512Digest sha = new Sha512Digest();
			sha.BlockUpdate(data, offset, count);
			byte[] rv = new byte[64];
			sha.DoFinal(rv, 0);
			sha.BlockUpdate(rv, 0, rv.Length);
			sha.DoFinal(rv, 0);
			return new uint256(rv);
#else
            using (var sha = new SHA512Managed())
            {
                if(count == 0)
                {
                    count = data.Length - offset;
                }
                var h = sha.ComputeHash(data, offset, count);
                return sha.ComputeHash(h, 0, h.Length);
            }
#endif
        }

        public static byte[] sha512sq(byte[] data, int offset = 0, int count = 0)
        {
            return sha512(sha512(data, offset, count));
        }

        public static byte[] sha512sqTrunc(byte[] data, int offset = 0, int count = 0, int hash_length = 32)
        {
            byte[] shaTrunc = new byte[hash_length];
            Array.Copy(sha512sq(data, offset, count), shaTrunc, hash_length);
            return shaTrunc;
        }
    }
}