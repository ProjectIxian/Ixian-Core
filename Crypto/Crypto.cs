using System.Security.Cryptography;
using System.Text;

namespace DLT
{

    public class Crypto
    {

        static public string sha256(string randomString)
        {
            System.Security.Cryptography.SHA256Managed crypt = new System.Security.Cryptography.SHA256Managed();
            System.Text.StringBuilder hash = new System.Text.StringBuilder();
            byte[] crypto = crypt.ComputeHash(Encoding.UTF8.GetBytes(randomString), 0, Encoding.UTF8.GetByteCount(randomString));
            return hashToString(crypto);
        }

        public static string hashToString(byte[] data)
        {
            System.Text.StringBuilder hash = new System.Text.StringBuilder();
            foreach (byte theByte in data)
            {
                hash.Append(theByte.ToString("x2"));
            }
            return hash.ToString();
        }

        public static byte[] sha256(byte[] data)
        {
            return sha256(data, 0, data.Length);
        }

        public static byte[] sha256(byte[] data, int count)
        {
            return sha256(data, 0, count);
        }

        public static byte[] sha256(byte[] data, int offset, int count)
        {
#if USEBC || WINDOWS_UWP || NETCORE
			Sha256Digest sha256 = new Sha256Digest();
			sha256.BlockUpdate(data, offset, count);
			byte[] rv = new byte[32];
			sha256.DoFinal(rv, 0);
			sha256.BlockUpdate(rv, 0, rv.Length);
			sha256.DoFinal(rv, 0);
			return new uint256(rv);
#else
            using (var sha = new SHA256Managed())
            {
                var h = sha.ComputeHash(data, offset, count);
                return sha.ComputeHash(h, 0, h.Length);
            }
#endif
        }

        // Used to compare checksums. Could move it to a better place
        public static bool byteArrayCompare(byte[] a1, byte[] a2)
        {
            if (a1.Length != a2.Length)
                return false;

            for (int i = 0; i < a1.Length; i++)
                if (a1[i] != a2[i])
                    return false;

            return true;
        }
    }


}