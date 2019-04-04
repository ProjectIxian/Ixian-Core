using System;
using System.Collections.Generic;
using System.Text;

namespace DLT
{
    public class AddressMatcher
    {
        // Match a single address
        public static bool matches(byte[] matcher, byte[] addr, int match_bytes)
        {
            int count = 0;
            // Note - we always skip first byte because no matcher is made with the first byte
            for (int i = 1; i < matcher.Length; i++)
            {
                if ((matcher[i] ^ addr[i]) == 0) count++;
                if (count >= match_bytes) return true;
            }
            return false;
        }

        // Match multiple addresses at once
        public static bool matchesAny(List<byte[]> matchers, byte[] addr, int match_bytes)
        {
            foreach (var m in matchers)
            {
                if (matches(m, addr, match_bytes))
                    return true;
            }
            return false;
        }
    }
}
