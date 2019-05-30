using System;
using System.Collections.Generic;
using System.Text;

namespace DLT
{
    /// <summary>
    ///  The other half of the implementation for `AddressClient`, which allows an untrusted party to check if given addresses
    ///  are of interest to the client. The client supplies a 'matcher' value, against which the addresses are checked.
    ///  The matcher will produce false-positives, but never false-negatives, which means that it is impossible to accurately
    ///  determine if an address belongs to the client or not.
    /// </summary>
    public class AddressMatcher
    {
        /// <summary>
        ///  Checks if the given address matches the provided 'matcher' data.
        /// </summary>
        /// <param name="matcher">Matcher data, as provided by the `AddressClient` object.</param>
        /// <param name="addr">Address to check.</param>
        /// <param name="match_bytes">Number of bytes to match. See remarks of `AddressClient.generateHiddenMatchAddresses()`.</param>
        /// <returns>True, if the address matches (may be a false positive)</returns>
        public static bool matches(byte[] matcher, byte[] addr, int match_bytes)
        {
            if (addr.Length != matcher.Length)
                return false;

            int count = 0;
            // Note - we always skip first byte because no matcher is made with the first byte
            for (int i = 1; i < matcher.Length; i++)
            {
                if ((matcher[i] ^ addr[i]) == 0) count++;
                if (count >= match_bytes) return true;
            }
            return false;
        }

        /// <summary>
        ///  Checks if the given addresses matches any of the provided 'matcher' data.
        /// </summary>
        /// <param name="matchers">A list of matcher objects.</param>
        /// <param name="addr">Address to check</param>
        /// <param name="match_bytes">Number of bytes to use for matching. See remarks of `AddressClient.generateHiddenMatchAddresses()`.</param>
        /// <returns>True, if the address matches any of the matchers (may be a false positive)</returns>
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
