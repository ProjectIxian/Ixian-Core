using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DLT
{
    public class AddressClient
    {
        private List<byte[]> addresses;

        public AddressClient()
        {
            addresses = new List<byte[]>();
        }

        public void addAddress(byte[] addr)
        {
            if (!addresses.Any(a => a.SequenceEqual(addr)))
            {
                addresses.Add(addr);
            }
        }

        public void clearAddresses()
        {
            addresses.Clear();
        }

        public List<byte[]> getAddresses()
        {
            return addresses;
        }

        public int numAddresses()
        {
            return addresses.Count;
        }

        private int getRandomUnfilledByte(Random rnd, byte[] filled)
        {
            int possible_rnd = rnd.Next(filled.Length) + 1;
            int i = 0;
            while (true)
            {
                if (filled[i] == 0)
                {
                    possible_rnd--;
                    if (possible_rnd == 0) return i;
                }
                i++;
                if (i >= filled.Length) { i = 0; }
            }
        }

        public List<byte[]> generateHiddenMatchAddresses(Random rnd, int bytes_per_addr)
        {
            List<byte[]> matchers = new List<byte[]>();
            byte[] matcher = new byte[48];
            byte[] filled = new byte[48];
            for (int i = 0; i < filled.Length; i++) { filled[i] = 0; }
            filled[0] = 1; // Never use the first byte for this
            // Start with initial random state
            rnd.NextBytes(matcher);

            foreach (var addr in addresses)
            {
                if (filled.Count(x => x == 0) < bytes_per_addr)
                {
                    // Matcher is full
                    matchers.Add(matcher);
                    matcher = new byte[48];
                    rnd.NextBytes(matcher);
                    for (int i = 0; i < filled.Length; i++) { filled[i] = 0; }
                    filled[0] = 1;
                }
                for (int j = 0; j < bytes_per_addr; j++)
                {
                    int b = getRandomUnfilledByte(rnd, filled);
                    matcher[b] = addr[b];
                    filled[b] = 1;
                }
            }
            // Add last matcher, if meaningful
            if (filled.Count(x => x > 0) > 1)
            {
                matchers.Add(matcher);
            }
            return matchers;
        }

        public bool containsAddress(byte[] addr)
        {
            return addresses.Any(x => x.SequenceEqual(addr));
        }
    }
}
