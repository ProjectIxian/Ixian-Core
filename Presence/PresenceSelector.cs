using System;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.Collections;

namespace DLT
{

    public class AddressComparer : IComparer<byte[]>
    {
        public int Compare(byte[] x, byte[] y)
        {
            if (x == null && y == null) return 0;
            if (x == null && y != null) return -1;
            if (x != null && y == null) return 1;

            int min_len = x.Length < y.Length ? x.Length : y.Length;
            for (int i = 0; i < min_len; i++)
            {
                if (x[i] < y[i]) return -1;
                if (x[i] > y[i]) return 1;
            }
            if (x.Length < y.Length) return -1;
            if (x.Length > y.Length) return 1;
            return 0;
        }
    }

    public class PresenceOrderedEnumerator : IEnumerator<byte[]>
    {
        private byte[] SelectorIndexes;
        private int AddressLen;
        private SortedDictionary<byte[], string[]> Addresses;
        // Iterator stuff
        int CurrentPosition;
        int TargetCount;
        //
        public PresenceOrderedEnumerator(IEnumerable<Presence> presences, int address_len, byte[] selector, int target_count = 2000)
        {
            if (selector.Length != address_len)
            {
                throw new ArgumentException("Selector must be exactly as long as the address.");
            }
            AddressLen = address_len;
            SelectorIndexes = selector;
            Addresses = new SortedDictionary<byte[], string[]>(new AddressComparer());
            //
            List<HashSet<string>> RepetitionsIP = new List<HashSet<string>>();
            // Please note:
            //  RepetitionsIP[0] = IPs which occur 1 times (repeat 0 times)
            //  RepetitionsIP[1] = IPs which occur 2 times (repeat 1 times)
            //
            foreach (var p in presences)
            {
                string[] ips = p.addresses.Select(pa => pa.address.Split(':')[0]).ToArray();
                foreach (var ip in ips)
                {
                    AddRepetition(RepetitionsIP, ip);
                }
                Addresses.Add(permute(p.wallet, SelectorIndexes), ips);
            }

            // Reduce number of addresses
            int max_rep = RepetitionsIP.Count - 1;
            while (Addresses.Count > target_count && max_rep > 0)
            {
                // remove IPs that occur most often
                List<byte[]> to_remove = new List<byte[]>();
                foreach (var ae in Addresses)
                {
                    if (ae.Value.Any(ip => RepetitionsIP[max_rep].Contains(ip)))
                    {
                        to_remove.Add(ae.Key);
                    }
                    if (Addresses.Count - to_remove.Count <= target_count) break;
                }
                foreach (var a in to_remove)
                {
                    Addresses.Remove(a);
                }
                max_rep--;
            }

            // Prepare iterator
            CurrentPosition = -1;
            TargetCount = target_count;
        }

        public static byte[] GenerateSelectorFromRandom(byte[] random)
        {
            byte[] selector = new byte[random.Length];
            for (int i = 0; i < selector.Length; i++)
            {
                selector[i] = (byte)i;
            }
            for (int i = 0; i < random.Length; i++)
            {
                int idx = random[i] % random.Length;
                byte t = selector[idx];
                selector[idx] = selector[i];
                selector[i] = t;
            }
            return selector;
        }

        private static void AddRepetition(List<HashSet<string>> repetition_ip, string ip)
        {
            int rep = repetition_ip.Count - 1;
            while (rep >= 0)
            {
                if (repetition_ip[rep].Contains(ip))
                {
                    break;
                }
                rep--;
            }
            if (rep >= 0) repetition_ip[rep].Remove(ip);
            if (repetition_ip.Count <= rep + 1) repetition_ip.Add(new HashSet<string>());
            repetition_ip[rep + 1].Add(ip);
        }

        private static byte[] permute(byte[] data, byte[] selector)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                result[i] = data[selector[i]];
            }
            return result;
        }

        private static byte[] unpermute(byte[] data, byte[] selector)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                result[selector[i]] = data[i];
            }
            return result;
        }

        public byte[] Current
        {
            get
            {
                return unpermute(Addresses.ElementAt(CurrentPosition).Key, SelectorIndexes);
            }
        }

        object IEnumerator.Current => this.Current;

        public void Dispose()
        {

        }

        public bool MoveNext()
        {
            CurrentPosition++;
            if (CurrentPosition >= Addresses.Count || CurrentPosition >= TargetCount) return false;
            return true;
        }

        public void Reset()
        {
            CurrentPosition = -1;
        }

        public IEnumerator GetEnumerator()
        {
            return this;
        }
    }
}