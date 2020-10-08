using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Numerics;

namespace IXICore.Utils
{
    public static class IxiUtils
    {
        // Helper for validating IPv4 addresses
        static public bool validateIPv4(string ipString)
        {
            if (String.IsNullOrWhiteSpace(ipString))
            {
                return false;
            }

            string[] splitValues = ipString.Split('.');
            if (splitValues.Length != 4)
            {
                return false;
            }

            byte tempForParsing;
            return splitValues.All(r => byte.TryParse(r, out tempForParsing));
        }

        static public void executeProcess(string filename, string arguments, bool wait_for_exit)
        {
            var psi = new ProcessStartInfo();
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;

            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;

            psi.FileName = filename;
            psi.Arguments = arguments;

            var p = Process.Start(psi);
            if (wait_for_exit)
            {
                p.WaitForExit();
            }
        }

        // Extension methods
        public static TValue TryGet<TKey, TValue>(this IDictionary<TKey, TValue> dictionary, TKey key)
        {
            TValue value;
            dictionary.TryGetValue(key, out value);
            return value;
        }

        public static void AddOrReplace<TKey, TValue>(this IDictionary<TKey, TValue> dico, TKey key, TValue value)
        {
            if (dico.ContainsKey(key))
                dico[key] = value;
            else
                dico.Add(key, value);
        }
    }


    // Extension - lambda comparer for stuff like SortedSet
    public class LambdaComparer<T> : IComparer<T>
    {
        private readonly Comparison<T> comparison;
        public LambdaComparer(Comparison<T> comparison)
        {
            this.comparison = comparison;
        }
        public int Compare(T x, T y)
        {
            return comparison(x, y);
        }
    }
}
