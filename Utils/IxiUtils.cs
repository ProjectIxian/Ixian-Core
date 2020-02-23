using System;
using System.Diagnostics;
using System.Linq;
using System.Numerics;

namespace IXICore.Utils
{
    static class IxiUtils
    {
        // Calculates the reward amount for a certain block
        public static IxiNumber calculateMiningRewardForBlock(ulong blockNum)
        {
            ulong pow_reward = 0;

            if (blockNum < 1051200) // first year
            {
                pow_reward = (blockNum * 9) + 9; // +0.009 IXI
            }
            else if (blockNum < 2102400) // second year
            {
                pow_reward = (1051200 * 9);
            }
            else if (blockNum < 3153600) // third year
            {
                pow_reward = (1051200 * 9) + ((blockNum - 2102400) * 9) + 9; // +0.009 IXI
            }
            else if (blockNum < 4204800) // fourth year
            {
                pow_reward = (2102400 * 9) + ((blockNum - 3153600) * 2) + 2; // +0.0020 IXI
            }
            else if (blockNum < 5256001) // fifth year
            {
                pow_reward = (2102400 * 9) + (1051200 * 2) + ((blockNum - 4204800) * 9) + 9; // +0.009 IXI
            }
            else // after fifth year if mining is still operational
            {
                pow_reward = ((3153600 * 9) + (1051200 * 2)) / 2;
            }

            pow_reward = (pow_reward / 2 + 10000) * 100000; // Divide by 2 (assuming 50% block coverage) + add inital 10 IXI block reward + add the full amount of 0s to cover IxiNumber decimals
            return new IxiNumber(new BigInteger(pow_reward)); // Generate the corresponding IxiNumber, including decimals
        }
        
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
    }
}
