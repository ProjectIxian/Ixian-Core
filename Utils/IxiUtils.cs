using System;
using System.Diagnostics;
using System.Linq;

namespace IXICore.Utils
{
    static class IxiUtils
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
    }
}
