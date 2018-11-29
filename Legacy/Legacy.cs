using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DLT
{
    class Legacy
    {
        // List of upgrades and corresponding block heights



        // Quickly checks if a block number is within a legacy window
        public static bool isLegacy(ulong blocknum)
        {
            /*if(blocknum < up20181017)
            {
                // Legacy code needed
                return true;
            }*/

            // This does not require legacy code
            return false;
        }

        // Returns the legacy level
        public static ulong getLegacyLevel()
        {
            //return up20181017;
            return 0;
        }

    }
}
