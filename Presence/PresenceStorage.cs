using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Linq;
using DLT.Meta;

namespace DLT
{
    class PresenceStorage
    {
        public static string presenceFilename = "presence.dat";

        // Saves a list of 500 master node addresses to a file
        public static void savePresenceFile()
        {
            // Get a list of master node presences
            List<string> mn_presences = PresenceList.getMasterNodeAddresses(500);
            // Don't write to file if no masternode presences were found in addition to the current node
            if (mn_presences.Count < 2)
                return;

            using (TextWriter tw = new StreamWriter(presenceFilename))
            {
                foreach (String addr in mn_presences)
                    tw.WriteLine(addr);
            }
            mn_presences.Clear();
        }

        // Retrieves the master node address file's contents
        public static List<string> readPresenceFile()
        {
            List<string> mn_presences = new List<string>();

            // Check if the presence file exists
            if (File.Exists(presenceFilename))
            {
                Logging.info("Presence file found. Adding addresses to initial connections.");
            }
            else
            {
                return mn_presences;
            }

            try
            {
                mn_presences = File.ReadAllLines(presenceFilename).ToList();
            }
            catch (Exception)
            {

            }

            return mn_presences;
        }

        // Deletes the presence file cache
        public static void deletePresenceFile()
        {
            if (File.Exists(PresenceStorage.presenceFilename))
            {
                File.Delete(PresenceStorage.presenceFilename);
            }

            return;
        }

    }
}
