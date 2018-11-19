using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DLT
{
    class CryptoManager
    {
        static public CryptoLib lib;


        static CryptoManager()
        {
        }

        private CryptoManager()
        {
        }

        public static void initLib()
        {
            lib = new CryptoLib(new CryptoLibs.BouncyCastle());
        }

        // Initialize with a specific crypto library
        public static void initLib(ICryptoLib crypto_lib)
        {
            lib = new CryptoLib(crypto_lib);
        }

    }
}
