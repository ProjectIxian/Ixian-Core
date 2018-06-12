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


        private static CryptoManager singletonInstance = new CryptoManager();
        static CryptoManager()
        {
        }

        private CryptoManager()
        {
        }

        public static CryptoManager singleton
        {
            get
            {
                return singletonInstance;
            }
        }

        public static void initLib()
        {
            lib = new CryptoLib(new CryptoLibs.BouncyCastle());
        }

    }
}
