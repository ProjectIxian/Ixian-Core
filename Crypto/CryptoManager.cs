using System;

namespace IXICore
{
    public class CryptoManager
    {
        static private CryptoLib _lib;

        static public CryptoLib lib
        {
            get
            {
                if (_lib == null)
                {
                    _lib = new CryptoLib(new BouncyCastle());
                }
                return _lib;
            }
        }

        [Obsolete]
        public static void initLib()
        {
        }

        // Initialize with a specific crypto library
        public static void initLib(ICryptoLib crypto_lib)
        {
            _lib = new CryptoLib(crypto_lib);
        }
    }
}
