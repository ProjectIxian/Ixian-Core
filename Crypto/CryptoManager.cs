
namespace DLT
{
    public class CryptoManager
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
