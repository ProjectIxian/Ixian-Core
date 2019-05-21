using System.Diagnostics;

namespace DLT
{
    public class IxianKeyPair
    {
        public byte[] publicKeyBytes = null;
        public byte[] privateKeyBytes = null;
        public byte[] lastNonceBytes = null; // nonce for generating new addresses
        public byte[] addressBytes = null;
    }

    public interface ICryptoLib
    {
        IxianKeyPair generateKeys(int keySize, bool skip_header = false);

        byte[] getSignature(byte[] input, byte[] privateKey);
        bool verifySignature(byte[] input, byte[] publicKey, byte[] signature);

        byte[] encryptWithRSA(byte[] input, byte[] publicKey);
        byte[] decryptWithRSA(byte[] input, byte[] privateKey);

        byte[] encryptDataAES(byte[] input, byte[] key);
        byte[] decryptDataAES(byte[] input, byte[] key, int offset = 0);

        byte[] encryptWithPassword(byte[] data, string password);
        byte[] decryptWithPassword(byte[] data, string password);

        byte[] encryptWithChacha(byte[] input, byte[] key);
        byte[] decryptWithChacha(byte[] input, byte[] key);

        byte[] generateChildKey(byte[] parentKey, int seed = 0);

        bool testKeys(byte[] keypair, IxianKeyPair kp);
    }


    public class CryptoLib
    {
        private ICryptoLib _cryptoLib = null;

        public CryptoLib(ICryptoLib crypto_lib)
        {
            _cryptoLib = crypto_lib;
        }

        public IxianKeyPair generateKeys(int keySize, bool skip_header = false)
        {
            Trace.Assert(_cryptoLib != null);
            return _cryptoLib.generateKeys(keySize, skip_header);
        }

        public byte[] getSignature(byte[] input, byte[] privateKey)
        {
            return _cryptoLib.getSignature(input, privateKey);
        }

        public bool verifySignature(byte[] input, byte[] publicKey, byte[] signature)
        {
            return _cryptoLib.verifySignature(input, publicKey, signature);
        }

        public byte[] encryptWithRSA(byte[] input, byte[] publicKey)
        {
            return _cryptoLib.encryptWithRSA(input, publicKey);
        }

        public byte[] decryptWithRSA(byte[] input, byte[] privateKey)
        {
            return _cryptoLib.decryptWithRSA(input, privateKey);
        }

        public byte[] encryptDataAES(byte[] input, byte[] key)
        {
            return _cryptoLib.encryptDataAES(input, key);
        }

        public byte[] decryptDataAES(byte[] input, byte[] key, int offset = 0)
        {
            return _cryptoLib.decryptDataAES(input, key, offset);
        }

        public byte[] encryptWithPassword(byte[] data, string password)
        {
            return _cryptoLib.encryptWithPassword(data, password);
        }

        public byte[] decryptWithPassword(byte[] data, string password)
        {
            return _cryptoLib.decryptWithPassword(data, password);
        }

        public byte[] encryptWithChacha(byte[] input, byte[] key)
        {
            return _cryptoLib.encryptWithChacha(input, key);
        }

        public byte[] decryptWithChacha(byte[] input, byte[] key)
        {
            return _cryptoLib.decryptWithChacha(input, key);
        }

        public byte[] generateChildKey(byte[] parentKey, int seed = 0)
        {
            return _cryptoLib.generateChildKey(parentKey, seed);
        }

        public bool testKeys(byte[] plaintext, IxianKeyPair kp)
        {
            return _cryptoLib.testKeys(plaintext, kp);
        }
    }
}
