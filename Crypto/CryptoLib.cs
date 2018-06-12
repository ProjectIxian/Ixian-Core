using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DLT
{
    interface ICryptoLib
    {
        bool generateKeys();
        List<string> generateEncryptionKeys();

        string getPublicKey();
        string getPrivateKey();

        string getEncPublicKey();
        string getEncPrivateKey();

        string getSignature(string text, string privateKey);
        bool verifySignature(string text, string publicKey, string signature);

        byte[] encryptData(byte[] data, string publicKey);
        byte[] decryptData(byte[] data, string privateKey);

        byte[] encryptDataS2(byte[] data, string publicKey);
        byte[] decryptDataS2(byte[] data, string privateKey);

        byte[] encryptDataAES(byte[] input, string key);
        byte[] decryptDataAES(byte[] input, string key);

    }


    class CryptoLib
    {
        private ICryptoLib _cryptoLib = null;

        public CryptoLib(ICryptoLib crypto_lib)
        {
            _cryptoLib = crypto_lib;
        }

        public bool generateKeys()
        {
            Trace.Assert(_cryptoLib != null);
            return _cryptoLib.generateKeys();
        }
        public List<string> generateEncryptionKeys()
        {
            Trace.Assert(_cryptoLib != null);
            return _cryptoLib.generateEncryptionKeys();
        }

        public string getPublicKey()
        {
            return _cryptoLib.getPublicKey();
        }

        public string getPrivateKey()
        {
            return _cryptoLib.getPrivateKey();
        }

        public string getEncPublicKey()
        {
            return _cryptoLib.getEncPublicKey();
        }

        public string getEncPrivateKey()
        {
            return _cryptoLib.getEncPrivateKey();
        }

        public string getSignature(string text, string privateKey)
        {
            return _cryptoLib.getSignature(text, privateKey);
        }

        public bool verifySignature(string text, string publicKey, string signature)
        {
            return _cryptoLib.verifySignature(text, publicKey, signature);
        }

        public byte[] encryptData(byte[] data, string publicKey)
        {
            return _cryptoLib.encryptData(data, publicKey);
        }

        public byte[] decryptData(byte[] data, string privateKey)
        {
            return _cryptoLib.decryptData(data, privateKey);
        }

        public byte[] encryptDataS2(byte[] data, string publicKey)
        {
            return _cryptoLib.encryptDataS2(data, publicKey);
        }

        public byte[] decryptDataS2(byte[] data, string privateKey)
        {
            return _cryptoLib.decryptDataS2(data, privateKey);
        }

        public byte[] encryptDataAES(byte[] input, string key)
        {
            return _cryptoLib.encryptDataAES(input, key);
        }

        public byte[] decryptDataAES(byte[] input, string key)
        {
            return _cryptoLib.decryptDataAES(input, key);
        }

    }
}
