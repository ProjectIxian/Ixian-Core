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
        bool generateKeys(int keySize);
        List<string> generateEncryptionKeys();

        byte[] getPublicKey();
        byte[] getPrivateKey();

        byte[] getEncPublicKey();
        byte[] getEncPrivateKey();

        byte[] getSignature(byte[] input, byte[] privateKey);
        bool verifySignature(byte[] input, byte[] publicKey, byte[] signature);

        byte[] encryptData(byte[] data, string publicKey);
        byte[] decryptData(byte[] data, string privateKey);

        byte[] encryptDataS2(byte[] data, string publicKey);
        byte[] decryptDataS2(byte[] data, string privateKey);

        byte[] encryptDataAES(byte[] input, byte[] key);
        byte[] decryptDataAES(byte[] input, byte[] key, int offset = 0);

        byte[] encryptWithPassword(byte[] data, string password);
        byte[] decryptWithPassword(byte[] data, string password);
    }


    class CryptoLib
    {
        private ICryptoLib _cryptoLib = null;

        public CryptoLib(ICryptoLib crypto_lib)
        {
            _cryptoLib = crypto_lib;
        }

        public bool generateKeys(int keySize)
        {
            Trace.Assert(_cryptoLib != null);
            return _cryptoLib.generateKeys(keySize);
        }
        public List<string> generateEncryptionKeys()
        {
            Trace.Assert(_cryptoLib != null);
            return _cryptoLib.generateEncryptionKeys();
        }

        public byte[] getPublicKey()
        {
            return _cryptoLib.getPublicKey();
        }

        public byte[] getPrivateKey()
        {
            return _cryptoLib.getPrivateKey();
        }

        public byte[] getEncPublicKey()
        {
            return _cryptoLib.getEncPublicKey();
        }

        public byte[] getEncPrivateKey()
        {
            return _cryptoLib.getEncPrivateKey();
        }

        public byte[] getSignature(byte[] input, byte[] privateKey)
        {
            return _cryptoLib.getSignature(input, privateKey);
        }

        public bool verifySignature(byte[] input, byte[] publicKey, byte[] signature)
        {
            return _cryptoLib.verifySignature(input, publicKey, signature);
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

    }
}
