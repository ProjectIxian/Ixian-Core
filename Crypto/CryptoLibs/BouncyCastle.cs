using DLT.Meta;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DLT;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using System.IO;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Asn1;
using System.Security.Cryptography;

namespace CryptoLibs
{
    class BouncyCastle : ICryptoLib
    {
        string publicKeyString;
        string privateKeyString;

        string encPublicKeyString;
        string encPrivateKeyString;

        // Private variables used for AES key expansion
        private int PBKDF2_iterations = 10000;
        private string AES_algorithm = "AES/CBC/PKCS7Padding";

        public BouncyCastle()
        {
            publicKeyString = "";
            privateKeyString = "";

            encPublicKeyString = "";
            encPrivateKeyString = "";
        }

        // Generates keys for RSA signing
        public bool generateKeys(int keySize)
        {
            try
            {
                // OLD BC RSA Code
                /*         var rsaKeyParams = new RsaKeyGenerationParameters(BigInteger.ProbablePrime(512, new Random()),
                                           new SecureRandom(), 3072, 25);
                         var keyGen = new RsaKeyPairGenerator();
                         keyGen.Init(rsaKeyParams);

                         AsymmetricCipherKeyPair key_pair = keyGen.GenerateKeyPair();

                         PrivateKeyInfo pkInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(key_pair.Private);
                         privateKeyString = Convert.ToBase64String(pkInfo.GetDerEncoded());

                         SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(key_pair.Public);
                         publicKeyString = Convert.ToBase64String(info.GetDerEncoded());*/


                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(keySize);
                string pubkey = rsa.ToXmlString(false); 
                string prikey = rsa.ToXmlString(true);
                privateKeyString = prikey;
                publicKeyString = pubkey;

            }
            catch (Exception e)
            {
                Logging.warn(string.Format("Exception while generating signature keys: {0}", e.ToString()));
                return false;
            }

            // Generate first stage encryption keys
            try
            {
                ElGamalParametersGenerator pGen = new ElGamalParametersGenerator();

                // Use 512bit key
                pGen.Init(512, 10, new SecureRandom());

                ElGamalParameters elParams = pGen.GenerateParameters();
                if (elParams.L != 0)
                {
                    Logging.warn("ElGamalParametersGenerator failed to set L to 0 in generated ElGamalParameters");
                    return false;
                }

                ElGamalKeyGenerationParameters ekgParams = new ElGamalKeyGenerationParameters(new SecureRandom(), elParams);
                ElGamalKeyPairGenerator kpGen = new ElGamalKeyPairGenerator();

                kpGen.Init(ekgParams);

                AsymmetricCipherKeyPair pair = kpGen.GenerateKeyPair();
                ElGamalPublicKeyParameters pu = (ElGamalPublicKeyParameters)pair.Public;
                ElGamalPrivateKeyParameters pv = (ElGamalPrivateKeyParameters)pair.Private;

                // Serialize keys and convert them to base64 strings
                byte[] serializedKeyPU = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pu).ToAsn1Object().GetDerEncoded();
                encPublicKeyString = Convert.ToBase64String(serializedKeyPU);

                byte[] serializedKeyPV = PrivateKeyInfoFactory.CreatePrivateKeyInfo(pv).ToAsn1Object().GetDerEncoded();
                encPrivateKeyString = Convert.ToBase64String(serializedKeyPV);

            }
            catch (Exception e)
            {
                Logging.warn(string.Format("Exception while generating encryption keys: {0}", e.ToString()));
                return false;
            }


            return true;
        }

        // Generates keys for S2 data encryption
        // Todo: re-design this at a later time
        public List<string> generateEncryptionKeys()
        {
            List<string> keys = new List<string>();
            try
            {
                var rsaKeyParams = new RsaKeyGenerationParameters(BigInteger.ProbablePrime(512, new Random()),
                                                  new SecureRandom(), 1024, 25);
                var keyGen = new RsaKeyPairGenerator();
                keyGen.Init(rsaKeyParams);

                AsymmetricCipherKeyPair key_pair = keyGen.GenerateKeyPair();

                {
                    TextWriter textWriter = new StringWriter();
                    PemWriter pemWriter = new PemWriter(textWriter);
                    pemWriter.WriteObject(key_pair.Public);
                    pemWriter.Writer.Flush();
                    keys.Add(textWriter.ToString());
                }
                {
                    TextWriter textWriter = new StringWriter();
                    PemWriter pemWriter = new PemWriter(textWriter);
                    pemWriter.WriteObject(key_pair.Private);
                    pemWriter.Writer.Flush();
                    keys.Add(textWriter.ToString());
                }


            }
            catch (Exception e)
            {
                Logging.warn(string.Format("Exception while generating encryption keys: {0}", e.ToString()));
            }

            return keys;
        }

        public string getPublicKey()
        {
            return publicKeyString;
        }

        public string getPrivateKey()
        {
            return privateKeyString;
        }

        // Return the first stage encryption public key
        public string getEncPublicKey()
        {
            return encPublicKeyString;
        }

        // Return the first stage encryption private key
        public string getEncPrivateKey()
        {
            return encPrivateKeyString;
        }

        public string getSignature(string text, string privateKey)
        {
            // Dev: for network testing
            //return Crypto.sha256(text);
            try
            {
                var input_data = Encoding.UTF8.GetBytes(text);
                // OLD BC RSA Code
                /*   byte[] privateKeyBytes = Convert.FromBase64String(privateKey);
                   AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory.CreateKey(privateKeyBytes);
                   RsaKeyParameters key = (RsaKeyParameters)asymmetricKeyParameter;

                   ISigner signer = SignerUtilities.GetSigner("SHA256withRSA");

                   signer.Init(true, key);
                   signer.BlockUpdate(input_data, 0, input_data.Length);

                   byte[] signature = signer.GenerateSignature();
                   return Convert.ToBase64String(signature);*/

                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(3072);
                rsa.FromXmlString(privateKey);

                byte[] signature = rsa.SignData(input_data, CryptoConfig.MapNameToOID("SHA512"));
                return Convert.ToBase64String(signature);
            }
            catch (Exception e)
            {
                Logging.warn(string.Format("Cannot generate signature: {0}", e.Message));
            }
            return null;
        }

        public bool verifySignature(string text, string publicKey, string signature)
        {
            // Dev: for network testing
            /*if (Crypto.sha256(text) == signature)
            {
                return true;
            }  
            return false;*/
            try
            {
                var input_data = Encoding.UTF8.GetBytes(text);
                // OLD BC RSA Code
                /*
                                byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
                                AsymmetricKeyParameter asymmetricKeyParameter = PublicKeyFactory.CreateKey(publicKeyBytes);
                                RsaKeyParameters key_parameters = (RsaKeyParameters)asymmetricKeyParameter;

                                ISigner signer = SignerUtilities.GetSigner("SHA256withRSA");

                                signer.Init(false, key_parameters);

                                byte[] signature_bytes = Convert.FromBase64String(signature);               
                                signer.BlockUpdate(input_data, 0, input_data.Length);
                                return signer.VerifySignature(signature_bytes);*/

                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(3072);
                rsa.FromXmlString(publicKey);
                byte[] signature_bytes = Convert.FromBase64String(signature);
                return rsa.VerifyData(input_data, CryptoConfig.MapNameToOID("SHA512"), signature_bytes);
            }
            catch (Exception e)
            {
                Logging.warn(string.Format("Invalid public key {0}:{1}", publicKey, e.Message));
            }
            return false;
        }

        // First stage encryption using ElGamal
        public byte[] encryptData(byte[] data, string publicKey)
        {
            ElGamalPublicKeyParameters pu = (ElGamalPublicKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey));

            ElGamalEngine encryptEngine = new ElGamalEngine();
            encryptEngine.Init(true, new ParametersWithRandom(pu, new SecureRandom()));

            // Check the block size and prepare the byte output
            int blockSize = encryptEngine.GetInputBlockSize();
            List<byte> output = new List<byte>();

            // Split block processing into multiple chunks
            for (int chunkPosition = 0; chunkPosition < data.Length; chunkPosition += blockSize)
            {
                int chunkSize = Math.Min(blockSize, data.Length - ((chunkPosition / blockSize) * blockSize));
                output.AddRange(encryptEngine.ProcessBlock(data, chunkPosition, chunkSize));
            }

            return output.ToArray();
        }

        // First stage decryption using ElGamal
        public byte[] decryptData(byte[] data, string privateKey)
        {
            ElGamalPrivateKeyParameters pv = (ElGamalPrivateKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));

            var decryptEngine = new ElGamalEngine();
            decryptEngine.Init(false, pv);

            // Check the block size and prepare the byte output
            int blockSize = decryptEngine.GetInputBlockSize();
            List<byte> output = new List<byte>();

            // Split block processing into multiple chunks
            for (int chunkPosition = 0; chunkPosition < data.Length; chunkPosition += blockSize)
            {
                int chunkSize = Math.Min(blockSize, data.Length - ((chunkPosition / blockSize) * blockSize));
                output.AddRange(decryptEngine.ProcessBlock(data, chunkPosition, chunkSize));
            }

            return output.ToArray();
        }

        // Encrypt using RSA Asymmetric Encryption, used when transferring messages through S2 nodes
        public byte[] encryptDataS2(byte[] data, string publicKey)
        {
            var encryptEngine = new Pkcs1Encoding(new RsaEngine());

            using (var txtreader = new StringReader(publicKey))
            {
                var keyPair = (AsymmetricKeyParameter)new PemReader(txtreader).ReadObject();
                encryptEngine.Init(true, keyPair);
            }

            // Check the block size and prepare the byte output
            int blockSize = encryptEngine.GetInputBlockSize();
            List<byte> output = new List<byte>();

            // Split block processing into multiple chunks
            for (int chunkPosition = 0; chunkPosition < data.Length; chunkPosition += blockSize)
            {
                int chunkSize = Math.Min(blockSize, data.Length - ((chunkPosition / blockSize) * blockSize));
                output.AddRange(encryptEngine.ProcessBlock(data, chunkPosition, chunkSize));
            }

            return output.ToArray();
        }

        // Decrypt using RSA Asymmetric Encryption, used when transferring messages through S2 nodes
        public byte[] decryptDataS2(byte[] data, string privateKey)
        {
            AsymmetricCipherKeyPair keyPair;
            var decryptEngine = new Pkcs1Encoding(new RsaEngine());

            using (var txtreader = new StringReader(privateKey))
            {
                keyPair = (AsymmetricCipherKeyPair)new PemReader(txtreader).ReadObject();
                decryptEngine.Init(false, keyPair.Private);
            }

            // Check the block size and prepare the byte output
            int blockSize = decryptEngine.GetInputBlockSize();
            List<byte> output = new List<byte>();

            // Split block processing into multiple chunks
            for (int chunkPosition = 0; chunkPosition < data.Length; chunkPosition += blockSize)
            {
                int chunkSize = Math.Min(blockSize, data.Length - ((chunkPosition / blockSize) * blockSize));
                output.AddRange(decryptEngine.ProcessBlock(data, chunkPosition, chunkSize));
            }

            return output.ToArray();
        }

        // Encrypt data using AES
        public byte[] encryptDataAES(byte[] input, byte[] key)
        {
            IBufferedCipher outCipher = CipherUtilities.GetCipher(AES_algorithm);

            int blockSize = outCipher.GetBlockSize();
            // Perform key expansion
            byte[] salt = new byte[blockSize];
            using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
            {
                // Fill the array with a random value.
                rngCsp.GetBytes(salt);
            }

            ParametersWithIV withIV = new ParametersWithIV(new KeyParameter(key), salt);
            try
            {
                outCipher.Init(true, withIV);
            }
            catch (Exception e)
            {
                Logging.error(string.Format("Error initializing encryption. {0}", e.ToString()));
                return null;
            }

            List<byte> bytes = new List<byte>();
            bytes.AddRange(salt);
            bytes.AddRange(outCipher.DoFinal(input));

            return bytes.ToArray();
        }

        // Decrypt data using AES
        public byte[] decryptDataAES(byte[] input, byte [] key, int inOffset = 0)
        {

            IBufferedCipher inCipher = CipherUtilities.GetCipher(AES_algorithm);

            int blockSize = inCipher.GetBlockSize();
            // Perform key expansion
            byte[] salt = new byte[blockSize];

            for (int i = 0; i < blockSize; i++)
            {
                salt[i] = input[inOffset + i];
            }

            ParametersWithIV withIV = new ParametersWithIV(new KeyParameter(key), salt);

            try
            {
                inCipher.Init(false, withIV);
            }
            catch (Exception e)
            {
                Logging.error(string.Format("Error initializing decryption. {0}", e.ToString()));
            }

            byte[] bytes = inCipher.DoFinal(input, inOffset + blockSize, input.Length - inOffset - blockSize);

            return bytes;
        }

        private static byte[] getPbkdf2BytesFromPassphrase(string password, byte[] salt, int iterations, int byteCount)
        {
            var pbkdf2 = new Rfc2898DeriveBytes(password, salt);
            pbkdf2.IterationCount = iterations;
            return pbkdf2.GetBytes(byteCount);
        }

        // Encrypt using password
        public byte[] encryptWithPassword(byte[] data, string password)
        {
            byte[] salt = new byte[16];
            using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
            {
                // Fill the array with a random value.
                rngCsp.GetBytes(salt);
            }
            byte[] key = getPbkdf2BytesFromPassphrase(password, salt, PBKDF2_iterations, 16);
            byte[] ret_data = encryptDataAES(data, key);

            List<byte> tmpList = new List<byte>();
            tmpList.AddRange(salt);
            tmpList.AddRange(ret_data);

            return tmpList.ToArray();
        }

        // Decrypt using password
        public byte[] decryptWithPassword(byte[] data, string password)
        {
            byte[] salt = new byte[16];
            for(int i = 0; i < 16; i++)
            {
                salt[i] = data[i];
            }
            byte[] key = getPbkdf2BytesFromPassphrase(password, salt, PBKDF2_iterations, 16);
            return decryptDataAES(data, key, 16);
        }
    }
}
