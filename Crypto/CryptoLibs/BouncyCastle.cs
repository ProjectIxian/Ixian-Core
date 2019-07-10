using IXICore.Meta;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace IXICore
{
    class BouncyCastle : ICryptoLib
    {
        // Private variables used for AES key expansion
        private int PBKDF2_iterations = 10000;
        private string AES_algorithm = "AES/CBC/PKCS7Padding";

        // Private variables used for Chacha
        private readonly int chacha_rounds = 20;


        public BouncyCastle()
        {
        }

        private byte[] rsaKeyToBytes(RSACryptoServiceProvider rsaKey, bool includePrivateParameters, bool skip_header)
        {
            List<byte> bytes = new List<byte>();

            RSAParameters rsaParams = rsaKey.ExportParameters(includePrivateParameters);

            // TODO TODO TODO TODO TODO skip header can be later removed after the upgrade/hard fork
            if (!skip_header)
            {
                bytes.Add((byte)1); // add version
                bytes.AddRange(BitConverter.GetBytes((int)0)); // prepend pub key version
            }

            bytes.AddRange(BitConverter.GetBytes(rsaParams.Modulus.Length));
            bytes.AddRange(rsaParams.Modulus);
            bytes.AddRange(BitConverter.GetBytes(rsaParams.Exponent.Length));
            bytes.AddRange(rsaParams.Exponent);
            if (includePrivateParameters)
            {
                bytes.AddRange(BitConverter.GetBytes(rsaParams.P.Length));
                bytes.AddRange(rsaParams.P);
                bytes.AddRange(BitConverter.GetBytes(rsaParams.Q.Length));
                bytes.AddRange(rsaParams.Q);
                bytes.AddRange(BitConverter.GetBytes(rsaParams.DP.Length));
                bytes.AddRange(rsaParams.DP);
                bytes.AddRange(BitConverter.GetBytes(rsaParams.DQ.Length));
                bytes.AddRange(rsaParams.DQ);
                bytes.AddRange(BitConverter.GetBytes(rsaParams.InverseQ.Length));
                bytes.AddRange(rsaParams.InverseQ);
                bytes.AddRange(BitConverter.GetBytes(rsaParams.D.Length));
                bytes.AddRange(rsaParams.D);
            }

            return bytes.ToArray();
        }

        private RSACryptoServiceProvider rsaKeyFromBytes(byte [] keyBytes)
        {
            try
            {
                RSAParameters rsaParams = new RSAParameters();

                int offset = 0;
                int dataLen = 0;
                int version = 0;

                if(keyBytes.Length != 523 && keyBytes.Length != 2339)
                {
                    offset += 1; // skip address version
                    version = BitConverter.ToInt32(keyBytes, offset);
                    offset += 4;
                    
                }

                dataLen = BitConverter.ToInt32(keyBytes, offset);
                offset += 4;
                rsaParams.Modulus = new byte[dataLen];
                Array.Copy(keyBytes, offset, rsaParams.Modulus, 0, dataLen);
                offset += dataLen;

                dataLen = BitConverter.ToInt32(keyBytes, offset);
                offset += 4;
                rsaParams.Exponent = new byte[dataLen];
                Array.Copy(keyBytes, offset, rsaParams.Exponent, 0, dataLen);
                offset += dataLen;

                if (keyBytes.Length > offset)
                {
                    dataLen = BitConverter.ToInt32(keyBytes, offset);
                    offset += 4;
                    rsaParams.P = new byte[dataLen];
                    Array.Copy(keyBytes, offset, rsaParams.P, 0, dataLen);
                    offset += dataLen;

                    dataLen = BitConverter.ToInt32(keyBytes, offset);
                    offset += 4;
                    rsaParams.Q = new byte[dataLen];
                    Array.Copy(keyBytes, offset, rsaParams.Q, 0, dataLen);
                    offset += dataLen;

                    dataLen = BitConverter.ToInt32(keyBytes, offset);
                    offset += 4;
                    rsaParams.DP = new byte[dataLen];
                    Array.Copy(keyBytes, offset, rsaParams.DP, 0, dataLen);
                    offset += dataLen;

                    dataLen = BitConverter.ToInt32(keyBytes, offset);
                    offset += 4;
                    rsaParams.DQ = new byte[dataLen];
                    Array.Copy(keyBytes, offset, rsaParams.DQ, 0, dataLen);
                    offset += dataLen;

                    dataLen = BitConverter.ToInt32(keyBytes, offset);
                    offset += 4;
                    rsaParams.InverseQ = new byte[dataLen];
                    Array.Copy(keyBytes, offset, rsaParams.InverseQ, 0, dataLen);
                    offset += dataLen;

                    dataLen = BitConverter.ToInt32(keyBytes, offset);
                    offset += 4;
                    rsaParams.D = new byte[dataLen];
                    Array.Copy(keyBytes, offset, rsaParams.D, 0, dataLen);
                    offset += dataLen;
                }

                RSACryptoServiceProvider rcsp = new RSACryptoServiceProvider();
                rcsp.ImportParameters(rsaParams);
                return rcsp;
            }catch(Exception e)
            {
                Logging.warn(String.Format("An exception occured while trying to reconstruct PKI from bytes: {0}", e.Message));
            }
            return null;
        }

        public bool testKeys(byte[] plain, IxianKeyPair key_pair)
        {
            Logging.info("Testing generated keys.");
            // Try if RSACryptoServiceProvider considers them a valid key
            if(rsaKeyFromBytes(key_pair.privateKeyBytes) == null)
            {
                Logging.warn("RSA key is considered invalid by RSACryptoServiceProvider!");
                return false;
            }

            byte[] encrypted = encryptWithRSA(plain, key_pair.publicKeyBytes);
            byte[] signature = getSignature(plain, key_pair.privateKeyBytes);

            if (!decryptWithRSA(encrypted, key_pair.privateKeyBytes).SequenceEqual(plain))
            {
                Logging.warn(string.Format("Error decrypting data while testing keys."));
                return false;
            }

            if (!verifySignature(plain, key_pair.publicKeyBytes, signature))
            {
                Logging.warn(string.Format("Error verifying signature while testing keys."));
                return false;
            }


            return true;
        }

        // Generates keys for RSA signing
        public IxianKeyPair generateKeys(int keySize, bool skip_header = false)
        {
            try
            {
                IxianKeyPair kp = new IxianKeyPair();
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(keySize);
                kp.privateKeyBytes = rsaKeyToBytes(rsa, true, skip_header);
                kp.publicKeyBytes = rsaKeyToBytes(rsa, false, skip_header);

                byte[] plain = Encoding.UTF8.GetBytes("Plain text string");
                if (!testKeys(plain, kp))
                {
                    return null;
                }
                return kp;
            }
            catch (Exception e)
            {
                Logging.warn(string.Format("Exception while generating signature keys: {0}", e.ToString()));
                return null;
            }
        }

        public byte[] getSignature(byte[] input_data, byte[] privateKey)
        {
            try
            {
                RSACryptoServiceProvider rsa = rsaKeyFromBytes(privateKey);

                byte[] signature = rsa.SignData(input_data, CryptoConfig.MapNameToOID("SHA512"));
                return signature;
            }
            catch (Exception e)
            {
                Logging.warn(string.Format("Cannot generate signature: {0}", e.Message));
            }
            return null;
        }

        public bool verifySignature(byte[] input_data, byte[] publicKey, byte[] signature)
        {
            try
            {

                RSACryptoServiceProvider rsa = rsaKeyFromBytes(publicKey);

                byte[] signature_bytes = signature;
                return rsa.VerifyData(input_data, CryptoConfig.MapNameToOID("SHA512"), signature_bytes);
            }
            catch (Exception e)
            {
                Logging.warn(string.Format("Invalid public key {0}:{1}", publicKey, e.Message));
            }
            return false;
        }

        // Encrypt data using RSA
        public byte[] encryptWithRSA(byte[] input, byte[] publicKey)
        {
            RSACryptoServiceProvider rsa = rsaKeyFromBytes(publicKey);
            return rsa.Encrypt(input, false);
        }


        // Decrypt data using RSA
        public byte[] decryptWithRSA(byte[] input, byte[] privateKey)
        {
            RSACryptoServiceProvider rsa = rsaKeyFromBytes(privateKey);
            return rsa.Decrypt(input, false);
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

        // Encrypt data using Chacha engine
        public byte[] encryptWithChacha(byte[] input, byte[] key)
        {
            // Create a buffer that will contain the encrypted output and an 8 byte nonce
            byte[] outData = new byte[input.Length + 8];

            // Generate the 8 byte nonce
            byte[] nonce = new byte[8];

            using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
            {
                // Fill the array with a random value.
                rngCsp.GetBytes(nonce);
            }

            // Prevent leading 0 to avoid edge cases
            if (nonce[0] == 0)
                nonce[0] = 1;
            
            // Generate the Chacha engine
            var parms = new ParametersWithIV(new KeyParameter(key), nonce);
            var chacha = new ChaChaEngine(chacha_rounds);
            
            try
            {
                chacha.Init(true, parms);
            }
            catch (Exception e)
            {
                Logging.error(string.Format("Error in chacha encryption. {0}", e.ToString()));
                return null;
            }

            // Encrypt the input data while maintaing an 8 byte offset at the start
            chacha.ProcessBytes(input, 0, input.Length, outData, 8);

            // Copy the 8 byte nonce to the start of outData buffer
            Buffer.BlockCopy(nonce, 0, outData, 0, 8);

            // Return the encrypted data buffer
            return outData;
        }

        // Decrypt data using Chacha engine
        public byte[] decryptWithChacha(byte[] input, byte[] key)
        {
            // Extract the nonce from the input
            byte[] nonce = input.Take(8).ToArray();

            // Generate the Chacha engine
            var parms = new ParametersWithIV(new KeyParameter(key), nonce);
            var chacha = new ChaChaEngine(chacha_rounds);
            try
            {
                chacha.Init(false, parms);
            }
            catch (Exception e)
            {
                Logging.error(string.Format("Error in chacha decryption. {0}", e.ToString()));
                return null;
            }

            // Create a buffer that will contain the decrypted output
            byte[] outData = new byte[input.Length - 8];

            // Decrypt the input data
            chacha.ProcessBytes(input, 8, input.Length - 8, outData, 0);

            // Return the decrypted data buffer
            return outData;
        }

        public byte[] generateChildKey(byte[] parentKey, int seed = 0)
        {
            RSACryptoServiceProvider origRsa = rsaKeyFromBytes(parentKey);
            if(origRsa.PublicOnly)
            {
                Logging.error("Child key cannot be generated from a public key! Private key is also required.");
                return null;
            }
            RSAParameters origKey = origRsa.ExportParameters(true);
            RsaKeyPairGenerator kpGenerator = new RsaKeyPairGenerator();
            int seed_len = origKey.P.Length + origKey.Q.Length;
            if (seed != 0)
            {
                seed_len += 4;
            }
            byte[] child_seed = new byte[seed_len];
            Array.Copy(origKey.P, 0, child_seed, 0, origKey.P.Length);
            Array.Copy(origKey.Q, 0, child_seed, origKey.P.Length, origKey.Q.Length);
            if(seed != 0)
            {
                Array.Copy(BitConverter.GetBytes(seed), 0, child_seed, origKey.P.Length + origKey.Q.Length, 4);
            }

            Org.BouncyCastle.Crypto.Digests.Sha512Digest key_digest = new Org.BouncyCastle.Crypto.Digests.Sha512Digest();
            Org.BouncyCastle.Crypto.Prng.DigestRandomGenerator digest_rng = new Org.BouncyCastle.Crypto.Prng.DigestRandomGenerator(key_digest);
            digest_rng.AddSeedMaterial(child_seed);
            // TODO: Check if certainty of 80 is good enough for us
            RsaKeyGenerationParameters keyParams = new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), new SecureRandom(digest_rng), 4096, 80);
            RsaKeyPairGenerator keyGen = new RsaKeyPairGenerator();
            keyGen.Init(keyParams);
            AsymmetricCipherKeyPair keyPair = keyGen.GenerateKeyPair();
            //
            RSACryptoServiceProvider newRsa = (RSACryptoServiceProvider)DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)keyPair.Private);
            return rsaKeyToBytes(newRsa, true, false);
        }

    }
}
