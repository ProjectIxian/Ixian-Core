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

namespace CryptoLibs
{
    class BouncyCastle : ICryptoLib
    {
        string publicKeyString;
        string privateKeyString;

        string encPublicKeyString;
        string encPrivateKeyString;

        // Private variables used for AES key expansion
        private string PBKDF2_DERIVATION = "PBKDF2WithHmacSHA1";
        private int iteration_count = 10000;
        private int key_length = 256;
        private int salt_length = 8;
        private string delimiter = ":";

        // Cache for signature
        private ISigner signer = null;
        private X9ECParameters curve = null;
        private ECDomainParameters curve_spec = null;


        public BouncyCastle()
        {
            publicKeyString = "";
            privateKeyString = "";

            encPublicKeyString = "";
            encPrivateKeyString = "";

            // Prepare the signature cache
            signer = SignerUtilities.GetSigner("ECDSA");
            curve = SecNamedCurves.GetByName("secp256k1");
            curve_spec = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
        }

        // Generates keys for secp256k1 ECDSA signing
        public bool generateKeys()
        {
            try
            {
                // Generate a secp256k1 ECDSA keypair
                X9ECParameters curve = SecNamedCurves.GetByName("secp256k1");
                ECDomainParameters curveSpec = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
                IAsymmetricCipherKeyPairGenerator generator = GeneratorUtilities.GetKeyPairGenerator("ECDSA");
                generator.Init(new ECKeyGenerationParameters(curveSpec, new SecureRandom()));

                AsymmetricCipherKeyPair key_pair = generator.GenerateKeyPair();

                // Store the private and public keys as base64-encoded strings
                byte[] serialized_private_bytes = ((ECPrivateKeyParameters)key_pair.Private).D.ToByteArray();
                privateKeyString = Convert.ToBase64String(serialized_private_bytes);

                byte[] serialized_public_bytes = ((ECPublicKeyParameters)key_pair.Public).Q.GetEncoded();
                publicKeyString = Convert.ToBase64String(serialized_public_bytes);

            }
            catch(Exception e)
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
            catch(Exception e)
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
            try
            {
                var input_data = Encoding.UTF8.GetBytes(text);
                var signer = SignerUtilities.GetSigner("ECDSA");

                BigInteger biPrivateKey = new BigInteger(Convert.FromBase64String(privateKey));
                ECPrivateKeyParameters key_parameters = new ECPrivateKeyParameters(biPrivateKey, curve_spec);

                signer.Init(true, key_parameters);
                signer.BlockUpdate(input_data, 0, input_data.Length);

                byte[] signature = signer.GenerateSignature();
                return Convert.ToBase64String(signature);
            }
            catch (Exception)
            {
                Logging.warn("Cannot generate signature");
            }
            return null;
        }

        public bool verifySignature(string text, string publicKey, string signature)
        {
            try
            {
                var input_data = Encoding.UTF8.GetBytes(text);

                ECCurve ecurve = curve_spec.Curve;
                ECPoint epoint = ecurve.DecodePoint(Convert.FromBase64String(publicKey));
                ECPublicKeyParameters key_parameters = new ECPublicKeyParameters(epoint, curve_spec);

                signer.Init(false, key_parameters);
                signer.BlockUpdate(input_data, 0, input_data.Length);

                byte[] signature_bytes = Convert.FromBase64String(signature);
                return signer.VerifySignature(signature_bytes);
            }
            catch(Exception)
            {
                Logging.warn(string.Format("Invalid public key for {0}", publicKey));
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
        public byte[] encryptDataAES(byte[] input, string key)
        {
            // Perform key expansion
            byte[] salt = new byte[salt_length];
            
            Asn1Encodable defParams = PbeUtilities.GenerateAlgorithmParameters("PBEWithSHA256And256BitAES-CBC-BC", salt, iteration_count);
            char[] password = key.ToCharArray();
            IWrapper wrapper = WrapperUtilities.GetWrapper("AES/CBC/PKCS5Padding");
            ICipherParameters parameters = PbeUtilities.GenerateCipherParameters("PBEWithSHA256And256BitAES-CBC-BC", password, defParams);
            wrapper.Init(true, parameters);

            byte[] keyText = wrapper.Wrap(Encoding.UTF8.GetBytes(key), 0, Encoding.UTF8.GetBytes(key).Length);

            KeyParameter keyp = ParameterUtilities.CreateKeyParameter("AES", keyText);
            IBufferedCipher outCipher = CipherUtilities.GetCipher("AES/CBC/PKCS5Padding");

            try
            {
                outCipher.Init(true, keyp);
            }
            catch (Exception e)
            {
                Logging.error(string.Format("Error initializing encryption. {0}", e.ToString()));
                return null;
            }

            MemoryStream bOut = new MemoryStream();
            CipherStream cOut = new CipherStream(bOut, null, outCipher);
            try
            {
                for (int i = 0; i < input.Length; i++)
                {
                    cOut.WriteByte(input[i]);
                }
                cOut.Close();
            }
            catch (IOException e)
            {
                Logging.error(string.Format("Error encrypting data. {0}", e.ToString()));
            }

            byte[] bytes = bOut.ToArray();

            return bytes;
        }

        // Decrypt data using AES
        public byte[] decryptDataAES(byte[] input, string key)
        {
            byte[] salt = new byte[salt_length];

            Asn1Encodable defParams = PbeUtilities.GenerateAlgorithmParameters("PBEWithSHA256And256BitAES-CBC-BC", salt, iteration_count);
            char[] password = key.ToCharArray();
            IWrapper wrapper = WrapperUtilities.GetWrapper("AES/CBC/PKCS5Padding");
            ICipherParameters parameters = PbeUtilities.GenerateCipherParameters("PBEWithSHA256And256BitAES-CBC-BC", password, defParams);
            wrapper.Init(true, parameters);
            byte[] keyText = wrapper.Wrap(Encoding.UTF8.GetBytes(key), 0, Encoding.UTF8.GetBytes(key).Length);

            KeyParameter keyp = ParameterUtilities.CreateKeyParameter("AES", keyText);
            IBufferedCipher inCipher = CipherUtilities.GetCipher("AES/CBC/PKCS5Padding");

            try
            {
                inCipher.Init(false, keyp);
            }
            catch (Exception e)
            {
                Logging.error(string.Format("Error initializing decryption. {0}", e.ToString()));
            }

            MemoryStream bIn = new MemoryStream(input, false);
            CipherStream cIn = new CipherStream(bIn, inCipher, null);
            byte[] bytes = null;

            try
            {
                BinaryReader dIn = new BinaryReader(cIn);

                bytes = new byte[input.Length];

                for (int i = 0; i < input.Length; i++)
                {
                    bytes[i] = dIn.ReadByte();
                }
            }
            catch(EndOfStreamException)
            {
                // TODO: handle this case and the different stream size when encrypted.
            }
            catch (Exception e)
            {
                //Logging.error(string.Format("Error decrypting data. {0}", e.ToString()));
                throw e;
            }

            return bytes;
        }

    }
}
