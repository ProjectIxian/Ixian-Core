using DLT;
using DLT.Meta;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace IXICore.CryptoKey
{
    /// <summary>
    /// Class is able to deterministically generate child RSA keys from a pool of random data.
    /// Note: Please do not put this into production until a crypto-expert takes a look at it. This falls under the heading "Roll your own crypto".
    /// The problem is that C# and Java (android) - and possibly iOS - implementations do not provide a way to do this. In some cases it's possible to
    /// substitute the random generator for something like Sha512/t digest, but the core RSA generation algorithm is implemented differently. That means
    /// generating RSA keys from the same starting point would yield different results on different platforms.
    /// Furthermore, implementations may change in the future, which would break all key derivation.
    /// I see no other way than to implement this ourselves, so that we have control over when we change it and appropriately handle legacy cases.
    /// </summary>
    public class KeyDerivation
    {
        class PRNG
        {
            // Entropy source
            byte[] initialRandomState;
            byte[] currentRandomState;
            int currentIteration;
            SHA512Managed sha;
            //
            public PRNG(byte[] random_state)
            {
                int total_len = random_state.Length;
                if(total_len % 64 != 0)
                {
                    throw new Exception("Random data must be divisible by the PRNG block size (64).");
                }
                initialRandomState = new byte[total_len];
                currentRandomState = new byte[total_len];
                Array.Copy(random_state, initialRandomState, total_len);
                Array.Copy(random_state, currentRandomState, total_len);
                currentIteration = 0;
                //
                sha = new SHA512Managed();
                sha.Initialize();
            }

            private void twiddleRandomState()
            {
                int blocks = currentRandomState.Length / 64;
                // each 64-byte region separately
                for (int i = 0; i < blocks; i++)
                {
                    Array.Copy(sha.ComputeHash(currentRandomState, i * 64, 64), 0, currentRandomState, i * 64, 64);
                }
                currentIteration += 1;
            }

            public void setIteration(int iteration)
            {
                if(iteration<0)
                {
                    Logging.error(String.Format("Attempted to set a negative iteration on the internal state: {0}", iteration));
                    iteration = 0;
                }
                if(iteration<currentIteration)
                {
                    Array.Copy(initialRandomState, currentRandomState, initialRandomState.Length);
                    currentIteration = 0;
                }
                while(currentIteration < iteration)
                {
                    twiddleRandomState();
                }
            }

            public byte[] getRandomState()
            {
                return currentRandomState;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct IXI_RSA_KEY
        {
            public uint len;
            public IntPtr data;
        }


        private PRNG RandomSource;

        public KeyDerivation(byte[] entropy)
        {
            RandomSource = new PRNG(entropy);
        }

        private IxianKeyPair buildIxianKeyPair(byte[] rsa_key)
        {
            IxianKeyPair kp = new IxianKeyPair();
            AsnKeyParser parser = new AsnKeyParser(rsa_key);
            RSAParameters rsaParams = parser.ParseRSAPrivateKey();
            List<byte> pubKey = new List<byte>();

            pubKey.AddRange(BitConverter.GetBytes(rsaParams.Modulus.Length));
            pubKey.AddRange(rsaParams.Modulus);
            pubKey.AddRange(BitConverter.GetBytes(rsaParams.Exponent.Length));
            pubKey.AddRange(rsaParams.Exponent);
            kp.publicKeyBytes = pubKey.ToArray();

            List<byte> privKey = new List<byte>();
            privKey.AddRange(BitConverter.GetBytes(rsaParams.Modulus.Length));
            privKey.AddRange(rsaParams.Modulus);
            privKey.AddRange(BitConverter.GetBytes(rsaParams.Exponent.Length));
            privKey.AddRange(rsaParams.Exponent);
            privKey.AddRange(BitConverter.GetBytes(rsaParams.P.Length));
            privKey.AddRange(rsaParams.P);
            privKey.AddRange(BitConverter.GetBytes(rsaParams.Q.Length));
            privKey.AddRange(rsaParams.Q);
            privKey.AddRange(BitConverter.GetBytes(rsaParams.DP.Length));
            privKey.AddRange(rsaParams.DP);
            privKey.AddRange(BitConverter.GetBytes(rsaParams.DQ.Length));
            privKey.AddRange(rsaParams.DQ);
            privKey.AddRange(BitConverter.GetBytes(rsaParams.InverseQ.Length));
            privKey.AddRange(rsaParams.InverseQ);
            privKey.AddRange(BitConverter.GetBytes(rsaParams.D.Length));
            privKey.AddRange(rsaParams.D);
            kp.privateKeyBytes = privKey.ToArray();

            return kp;
        }

        [DllImport("IXICrypt.dll", CallingConvention = CallingConvention.Cdecl)]
        static extern IntPtr ix_generate_rsa(IntPtr entropy, uint entropy_len, int key_size_bits, ulong pub_exponent);

        [DllImport("IXICrypt.dll", CallingConvention = CallingConvention.Cdecl)]
        static extern void ix_free_key(IntPtr key);


        public IxianKeyPair deriveKey(int key_index, int key_length, ulong public_exponent)
        {
            DateTime start = DateTime.Now;
            RandomSource.setIteration(key_index);
            byte[] entropy = RandomSource.getRandomState();
            IntPtr c_entropy = Marshal.AllocHGlobal(entropy.Length);
            Marshal.Copy(entropy, 0, c_entropy, entropy.Length);
            IntPtr c_rsa_key = ix_generate_rsa(c_entropy, (uint)entropy.Length, key_length, public_exponent);
            IXI_RSA_KEY rsa_key = (IXI_RSA_KEY)Marshal.PtrToStructure(c_rsa_key, typeof(IXI_RSA_KEY));
            byte[] returned_key = new byte[rsa_key.len];
            Marshal.Copy(rsa_key.data, returned_key, 0, (int)rsa_key.len);
            Marshal.FreeHGlobal(c_entropy);
            ix_free_key(c_rsa_key);
            Console.WriteLine(String.Format("Duration: {0} ms.", (DateTime.Now - start).TotalMilliseconds));
            //
            // returned_key is in pkcs #1 format
            return buildIxianKeyPair(returned_key);            
        }

        public static byte[] getNewRandomSeed(int seed_len)
        {
            byte[] entropy = new byte[seed_len];
            System.Security.Cryptography.RNGCryptoServiceProvider rngCSP = new System.Security.Cryptography.RNGCryptoServiceProvider();
            rngCSP.GetBytes(entropy);
            return entropy;
        }

        public static void BenchmarkKeyGeneration(int num_iterations, int key_size)
        {
            // Testing some key generation features
            Logging.info("Preparing entropy to benchmark key generation speed...");
            byte[] entropy = getNewRandomSeed(1024 * 1024);
            IXICore.CryptoKey.KeyDerivation kd = new IXICore.CryptoKey.KeyDerivation(entropy);
            DLT.CryptoManager.initLib();
            Logging.info(String.Format("Starting key generation. Iterations: {0}", num_iterations));
            for (int i = 0; i < num_iterations; i++)
            {
                DateTime start = DateTime.Now;
                Logging.info(String.Format("Generating key {0}...", i));
                IxianKeyPair kp = kd.deriveKey(i, key_size, 65537);
                Logging.info(String.Format("Key generated. ({0:0.00} ms)",
                    (DateTime.Now-start).TotalMilliseconds));
                bool success = DLT.CryptoManager.lib.testKeys(Encoding.Unicode.GetBytes("TEST TEST"), kp);
                Logging.info(String.Format("Key test: {0}", success ? "success" : "failure"));
            }
            return;

        }
    }
}
