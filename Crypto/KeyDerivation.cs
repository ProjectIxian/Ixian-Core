using DLT.Meta;
using System;
using System.Collections.Generic;
using System.Linq;
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
            // Key size: 32B
            // Block size: 16B
            byte[] currentRandomBlock;
            int positionInBlock; // for reading random bytes
            byte[] passwordHash; // password is hashed down to 12B
            uint counter = 0; // counter is increased for each encrypt operation
            int keyIndex = 0; // n-th splice of 'currentRandomState'
            AesManaged aes;
            // stats
            public ulong rngBytesRead { get; private set; }

            public PRNG(byte[] random_state, string password)
            {
                int total_len = random_state.Length;
                if(total_len % 32 != 0)
                {
                    throw new Exception("Random data must be divisible by the PRNG block size (32).");
                }
                initialRandomState = new byte[total_len];
                currentRandomState = new byte[total_len];
                Array.Copy(random_state, initialRandomState, total_len);
                Array.Copy(random_state, currentRandomState, total_len);
                currentIteration = 0;
                //
                sha = new SHA512Managed();
                sha.Initialize();
                byte[] pwd_bytes = Encoding.Unicode.GetBytes(password);
                passwordHash = sha.ComputeHash(pwd_bytes).Take(12).ToArray();
                sha.Initialize();
                //
                aes = new AesManaged();
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
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
                // generate at least the first random block
                rngBytesRead = 0;
                getNextRandomBlock();
            }

            private void getNextRandomBlock()
            {
                byte[] ency_block = new byte[16];
                Array.Copy(passwordHash, 0, ency_block, 0, 12);
                byte[] counter_data = BitConverter.GetBytes(counter);
                Array.Copy(counter_data, 0, ency_block, 12, 4);
                byte[] iv = new byte[16]; // IV is zero
                byte[] key = new byte[32];
                if(keyIndex*32 >= currentRandomState.Length)
                {
                    keyIndex = 0;
                }
                Array.Copy(currentRandomState, keyIndex * 32, key, 0, 32);
                ICryptoTransform crypt = aes.CreateEncryptor(key, iv);
                currentRandomBlock = crypt.TransformFinalBlock(ency_block, 0, 16);
                positionInBlock = 0;
                // bookkeeping
                keyIndex += 1;
                counter += 1;
            }


            public byte NextByte()
            {
                if(positionInBlock >= 16)
                {
                    getNextRandomBlock();
                }
                rngBytesRead++;
                return currentRandomBlock[positionInBlock++];
            }

            public byte[] NextBytes(int num_bytes)
            {
                byte[] output = new byte[num_bytes];
                int written = 0;
                while(written < num_bytes)
                {
                    if(positionInBlock >= 16)
                    {
                        getNextRandomBlock();
                    }
                    int avail = 16 - positionInBlock;
                    int to_copy = 0;
                    if(avail >= (num_bytes-written))
                    {
                        to_copy = (num_bytes-written);
                    } else
                    {
                        to_copy = avail;
                    }
                    Array.Copy(currentRandomBlock, positionInBlock, output, written, to_copy);
                    written += to_copy;
                    positionInBlock += to_copy;
                }
                rngBytesRead += (ulong)output.Length;
                return output;
            }
        }

        private PRNG RandomSource;
        private int statPrimeChecks;
        private int statNumGens;

        public KeyDerivation(byte[] entropy, string password)
        {
            RandomSource = new PRNG(entropy, password);
        }

        private void clearStats()
        {
            statNumGens = 0;
            statPrimeChecks = 0;
        }

        private BigInteger RandomPrime(int bit_len, BigInteger public_exp)
        {
            while (true) {
                BigInteger candidate;
                BigInteger One = new BigInteger(1);
                while (true)
                {
                    int needed_bytes = (bit_len / 8) + 1;
                    byte[] value = RandomSource.NextBytes(needed_bytes);
                    // leading byte - this is to ensure an appropriate bit length
                    int rem = bit_len % 8;
                    if (rem == 0)
                    {
                        value[needed_bytes - 2] |= 0x80;
                        value[needed_bytes - 1] = 0x00;
                    } else
                    {
                        value[needed_bytes - 1] |= (byte)(1 << (rem - 1));
                    }
                    // lowest bit should be 1, so we assure an odd number
                    value[0] |= 0x01;
                    value = value.Reverse().ToArray();
                    candidate = new BigInteger(value);
                    statPrimeChecks++;
                    if (candidate.isProbablePrime())
                    {
                        break;
                    }
                    /*for(int i=1;i<value.Length-1;i++)
                    {
                        value[i] ^= RandomSource.NextByte();
                        candidate = new BigInteger(value);
                        statPrimeChecks++;
                        if (candidate.isProbablePrime())
                        {
                            break;
                        }
                    }*/
                }
                // at this point, the number passed the Miller-Rabin test and is a probable prime
                // Sanity checks
                if (candidate % public_exp == One)
                {
                    continue;
                }
                BigInteger gcd = (candidate - 1).gcd(public_exp);
                if(gcd != One)
                {
                    // public_exp and Q-1 (or P-1) should be relatively prime
                    continue;
                }
                statNumGens++;
                return candidate;
            }
        }

        private byte[] buildIXIANKey(BigInteger modulus, BigInteger public_exp, BigInteger P, BigInteger Q, BigInteger DP, BigInteger DQ, BigInteger InvQ, BigInteger D)
        {
            List<byte> bytes = new List<byte>();
            byte[] mod_bytes = modulus.getBytes();
            bytes.AddRange(BitConverter.GetBytes(mod_bytes.Length));
            bytes.AddRange(mod_bytes);

            byte[] exp_bytes = public_exp.getBytes();
            bytes.AddRange(BitConverter.GetBytes(exp_bytes.Length));
            bytes.AddRange(exp_bytes);
            //
            byte[] p_bytes = P.getBytes();
            bytes.AddRange(BitConverter.GetBytes(p_bytes.Length));
            bytes.AddRange(p_bytes);

            byte[] q_bytes = Q.getBytes();
            bytes.AddRange(BitConverter.GetBytes(q_bytes.Length));
            bytes.AddRange(q_bytes);

            byte[] dp_bytes = DP.getBytes();
            bytes.AddRange(BitConverter.GetBytes(dp_bytes.Length));
            bytes.AddRange(dp_bytes);

            byte[] dq_bytes = DQ.getBytes();
            bytes.AddRange(BitConverter.GetBytes(dq_bytes.Length));
            bytes.AddRange(dq_bytes);

            byte[] qinv_bytes = InvQ.getBytes();
            bytes.AddRange(BitConverter.GetBytes(qinv_bytes.Length));
            bytes.AddRange(qinv_bytes);

            byte[] d_bytes = D.getBytes();
            bytes.AddRange(BitConverter.GetBytes(d_bytes.Length));
            bytes.AddRange(d_bytes);
            //
            return bytes.ToArray();
        }

        public byte[] deriveKey(int key_index, int key_length, ulong public_exponent)
        {
            clearStats();
            // put the random source into appropriate state
            RandomSource.setIteration(key_index);
            BigInteger public_exp = new BigInteger(public_exponent);

            int p_len = (key_length + 1) / 2;
            int q_len = key_length - p_len;

            BigInteger P = RandomPrime(p_len, public_exp);
            BigInteger minDifference = new BigInteger("10000000000", 10);

            while(true)
            {
                BigInteger Q = RandomPrime(q_len, public_exp);
                BigInteger diff = (P - Q).abs();
                // primes should not be too near each other, otherwise vulnerable to Fermat factoring (http://deweger.xs4all.nl/papers/%5b33%5ddW-SmlPrDif-AAECC%5b2002%5d.pdf)
                if (diff < minDifference)
                {
                    continue;
                }
                BigInteger modulus = P * Q;
                if(modulus.bitCount() != key_length)
                {
                    // retry - we want exactly the same bit length as requested
                    P = P.max(Q);
                    continue;
                }
                // TODO: Possibly NAF check
                // P should be the larger prime, by convention
                if(P < Q)
                {
                    BigInteger tmp = P;
                    P = Q;
                    Q = tmp;
                }
                BigInteger P_s1 = P - 1;
                BigInteger Q_s1 = Q - 1;
                BigInteger gcd = P_s1.gcd(Q_s1);
                BigInteger lcm = (P_s1 / gcd) * Q_s1;

                // private exponent
                BigInteger d = public_exp.modInverse(lcm);
                // should be large enough
                if(d.bitCount() <= q_len)
                {
                    continue;
                }

                // CRT factors
                BigInteger dP = d % P_s1;
                BigInteger dQ = d % Q_s1;
                BigInteger qInv = Q.modInverse(P);
                Logging.info(String.Format("Key generated, numbers: {0}, prime checks: {1}, entropy bytes read: {2}",
                    statNumGens, statPrimeChecks, RandomSource.rngBytesRead));
                // Return values
                return buildIXIANKey(modulus, public_exp, P, Q, dP, dQ, qInv, d);
            }
        }

        public static void BenchmarkKeyGeneration(int num_iterations, int key_size)
        {
            // Testing some key generation features
            Logging.info("Preparing entropy to benchmark key generation speed...");
            byte[] entropy = new byte[16 * 1024];
            System.Security.Cryptography.RNGCryptoServiceProvider rngCSP = new System.Security.Cryptography.RNGCryptoServiceProvider();
            rngCSP.GetBytes(entropy);
            IXICore.CryptoKey.KeyDerivation kd = new IXICore.CryptoKey.KeyDerivation(entropy, "IXIAN");
            DLT.CryptoManager.initLib();
            Logging.info(String.Format("Starting key generation. Iterations: {0}", num_iterations));
            for (int i = 0; i < num_iterations; i++)
            {
                DateTime start = DateTime.Now;
                Logging.info(String.Format("Generating key {0}...", i));
                byte[] ixi_key = kd.deriveKey(i, key_size, 65537);
                Logging.info(String.Format("Key generated. ({0:0.00} ms)",
                    (DateTime.Now-start).TotalMilliseconds));
                DLT.CryptoManager.lib.importKeys(ixi_key);
                bool success = DLT.CryptoManager.lib.testKeys(Encoding.Unicode.GetBytes("TEST TEST"));
                Logging.info(String.Format("Key test: {0}", success ? "success" : "failure"));
            }
            return;

        }
    }
}
