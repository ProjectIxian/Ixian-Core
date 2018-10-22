using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DLT
{
    class Address
    {
        public byte[] address;
        private byte[] checksum;

        public Address()
        {
            address = null;
        }

        public Address(byte[] publicKeyOrAddress)
        {
            if (publicKeyOrAddress.Length != 36)
            {
                //  the public key using SHA512 squared truncated
                byte[] hashed_key = new byte[33];
                hashed_key[0] = 0;
                Array.Copy(Crypto.sha512sqTrunc(publicKeyOrAddress), 0, hashed_key, 1, 32);

                checksum = Crypto.sha512(hashed_key);

                address = new byte[hashed_key.Length + 3];
                Array.Copy(hashed_key, address, hashed_key.Length);
                Array.Copy(checksum, 0, address, hashed_key.Length, 3);

                //Mnemonic mnemonic_addr = new Mnemonic(Wordlist.English, Encoding.ASCII.GetBytes(hashed_key.ToString()));
                //address = mnemonic_addr.ToString();
            }
            else
            {
                address = publicKeyOrAddress;
                checksum = address.Skip(33).Take(3).ToArray();
            }
        }

        public override string ToString()
        {
            return Base58Check.Base58CheckEncoding.EncodePlain(address);
        }

        // Validates an address by checking the checksum
        public static bool validateChecksum(byte[] address)
        {
            try
            {
                // Check the address length
                if (address.Length != 36)
                {
                    return false;
                }

                if(address[0] != 0)
                {
                    return false;
                }

                byte[] in_addr = address.Take(33).ToArray();
                byte[] in_chk = address.Skip(33).Take(3).ToArray();

                byte[] checksum = Crypto.sha512(in_addr);
                checksum = checksum.Take(3).ToArray();

                if (checksum.SequenceEqual(in_chk))
                {
                    return true;
                }
            }
            catch(Exception)
            {
                // If any exception occurs, the checksum is invalid
                return false;
            }

            // Checksums don't match
            return false;
        }


    }
}
