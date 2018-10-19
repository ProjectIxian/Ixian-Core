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

        public Address(byte[] public_key)
        {
            //  the public key using SHA256 
            byte[] hashed_key = Crypto.sha256(public_key);

            checksum = Crypto.sha256(hashed_key);

            address = new byte[hashed_key.Length + 2];
            Array.Copy(hashed_key, address, hashed_key.Length);
            Array.Copy(checksum, 0, address, hashed_key.Length, 2);

            //Mnemonic mnemonic_addr = new Mnemonic(Wordlist.English, Encoding.ASCII.GetBytes(hashed_key.ToString()));
            //address = mnemonic_addr.ToString();

        }

        public override string ToString()
        {
            return Crypto.hashToString(address);
        }

        // Validates an address by checking the checksum
        public static bool validateChecksum(byte[] address)
        {
            try
            {
                // Check the address length
                if (address.Length != 34)
                {
                    return false;
                }

                byte[] in_addr = address.Take(32).ToArray();
                byte[] in_chk = address.Skip(32).Take(2).ToArray();

                byte[] checksum = Crypto.sha256(in_addr);
                checksum = checksum.Take(2).ToArray();

                if (checksum.SequenceEqual(in_chk))
                {
                    return true;
                }
            }
            catch(Exception e)
            {
                // If any exception occurs, the checksum is invalid
                return false;
            }

            // Checksums don't match
            return false;
        }


    }
}
