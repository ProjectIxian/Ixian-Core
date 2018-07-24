using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DLT
{
    class Address
    {
        private string publicKey;
        private string address;
        private string checksum;

        public Address()
        {
            address = "";
        }

        public Address(string public_key)
        {
            publicKey = public_key;

            // Hash the public key using SHA256 
            var hashed_key = Crypto.sha256(publicKey);

            // Hash the hashed key using Mnemonics
            address = hashed_key;

            checksum = Crypto.sha256(address);
            checksum = checksum.Substring(0, 4);

            address = hashed_key + checksum;

            //Mnemonic mnemonic_addr = new Mnemonic(Wordlist.English, Encoding.ASCII.GetBytes(hashed_key.ToString()));
            //address = mnemonic_addr.ToString();

        }



        public override string ToString()
        {
            return address;
        }

        // Generates the checksummed address from a normal address
        public static string generateChecksumAddress(string address)
        {
            // Check if the address already has a checksum
            if (validateChecksum(address) == true)
                return address;

            // Generate the actual checksum
            string chk_address = address;
            string checksum = Crypto.sha256(address);
            checksum = checksum.Substring(0, 4);

            chk_address = chk_address + checksum;

            return chk_address;
        }

        // Validates an address by checking the checksum
        public static bool validateChecksum(string address)
        {
            try
            {
                // Check the address length
                if (address.Length != 68)
                {
                    return false;
                }

                string in_addr = address.Substring(0, 64);
                string in_chk = address.Substring(64, 4);

                string checksum = Crypto.sha256(in_addr);
                checksum = checksum.Substring(0, 4);

                if (checksum.Equals(in_chk, StringComparison.Ordinal))
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
