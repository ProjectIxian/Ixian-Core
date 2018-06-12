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

            //Mnemonic mnemonic_addr = new Mnemonic(Wordlist.English, Encoding.ASCII.GetBytes(hashed_key.ToString()));
            //address = mnemonic_addr.ToString();

        }



        public override string ToString()
        {
            return address;
        }


    }
}
