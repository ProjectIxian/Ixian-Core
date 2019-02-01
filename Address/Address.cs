using System;
using System.Collections.Generic;
using System.Linq;

namespace DLT
{
    class Address
    {
        public int version = 0;
        public byte[] address;
        private byte[] checksum;

        public Address()
        {
            address = null;
        }

        public Address(byte[] public_key_or_address, byte[] nonce = null)
        {
            version = 0;

            if (public_key_or_address == null)
            {
                throw new Exception("Cannot construct address, nonce is null");
            }
            else
            {
                if (public_key_or_address.Length == 523)
                {
                    version = 0;
                }else
                {
                    version = public_key_or_address[0];
                }
            }

            if(version == 0)
            {
                constructAddress_v0(public_key_or_address, nonce);
            }else
            {
                constructAddress_v1(public_key_or_address, nonce);
            }
        }

        private void constructAddress_v0(byte[] public_key_or_address, byte[] nonce)
        {
            byte[] base_address = null;
            if (public_key_or_address.Length == 36)
            {
                base_address = public_key_or_address;
            }
            else
            {
                byte[] raw_address = new byte[36];
                raw_address[0] = 0; // version

                byte[] hashed_pub_key = Crypto.sha512quTrunc(public_key_or_address, 0, public_key_or_address.Length, 33);
                Array.Copy(hashed_pub_key, 0, raw_address, 1, hashed_pub_key.Length);

                checksum = Crypto.sha512sqTrunc(raw_address, 0, 33, 3);
                Array.Copy(checksum, 0, raw_address, 32, 3);
            }

            if (nonce.Length == 1 && nonce[0] == 0)
            {
                address = base_address;
            }
            else
            {
                byte[] raw_address = new byte[36];
                raw_address[0] = 0; // version

                List<byte> tmp_address = base_address.ToList();
                tmp_address.AddRange(nonce);

                byte[] hashed_pub_key = Crypto.sha512quTrunc(tmp_address.ToArray(), 0, tmp_address.Count, 33);
                Array.Copy(hashed_pub_key, 0, raw_address, 1, hashed_pub_key.Length);

                checksum = Crypto.sha512sqTrunc(raw_address, 0, 33, 3);
                Array.Copy(checksum, 0, raw_address, 32, 3);
            }
        }

        private void constructAddress_v1(byte[] public_key_or_address, byte[] nonce)
        {
            byte[] base_address = null;
            if (public_key_or_address.Length == 48)
            {
                base_address = public_key_or_address;
            }
            else
            {
                byte[] raw_address = new byte[48];
                raw_address[0] = 1; // version

                byte[] hashed_pub_key = Crypto.sha512sqTrunc(public_key_or_address, 0, public_key_or_address.Length, 43);
                Array.Copy(hashed_pub_key, 0, raw_address, 1, hashed_pub_key.Length);

                checksum = Crypto.sha512sqTrunc(raw_address, 0, 43, 3);
                Array.Copy(checksum, 0, raw_address, 42, 3);
            }

            if (nonce.Length == 2 && nonce[1] == 0)
            {
                address = base_address;
            }else
            {
                byte[] raw_address = new byte[48];
                raw_address[0] = 1; // version

                List<byte> tmp_address = base_address.ToList();
                tmp_address.AddRange(nonce);

                byte[] hashed_pub_key = Crypto.sha512sqTrunc(tmp_address.ToArray(), 0, tmp_address.Count, 43);
                Array.Copy(hashed_pub_key, 0, raw_address, 1, hashed_pub_key.Length);

                checksum = Crypto.sha512sqTrunc(raw_address, 0, 43, 3);
                Array.Copy(checksum, 0, raw_address, 42, 3);
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
                if (address.Length < 4 || address.Length > 128)
                {
                    return false;
                }
                int version = address[0];
                byte[] in_addr = address.Take(address.Length - 3).ToArray();
                byte[] in_chk = address.Skip(address.Length - 3).Take(3).ToArray();

                byte[] checksum = checksum = Crypto.sha512sqTrunc(in_addr, 0, 0, 3);

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
