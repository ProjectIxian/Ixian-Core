using System;
using System.Collections.Generic;
using System.Linq;

namespace DLT
{
    class Address
    {
        public int version = 0;
        public byte[] address;

        public Address()
        {
            address = null;
        }

        public Address(byte[] public_key_or_address, byte[] nonce = null)
        {
            version = 0;

            if (public_key_or_address == null)
            {
                throw new Exception("Cannot construct address, public_key_or_address is null");
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

                byte[] hashed_pub_key = Crypto.sha512quTrunc(public_key_or_address, 0, public_key_or_address.Length, 32);
                Array.Copy(hashed_pub_key, 0, raw_address, 1, hashed_pub_key.Length);

                byte[] checksum = Crypto.sha512sqTrunc(raw_address, 0, 33, 3);
                Array.Copy(checksum, 0, raw_address, 33, 3);

                base_address = raw_address;
            }

            if (nonce == null || (nonce.Length == 1 && nonce[0] == 0))
            {
                address = base_address;
            }
            else
            {
                byte[] raw_address = new byte[36];
                raw_address[0] = 0; // version

                List<byte> tmp_address = base_address.ToList();
                tmp_address.AddRange(nonce);

                byte[] hashed_pub_key = Crypto.sha512quTrunc(tmp_address.ToArray(), 0, tmp_address.Count, 32);
                Array.Copy(hashed_pub_key, 0, raw_address, 1, hashed_pub_key.Length);

                byte[] checksum = Crypto.sha512sqTrunc(raw_address, 0, 33, 3);
                Array.Copy(checksum, 0, raw_address, 33, 3);

                address = raw_address;
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

                byte[] hashed_pub_key = Crypto.sha512sqTrunc(public_key_or_address, 5, 0, 44);
                Array.Copy(hashed_pub_key, 0, raw_address, 1, hashed_pub_key.Length);

                byte[] checksum = Crypto.sha512sqTrunc(raw_address, 0, 45, 3);
                Array.Copy(checksum, 0, raw_address, 45, 3);

                base_address = raw_address;
            }

            if (nonce == null || (nonce.Length == 1 && nonce[0] == 0))
            {
                address = base_address;
            }else
            {
                byte[] raw_address = new byte[48];
                raw_address[0] = 1; // version

                List<byte> tmp_address = base_address.ToList();
                tmp_address.AddRange(nonce);

                byte[] hashed_pub_key = Crypto.sha512sqTrunc(tmp_address.ToArray(), 5, 0, 44);
                Array.Copy(hashed_pub_key, 0, raw_address, 1, hashed_pub_key.Length);

                byte[] checksum = Crypto.sha512sqTrunc(raw_address, 0, 45, 3);
                Array.Copy(checksum, 0, raw_address, 45, 3);

                address = raw_address;
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
