using System;
using System.Collections.Generic;
using System.Linq;

namespace IXICore
{
    /// <summary>
    /// Ixian Wallet Address.
    ///  This class holds a binary value of an Ixian Address and contains functions to encode that information to- or retrieve it from a bytestream.
    ///  An address can be constructed either directly from address bytes or from a combination of public key and a 'nonce' value.
    /// </summary>
    /// <remarks>
    ///  All versions of addreses are supported and basic checksum verification is possible. It is recommended to always generate addresses in the latest
    ///  format for best performance and security.
    ///  Ixian addresses v1 and above are generated from the wallet's primary key using a 'nonce' value, allowing for fast and efficient generation of multiple
    ///  addresses from the same keypair.
    /// </remarks>
    public class Address
    {
        /// <summary>
        /// Version of the Ixian Address.
        /// </summary>
        public int version = 0;
        /// <summary>
        ///  Byte value of the address.
        /// </summary>
        /// <remarks>
        ///  It is not recommended to manipulate this directly, but the field is exposed because some DLT components rely on 
        /// </remarks>
        public byte[] address;
        /// <summary>
        ///  Address nonce value. Applicable only for v1 and above.
        /// </summary>
        public byte[] nonce;


        public Address()
        {
            address = null;
            nonce = null;
        }

        /// <summary>
        ///  Constructs an Ixian address with the given byte value or alternatively from the given public key using a nonce value.
        /// </summary>
        /// <remarks>
        ///  The address can be constructed either directly from the address byte value, or indirectly via a public key and a nonce value.
        ///  If the address bytes are given directly, the nonce value may be omitted.
        /// </remarks>
        /// <param name="public_key_or_address">Byte value of the address or of the wallet's public key. See Remarks.</param>
        /// <param name="nonce">If the value given for address bytes is a public key, this field is required to specify with actual address to generate.</param>
        /// <param name="verify_checksum">If true, the given address will be verified for the correct checksum.</param>
        public Address(byte[] public_key_or_address, byte[] nonce = null, bool verify_checksum = true)
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

            this.nonce = nonce;

            if(version == 0)
            {
                constructAddress_v0(public_key_or_address, nonce, verify_checksum);
            }else if(version == 1)
            {
                constructAddress_v1(public_key_or_address, nonce, verify_checksum);
            }else
            {
                throw new Exception("Cannot construct address, unknown address version");
            }
        }

        private void constructAddress_v0(byte[] public_key_or_address, byte[] nonce, bool verify_checksum)
        {
            byte[] base_address = null;
            if (public_key_or_address.Length == 36)
            {
                base_address = public_key_or_address;
                if(verify_checksum && !validateChecksum(base_address))
                {
                    throw new Exception("Invalid address was specified (checksum error).");
                }
            }
            else
            {
                byte[] raw_address = new byte[36];
                raw_address[0] = 0; // version

                int public_key_offset = 5;
                if (public_key_or_address.Length == 523)
                {
                    public_key_offset = 0;
                }
                byte[] hashed_pub_key = Crypto.sha512quTrunc(public_key_or_address, public_key_offset, 0, 32);
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

        private void constructAddress_v1(byte[] public_key_or_address, byte[] nonce, bool verify_checksum)
        {
            byte[] base_address = null;
            if (public_key_or_address.Length == 48)
            {
                base_address = public_key_or_address;
                if (verify_checksum && !validateChecksum(base_address))
                {
                    throw new Exception("Invalid address was specified (checksum error).");
                }
            }
            else
            {
                byte[] raw_address = new byte[48];
                raw_address[0] = 1; // version

                byte[] hashed_pub_key = Crypto.sha512sqTrunc(public_key_or_address, 1, 0, 44);
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

        /// <summary>
        ///  Converts a binary Address representation into it's textual (base58) form, which is used in the Json Api and various clients.
        /// </summary>
        /// <returns>Textual representation of the wallet.</returns>
        public override string ToString()
        {
            return Base58Check.Base58CheckEncoding.EncodePlain(address);
        }

        /// <summary>
        ///  Validates that the given value is a valid Address by checking the embedded checksum.
        /// </summary>
        /// <remarks>
        ///  This function accepts only the final address bytes, not a public key + nonce pair. If you are generating an Address from 
        ///  public key + nonce, the Address constructor will automatically embed the correct checksum, so testing it here would be pointless.
        /// </remarks>
        /// <param name="address">Bytes of an Ixian Address.</param>
        /// <returns>True, if the value is a valid Address.</returns>
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
                int raw_address_len = address.Length - 3;
                byte[] in_chk = address.Skip(raw_address_len).Take(3).ToArray();

                byte[] checksum = Crypto.sha512sqTrunc(address, 0, raw_address_len, 3);

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
