using IXICore;
using IXICore.Meta;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace IXICore
{
    // The message codes available in S2.
    // Error and Info are free, while data requires a transaction
    public enum StreamMessageCode
    {
        error,      // Reserved for S2 nodes only
        info,       // Free, limited message type
        data        // Paid, transaction-based type
    }

    // The encryption message codes available in S2.
    public enum StreamMessageEncryptionCode
    {
        none,
        rsa,
        spixi1
    }

    class StreamMessage
    {
        public int version = 0;                 // Stream Message version

        public StreamMessageCode type;          // Stream Message type
        public byte[] realSender = null;        // Used by group chat bots, isn't transmitted to the network
        public byte[] sender = null;            // Sender wallet
        public byte[] recipient = null;         // Recipient wallet 

        public byte[] transaction = null;       // Unsigned transaction
        public byte[] data = null;              // Actual message data, encrypted
        public byte[] sigdata = null;           // Signature data (for S2), encrypted

        public byte[] signature = null;         // Sender's signature

        public StreamMessageEncryptionCode encryptionType;

        public bool encrypted = false; // used locally to avoid double encryption of data
        public bool sigEncrypted = false; // used locally to avoid double encryption of tx sig

        public byte[] id;                      // Message unique id

        public StreamMessage()
        {
            id = Guid.NewGuid().ToByteArray(); // Generate a new unique id
            type = StreamMessageCode.info;
            sender = null;
            recipient = null;
            transaction = null;
            data = null;
            sigdata = null;
            encryptionType = StreamMessageEncryptionCode.spixi1;
        }

        public StreamMessage(byte[] bytes)
        {
            try
            {
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        int version = reader.ReadInt32();

                        int id_len = reader.ReadInt32();
                        id = reader.ReadBytes(id_len);

                        int message_type = reader.ReadInt32();
                        type = (StreamMessageCode)message_type;

                        int encryption_type = reader.ReadInt32();
                        encryptionType = (StreamMessageEncryptionCode)encryption_type;

                        int sender_length = reader.ReadInt32();
                        if (sender_length > 0)
                            sender = reader.ReadBytes(sender_length);

                        int recipient_length = reader.ReadInt32();
                        if (recipient_length > 0)
                            recipient = reader.ReadBytes(recipient_length);

                        int data_length = reader.ReadInt32();
                        if (data_length > 0)
                            data = reader.ReadBytes(data_length);

                        int tx_length = reader.ReadInt32();
                        if (tx_length > 0)
                            transaction = reader.ReadBytes(tx_length);

                        int sigdata_length = reader.ReadInt32();
                        if (sigdata_length > 0)
                            sigdata = reader.ReadBytes(sigdata_length);

                        encrypted = reader.ReadBoolean();
                        sigEncrypted = reader.ReadBoolean();

                        int sig_length = reader.ReadInt32();
                        if (sig_length > 0)
                            signature = reader.ReadBytes(sig_length);
                    }
                }
            }
            catch (Exception e)
            {
                Logging.error("Exception occured while trying to construct StreamMessage from bytes: " + e);
            }
        }

        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(version);

                    writer.Write(id.Length);
                    writer.Write(id);

                    // Write the type
                    writer.Write((int)type);

                    // Write the encryption type
                    writer.Write((int)encryptionType);

                    // Write the sender
                    if (sender != null)
                    {
                        writer.Write(sender.Length);
                        writer.Write(sender);
                    }
                    else
                    {
                        writer.Write(0);
                    }


                    // Write the recipient
                    if (recipient != null)
                    {
                        writer.Write(recipient.Length);
                        writer.Write(recipient);
                    }
                    else
                    {
                        writer.Write(0);
                    }


                    // Write the data
                    if (data != null)
                    {
                        writer.Write(data.Length);
                        writer.Write(data);
                    }
                    else
                    {
                        writer.Write(0);
                    }

                    // Write the tx
                    if (transaction != null)
                    {
                        writer.Write(transaction.Length);
                        writer.Write(transaction);
                    }
                    else
                    {
                        writer.Write(0);
                    }


                    // Write the sigdata
                    if (sigdata != null)
                    {
                        writer.Write(sigdata.Length);
                        writer.Write(sigdata);
                    }
                    else
                    {
                        writer.Write(0);
                    }

                    writer.Write(encrypted);
                    writer.Write(sigEncrypted);

                    // Write the sig
                    if (signature != null)
                    {
                        writer.Write(signature.Length);
                        writer.Write(signature);
                    }
                    else
                    {
                        writer.Write(0);
                    }
                }
                return m.ToArray();
            }
        }

        // Encrypts a provided message with aes, then chacha based on the keys provided
        public bool encrypt(byte[] public_key, byte[] aes_password, byte[] chacha_key)
        {
            if(encrypted)
            {
                return true;
            }
            byte[] encrypted_data = _encrypt(data, public_key, aes_password, chacha_key);
            if(encrypted_data != null)
            {
                data = encrypted_data;
                encrypted = true;
                return true;
            }
            return false;
        }

        public bool decrypt(byte[] private_key, byte[] aes_key, byte[] chacha_key)
        {
            byte[] decrypted_data = _decrypt(data, private_key, aes_key, chacha_key);
            if (decrypted_data != null)
            {
                data = decrypted_data;
                return true;
            }
            return false;
        }

        // Encrypts a provided signature with aes, then chacha based on the keys provided
        public bool encryptSignature(byte[] public_key, byte[] aes_password, byte[] chacha_key)
        {
            if (sigEncrypted)
            {
                return true;
            }
            byte[] encrypted_data = _encrypt(sigdata, public_key, aes_password, chacha_key);
            if (encrypted_data != null)
            {
                sigdata = encrypted_data;
                sigEncrypted = true;
                return true;
            }
            return false;
        }

        public bool decryptSignature(byte[] private_key, byte[] aes_key, byte[] chacha_key)
        {
            byte[] decrypted_data = _decrypt(sigdata, private_key, aes_key, chacha_key);
            if (decrypted_data != null)
            {
                sigdata = decrypted_data;
                return true;
            }
            return false;
        }

        private byte[] calculateChecksum()
        {
            return Crypto.sha512(getBytes());
        }

        public bool sign(byte[] private_key)
        {
            byte[] checksum = calculateChecksum();
            signature = CryptoManager.lib.getSignature(checksum, private_key);
            return false;
        }

        public bool verifySignature(byte[] public_key)
        {
            byte[] checksum = calculateChecksum();
            return CryptoManager.lib.verifySignature(checksum, public_key, signature);
        }

        private byte[] _encrypt(byte[] data_to_encrypt, byte[] public_key, byte[] aes_key, byte[] chacha_key)
        {
            if (encryptionType == StreamMessageEncryptionCode.spixi1)
            {
                if (aes_key != null && chacha_key != null)
                {
                    byte[] aes_encrypted = CryptoManager.lib.encryptWithAES(data_to_encrypt, aes_key, true);
                    byte[] chacha_encrypted = CryptoManager.lib.encryptWithChacha(aes_encrypted, chacha_key);
                    return chacha_encrypted;
                }
                else
                {
                    Logging.error("Cannot encrypt message, no AES and CHACHA keys were provided.");
                }
            }
            else if (encryptionType == StreamMessageEncryptionCode.rsa)
            {
                if (public_key != null)
                {
                    return CryptoManager.lib.encryptWithRSA(data_to_encrypt, public_key);
                }
                else
                {
                    Logging.error("Cannot encrypt message, no RSA key was provided.");
                }
            }
            else
            {
                Logging.error("Cannot encrypt message, invalid encryption type {0} was specified.", encryptionType);
            }
            return null;
        }

        private byte[] _decrypt(byte[] data_to_decrypt, byte[] private_key, byte[] aes_key, byte[] chacha_key)
        {
            if(encryptionType == StreamMessageEncryptionCode.spixi1)
            {
                if (aes_key != null && chacha_key != null)
                {
                    byte[] chacha_decrypted = CryptoManager.lib.decryptWithChacha(data_to_decrypt, chacha_key);
                    byte[] aes_decrypted = CryptoManager.lib.decryptWithAES(chacha_decrypted, aes_key, true);
                    return aes_decrypted;
                }else
                {
                    Logging.error("Cannot decrypt message, no AES and CHACHA keys were provided.");
                }
            }
            else if (encryptionType == StreamMessageEncryptionCode.rsa)
            {
                if(private_key != null)
                {
                    return CryptoManager.lib.decryptWithRSA(data_to_decrypt, private_key);
                }else
                {
                    Logging.error("Cannot decrypt message, no RSA key was provided.");
                }
            }
            else
            {
                Logging.error("Cannot decrypt message, invalid decryption type {0} was specified.", encryptionType);
            }
            return null;
        }

    }
}
