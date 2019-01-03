using DLT.Meta;
using IXICore;
using IXICore.CryptoKey;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace DLT
{
    public class AddressData
    {
        public byte[] nonce = null;
        public IxianKeyPair keyPair = null;
    }

    class WalletStorage
    {
        private string filename;

        private int walletVersion = 0;
        private string walletPassword = ""; // TODO TODO TODO TODO wallet password, seed and keys should be encrypted in memory

        private byte[] seedHash = null;
        private byte[] masterSeed = null;
        private byte[] derivedMasterSeed = null;

        private readonly Dictionary<byte[], IxianKeyPair> myKeys = new Dictionary<byte[], IxianKeyPair>(new IXICore.Utils.ByteArrayComparer());
        private readonly Dictionary<byte[], AddressData> myAddresses = new Dictionary<byte[], AddressData>(new IXICore.Utils.ByteArrayComparer());

        private byte[] privateKey = null;
        private byte[] publicKey = null;
        private byte[] address = null;

        public WalletStorage()
        {
            filename = "ixian.wal";
            readWallet();
        }

        public WalletStorage(string file_name)
        {
            filename = file_name;
            readWallet();
        }

        private void displayBackupText()
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("");
            Console.WriteLine("!! Always remember to keep a backup of your ixian.wal file and your password.");
            Console.WriteLine("!! In case of a lost file you will not be able to access your funds.");
            Console.WriteLine("!! Never give your ixian.wal and/or password to anyone.");
            Console.WriteLine("");
            Console.ResetColor();
        }

        private void readWallet_v1(BinaryReader reader)
        {
            walletVersion = 1;

            // Read the encrypted keys
            int b_privateKeyLength = reader.ReadInt32();
            byte[] b_privateKey = reader.ReadBytes(b_privateKeyLength);

            int b_publicKeyLength = reader.ReadInt32();
            byte[] b_publicKey = reader.ReadBytes(b_publicKeyLength);

            byte[] b_last_nonce = null;
            if(reader.BaseStream.Position < reader.BaseStream.Length)
            {
                int b_last_nonceLength = reader.ReadInt32();
                b_last_nonce = reader.ReadBytes(b_last_nonceLength);
            }

            bool success = false;
            while (!success)
            {
                displayBackupText();

                Console.Write("Enter wallet password: ");
                string password = getPasswordInput();
                success = true;
                try
                {
                    // Decrypt
                    privateKey = CryptoManager.lib.decryptWithPassword(b_privateKey, password);
                    publicKey = CryptoManager.lib.decryptWithPassword(b_publicKey, password);
                    walletPassword = password;
                }
                catch (Exception)
                {
                    Logging.error(string.Format("Incorrect password"));
                    Logging.flush();
                    success = false;
                }

            }

            Address addr = new Address(publicKey);
            address = addr.address;

            IxianKeyPair kp = new IxianKeyPair();
            kp.privateKeyBytes = privateKey;
            kp.publicKeyBytes = publicKey;
            lock (myKeys)
            {
                myKeys.Add(address, kp);
            }
            lock (myAddresses)
            {
                AddressData ad = new AddressData() { nonce = null, keyPair = kp };
                myAddresses.Add(address, ad);

                if (b_last_nonce != null)
                {
                    byte[] last_nonce_bytes = CryptoManager.lib.decryptWithPassword(b_last_nonce, walletPassword);
                    while (!last_nonce_bytes.SequenceEqual(kp.lastNonceBytes))
                    {
                        generateNewAddress(addr, false);
                    }
                }
            }
        }

        private void readWallet_v2(BinaryReader reader)
        {
            walletVersion = 2;

            // Read the master seed
            int b_master_seed_length = reader.ReadInt32();
            byte[] b_master_seed = reader.ReadBytes(b_master_seed_length);

            string password = "";

            bool success = false;
            while (!success)
            {
                displayBackupText();

                Console.Write("Enter wallet password: ");
                password = getPasswordInput();
                success = true;
                try
                {
                    // Decrypt
                    masterSeed = CryptoManager.lib.decryptWithPassword(b_master_seed, password);
                    seedHash = Crypto.sha512sqTrunc(masterSeed);
                    walletPassword = password;
                }
                catch (Exception)
                {
                    Logging.error(string.Format("Incorrect password"));
                    Logging.flush();
                    success = false;
                }

            }

            int key_count = reader.ReadInt32();
            for (int i = 0; i < key_count; i++)
            {
                int len = reader.ReadInt32();
                if (reader.BaseStream.Position + len > reader.BaseStream.Length)
                {
                    Logging.error("Wallet file is corrupt, expected more data than available.");
                    break;
                }
                byte[] enc_private_key = reader.ReadBytes(len);

                len = reader.ReadInt32();
                if (reader.BaseStream.Position + len > reader.BaseStream.Length)
                {
                    Logging.error("Wallet file is corrupt, expected more data than available.");
                    break;
                }
                byte[] enc_public_key = reader.ReadBytes(len);

                len = reader.ReadInt32();
                if (reader.BaseStream.Position + len > reader.BaseStream.Length)
                {
                    Logging.error("Wallet file is corrupt, expected more data than available.");
                    break;
                }
                byte[] enc_nonce = null;
                if (len > 0)
                {
                    enc_nonce = reader.ReadBytes(len);
                }

                byte[] dec_private_key = CryptoManager.lib.decryptWithPassword(enc_private_key, password);
                byte[] dec_public_key = CryptoManager.lib.decryptWithPassword(enc_public_key, password);
                byte[] tmp_address = (new Address(dec_public_key)).address;

                IxianKeyPair kp = new IxianKeyPair();
                kp.privateKeyBytes = dec_private_key;
                kp.publicKeyBytes = dec_public_key;
                if(enc_nonce != null)
                {
                    kp.lastNonceBytes = CryptoManager.lib.decryptWithPassword(enc_nonce, password);
                }

                if (privateKey == null)
                {
                    privateKey = dec_private_key;
                    publicKey = dec_public_key;
                    address = tmp_address;
                }

                lock (myKeys)
                {
                    myKeys.Add(tmp_address, kp);
                }
                lock (myAddresses)
                {
                    AddressData ad = new AddressData() { nonce = null, keyPair = kp };
                    myAddresses.Add(tmp_address, ad);
                }
            }

            int seed_len = reader.ReadInt32();
            byte[] enc_derived_seed = reader.ReadBytes(seed_len);
            derivedMasterSeed = CryptoManager.lib.decryptWithPassword(enc_derived_seed, password);
        }

        // Try to read wallet information from the file
        private bool readWallet()
        {
            
            if (File.Exists(filename) == false)
            {
                Logging.log(LogSeverity.error, "Cannot read wallet file.");

                // Generate a new wallet
                return generateWallet();
            }

            Logging.log(LogSeverity.info, "Wallet file found, reading data...");
            Logging.flush();

            BinaryReader reader;
            try
            {
                reader = new BinaryReader(new FileStream(filename, FileMode.Open));
            }
            catch (IOException e)
            {
                Logging.log(LogSeverity.error, String.Format("Cannot open wallet file. {0}", e.Message));
                return false;
            }

            try
            {
                // Read the wallet version
                System.Int32 version = reader.ReadInt32();

                if(version == 1)
                {
                    readWallet_v1(reader);
                }else if(version == 2)
                {
                    readWallet_v2(reader);
                }else
                {
                    Logging.error("Unknown wallet version {0}", version);
                    return false;
                }

                // Wait for any pending log messages to be written
                Logging.flush();

                Console.WriteLine();
                Console.Write("Your IXIAN address is ");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(Base58Check.Base58CheckEncoding.EncodePlain(address));
                Console.ResetColor();
                Console.WriteLine();

            }
            catch (IOException e)
            {
                Logging.error("Cannot read from wallet file. {0}", e.Message);
                return false;
            }

            reader.Close();

            // Check if we should change the password of the wallet
            if(Config.changePass == true)
            {
                // Request a new password
                string new_password = "";
                while (new_password.Length < 10)
                {
                    new_password = requestNewPassword("Enter a new password for your wallet: ");
                }
                writeWallet(new_password);
            }

            Logging.info("Public Node Address: {0}", Base58Check.Base58CheckEncoding.EncodePlain(address));

            return true;
        }

        // Write the wallet to the file
        private bool writeWallet_v1(string password)
        {
            if (password.Length < 10)
                return false;

            // Encrypt data first
            byte[] b_privateKey = CryptoManager.lib.encryptWithPassword(privateKey, password);
            byte[] b_publicKey = CryptoManager.lib.encryptWithPassword(publicKey, password);

            BinaryWriter writer;
            try
            {
                writer = new BinaryWriter(new FileStream(filename, FileMode.Create));
            }
            catch (IOException e)
            {
                Logging.error("Cannot create wallet file. {0}", e.Message);
                return false;
            }

            try
            {
                int version = 1; // Set the wallet version
                writer.Write(version);

                // Write the address keypair
                writer.Write(b_privateKey.Length);
                writer.Write(b_privateKey);

                writer.Write(b_publicKey.Length);
                writer.Write(b_publicKey);

                if (myKeys.First().Value.lastNonceBytes != null)
                {
                    byte[] b_last_nonce = CryptoManager.lib.encryptWithPassword(myKeys.First().Value.lastNonceBytes, password);
                    writer.Write(b_last_nonce.Length);
                    writer.Write(b_last_nonce);
                }

            }

            catch (IOException e)
            {
                Logging.error("Cannot write to wallet file. {0}", e.Message);
                return false;
            }

            writer.Close();

            return true;
        }

        // Write the wallet to the file
        private bool writeWallet_v2(string password)
        {
            if (password.Length < 10)
                return false;

            BinaryWriter writer;
            try
            {
                writer = new BinaryWriter(new FileStream(filename, FileMode.Create));
            }
            catch (IOException e)
            {
                Logging.error("Cannot create wallet file. {0}", e.Message);
                return false;
            }

            try
            {
                int version = 2; // Set the wallet version
                writer.Write(version);

                // Write the master seed
                byte[] enc_master_seed = CryptoManager.lib.encryptWithPassword(masterSeed, password);
                writer.Write(enc_master_seed.Length);
                writer.Write(enc_master_seed);

                lock (myKeys)
                {
                    writer.Write(myKeys.Count());

                    foreach (var entry in myKeys)
                    {
                        byte[] enc_private_key = CryptoManager.lib.encryptWithPassword(entry.Value.privateKeyBytes, password);
                        writer.Write(enc_private_key.Length);
                        writer.Write(enc_private_key);

                        byte[] enc_public_key = CryptoManager.lib.encryptWithPassword(entry.Value.publicKeyBytes, password);
                        writer.Write(enc_public_key.Length);
                        writer.Write(enc_public_key);

                        if (entry.Value.lastNonceBytes != null)
                        {
                            byte[] enc_nonce = CryptoManager.lib.encryptWithPassword(entry.Value.lastNonceBytes, password);
                            writer.Write(enc_nonce.Length);
                            writer.Write(enc_nonce);
                        }else
                        {
                            writer.Write((int) 0);
                        }
                    }
                }

                byte[] enc_derived_master_seed = CryptoManager.lib.encryptWithPassword(derivedMasterSeed, password);
                writer.Write(enc_derived_master_seed.Length);
                writer.Write(enc_derived_master_seed);
            }

            catch (IOException e)
            {
                Logging.error("Cannot write to wallet file. {0}", e.Message);
                return false;
            }

            writer.Close();

            return true;
        }
        // Generate a new wallet with matching private/public key pairs
        private bool generateWallet()
        {
            Logging.info("A new wallet will be generated for you.");

            Logging.flush();

            displayBackupText();

            Logging.flush();

            // Request a password
            string password = "";
            while(password.Length < 10)
            {
                password = requestNewPassword("Enter a password for your new wallet: ");
            }


            walletVersion = 1;
            walletPassword = password;

            Logging.log(LogSeverity.info, "Generating master seed, this may take a while, please wait...");

            masterSeed = KeyDerivation.getNewRandomSeed(1024 * 1024);
            seedHash = Crypto.sha512sqTrunc(masterSeed);
            derivedMasterSeed = masterSeed;

            Logging.log(LogSeverity.info, "Generating primary wallet keys, this may take a while, please wait...");

            //IxianKeyPair kp = generateNewKeyPair(false);
            IxianKeyPair kp = CryptoManager.lib.generateKeys(CoreConfig.defaultRsaKeySize);

            if (kp == null)
            {
                Logging.error("Error creating wallet, unable to generate a new keypair.");
                return false;
            }

            privateKey = kp.privateKeyBytes;
            publicKey = kp.publicKeyBytes;

            Address addr = new Address(publicKey);
            address = addr.address;

            myKeys.Add(address, kp);
            myAddresses.Add(address, new AddressData() { keyPair = kp, nonce = null });


            Logging.info(String.Format("Public Key: {0}", Crypto.hashToString(publicKey)));
            Logging.info(String.Format("Public Node Address: {0}", Base58Check.Base58CheckEncoding.EncodePlain(address)));

            // Wait for any pending log messages to be written
            Logging.flush();

            Console.WriteLine();
            Console.Write("Your IXIAN address is ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(Base58Check.Base58CheckEncoding.EncodePlain(address));
            Console.ResetColor();
            Console.WriteLine();

            // Write the new wallet data to the file
            return writeWallet(password);
        }

        // Requests the user to type a new password
        private string requestNewPassword(string banner)
        {
            Console.WriteLine();
            Console.Write(banner);
            try
            {
                string pass = getPasswordInput();

                if(pass.Length < 10)
                {
                    Console.WriteLine("Password needs to be at least 10 characters. Try again.");
                    return "";
                }

                Console.Write("Type it again to confirm: ");

                string passconfirm = getPasswordInput();

                if(pass.Equals(passconfirm, StringComparison.Ordinal))
                {                   
                    return pass;
                }
                else
                {
                    Console.WriteLine("Passwords don't match, try again.");

                    // Passwords don't match
                    return "";
                }

            }
            catch (Exception)
            {
                // Handle exceptions
                return "";
            }
        }

        // Handles console password input
        public string getPasswordInput()
        {
            StringBuilder sb = new StringBuilder();
            while (true)
            {
                ConsoleKeyInfo i = Console.ReadKey(true);
                if (i.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine();
                    break;
                }
                else if (i.Key == ConsoleKey.Backspace)
                {
                    if (sb.Length > 0)
                    {
                        sb.Remove(sb.Length - 1, 1);
                        Console.Write("\b \b");
                    }
                }
                else if (i.KeyChar != '\u0000')
                {
                    sb.Append(i.KeyChar);
                    Console.Write("*");
                }
            }
            return sb.ToString();
        }

        public byte[] getPrimaryAddress()
        {
            return address;
        }

        public byte[] getPrimaryPrivateKey()
        {
            return privateKey;
        }

        public byte[] getPrimaryPublicKey()
        {
            return publicKey;
        }

        public byte[] getLastAddress()
        {
            // TODO TODO TODO TODO TODO this doesn't do what it's intended
            // Also you have to take into account what happens when loading from file and the difference between v1 and v2 wallets (key related)
            lock (myAddresses)
            {
                return myAddresses.Last().Key;
            }
        }

        public byte[] getSeedHash()
        {
            return seedHash;
        }

        public bool backup(string destination)
        {
            File.Copy(filename, destination);
            return true;
        }

        public bool writeWallet(string password)
        {
            // TODO TODO TODO TODO TODO TODO backup the wallet first.
            if (walletVersion == 1)
            {
                return writeWallet_v1(walletPassword);
            }
            if (walletVersion == 2)
            {
                return writeWallet_v2(walletPassword);
            }
            return false;
        }

        public IxiNumber getMyTotalBalance()
        {
            IxiNumber balance = 0;
            lock (myAddresses)
            {
                foreach (var entry in myAddresses)
                {
                    balance += Node.walletState.getWalletBalance(entry.Key);
                }
            }
            return balance;
        }

        public Address generateNewAddress(Address key_primary_address, bool write_to_file = true)
        {
            lock (myKeys)
            {
                if(!myKeys.ContainsKey(key_primary_address.address))
                {
                    return null;
                }

                IxianKeyPair kp = myKeys[key_primary_address.address];

                byte[] base_nonce = null;
                if (walletVersion < 2)
                {
                    base_nonce = Crypto.sha512sqTrunc(privateKey.Skip(publicKey.Length).Take(64).ToArray());
                }
                else
                {
                    base_nonce = Crypto.sha512sqTrunc(masterSeed.Take(64).ToArray());
                }

                byte[] last_nonce = kp.lastNonceBytes;

                List<byte> new_nonce = base_nonce.ToList();
                if (last_nonce != null)
                {
                    new_nonce.AddRange(last_nonce);
                }
                kp.lastNonceBytes = Crypto.sha512sqTrunc(new_nonce.ToArray()).Take(16).ToArray();

                Address new_address = new Address(key_primary_address.address, kp.lastNonceBytes);

                lock (myAddresses)
                {
                    AddressData ad = new AddressData() { nonce = kp.lastNonceBytes, keyPair = kp };
                    myAddresses.Add(new_address.address, ad);
                }

                if (write_to_file)
                {
                    writeWallet(walletPassword);
                }

                return new_address;
            }
        }

        public IxianKeyPair generateNewKeyPair(bool writeToFile = true)
        {
            if (walletVersion < 2)
            {
                lock (myKeys)
                {
                    return myKeys.First().Value;
                }
            }

            IXICore.CryptoKey.KeyDerivation kd = new IXICore.CryptoKey.KeyDerivation(masterSeed);

            int key_count = 0;

            lock (myKeys)
            {
                key_count = myKeys.Count();
            }

            IxianKeyPair kp = kd.deriveKey(key_count, CoreConfig.defaultRsaKeySize, 65537);

            if (kp == null)
            {
                Logging.error("An error occured generating new key pair, unable to derive key.");
                return null;
            }

            if (!DLT.CryptoManager.lib.testKeys(Encoding.Unicode.GetBytes("TEST TEST"), kp))
            {
                Logging.error("An error occured while testing the newly generated keypair, unable to produce a valid address.");
                return null;
            }
            Address addr = new Address(kp.publicKeyBytes);
            address = addr.address;

            if (addr.address == null)
            {
                Logging.error("An error occured generating new key pair, unable to produce a valid address.");
                return null;
            }
            lock (myKeys)
            {
                lock (myAddresses)
                {
                    if (!writeToFile)
                    {
                        myKeys.Add(address, kp);
                        AddressData ad = new AddressData() { nonce = kp.lastNonceBytes, keyPair = kp };
                        myAddresses.Add(address, ad);
                    }
                    else
                    {
                        if (writeWallet(walletPassword))
                        {
                            myKeys.Add(address, kp);
                            AddressData ad = new AddressData() { nonce = kp.lastNonceBytes, keyPair = kp };
                            myAddresses.Add(address, ad);
                        }
                        else
                        {
                            Logging.error("An error occured while writing wallet file.");
                            return null;
                        }
                    }
                }
            }

            return kp;
        }

        public IxianKeyPair getKeyPair(byte[] address)
        {
            lock (myKeys)
            {
                if (myKeys.ContainsKey(address))
                {
                    return myKeys[address];
                }
                return null;
            }
        }

        public bool isMyAddress(byte[] address)
        {
            lock (myAddresses)
            {
                if (myAddresses.ContainsKey(address))
                {
                    return true;
                }
            }
            return false;
        }

        public byte[] isMyAddress(SortedDictionary<byte[], IxiNumber> address_list)
        {
            lock (myAddresses)
            {
                foreach (var entry in address_list)
                {
                    if (myAddresses.ContainsKey(entry.Key))
                    {
                        return entry.Key;
                    }
                }
            }
            return null;
        }

        public List<Address> getMyAddresses()
        {
            lock(myAddresses)
            {
                return myAddresses.Select(x => new Address(x.Key)).ToList();
            }
        }
    }
}
