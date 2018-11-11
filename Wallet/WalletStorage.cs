using DLT;
using DLT.Meta;
using IXICore;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DLT
{
    class WalletStorage
    {
        private string filename;

        public byte[] privateKey = null;
        public byte[] publicKey = null;
        public byte[] address = null;

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

            // Sleep a bit for the logger to catch up
            while (Logging.getRemainingStatementsCount() > 0)
            {
                Thread.Sleep(100);
            }

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
                
                if(version != 1)
                {
                    Logging.error(string.Format("Wallet version mismatch, expecting {0}, got {1}", 1, version));
                    return false;
                }

                // Read the encrypted keys
                int b_privateKeyLength = reader.ReadInt32();
                byte[] b_privateKey = reader.ReadBytes(b_privateKeyLength);

                int b_publicKeyLength = reader.ReadInt32();
                byte[] b_publicKey = reader.ReadBytes(b_publicKeyLength);

                bool success = false;
                while (!success)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("");
                    Console.WriteLine("!! Always remember to keep a backup of your ixian.wal file and your password.");
                    Console.WriteLine("!! In case of a lost file you will not be able to access your funds.");
                    Console.WriteLine("!! Never give your ixian.wal and/or password to anyone.");
                    Console.WriteLine("");
                    Console.ResetColor();

                    Console.Write("Enter wallet password: ");
                    string password = getPasswordInput();
                    success = true;
                    try
                    {
                        // Decrypt
                        privateKey = CryptoManager.lib.decryptWithPassword(b_privateKey, password);
                        publicKey = CryptoManager.lib.decryptWithPassword(b_publicKey, password);
                    }
                    catch(Exception)
                    {
                        Logging.error(string.Format("Incorrect password"));
                        while (Logging.getRemainingStatementsCount() > 0)
                        {
                            Thread.Sleep(100);
                        }
                        success = false;
                    }
                  
                }

                Address addr = new Address(publicKey);
                address = addr.address;

                // Wait for any pending log messages to be written
                while (Logging.getRemainingStatementsCount() > 0)
                {
                    Thread.Sleep(100);
                }

                Console.WriteLine();
                Console.Write("Your IXIAN address is ");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(Base58Check.Base58CheckEncoding.EncodePlain(address));
                Console.ResetColor();
                Console.WriteLine();

            }
            catch (IOException e)
            {
                Logging.log(LogSeverity.error, String.Format("Cannot read from wallet file. {0}", e.Message));
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

            Logging.log(LogSeverity.info, String.Format("Public Node Address: {0}", Base58Check.Base58CheckEncoding.EncodePlain(address)));

            return true;
        }

        // Write the wallet to the file
        private bool writeWallet(string password)
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
                Logging.log(LogSeverity.error, String.Format("Cannot create wallet file. {0}", e.Message));
                return false;
            }

            try
            {
                System.Int32 version = 1; // Set the wallet version
                writer.Write(version);

                // Write the address keypair
                writer.Write(b_privateKey.Length);
                writer.Write(b_privateKey);

                writer.Write(b_publicKey.Length);
                writer.Write(b_publicKey);

            }

            catch (IOException e)
            {
                Logging.log(LogSeverity.error, String.Format("Cannot write to wallet file. {0}", e.Message));
                return false;
            }

            writer.Close();

            return true;
        }

        // Generate a new wallet with matching private/public key pairs
        private bool generateWallet()
        {
            Logging.log(LogSeverity.info, "Generating new wallet keys, this may take a while, please wait...");

            // Generate the private and public key pair
            try
            {
                CryptoManager.lib.generateKeys(CoreConfig.defaultRsaKeySize);
            }
            catch(Exception e)
            {
                Logging.error(string.Format("Error generating wallet: {0}", e.ToString()));
                return false;
            }

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("");
            Console.WriteLine("!! Always remember to keep a backup of your ixian.wal file and your password.");
            Console.WriteLine("!! In case of a lost file you will not be able to access your funds.");
            Console.WriteLine("!! Never give your ixian.wal and/or password to anyone.");
            Console.WriteLine("");
            Console.ResetColor();

            // Request a password
            string password = "";
            while(password.Length < 10)
            {
                password = requestNewPassword("Enter a password for your wallet: ");
            }

            privateKey = CryptoManager.lib.getPrivateKey();
            publicKey = CryptoManager.lib.getPublicKey();

            Address addr = new Address(publicKey);
            address = addr.address;

            Logging.info(String.Format("Public Key: {0}", Crypto.hashToString(publicKey)));
            Logging.info(String.Format("Public Node Address: {0}", Base58Check.Base58CheckEncoding.EncodePlain(address)));

            // Wait for any pending log messages to be written
            while (Logging.getRemainingStatementsCount() > 0)
            {
                Thread.Sleep(100);
            }

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

        // Obtain the mnemonic address
        public byte[] getWalletAddress()
        {
            return address;
        }

        public bool backup(string destination)
        {
            File.Copy(filename, destination);
            return true;
        }

        public byte[] generateNewAddress()
        {
            return address;
        }
    }
}
