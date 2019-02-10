using DLT.Meta;
using IXICore;
using IXICore.CryptoKey;
using IXICore.Utils;
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
        protected string filename;

        protected int walletVersion = 0;
        protected string walletPassword = ""; // TODO TODO TODO TODO wallet password, seed and keys should be encrypted in memory

        protected byte[] seedHash = null;
        protected byte[] masterSeed = null;
        protected byte[] derivedMasterSeed = null;

        protected readonly Dictionary<byte[], IxianKeyPair> myKeys = new Dictionary<byte[], IxianKeyPair>(new IXICore.Utils.ByteArrayComparer());
        protected readonly Dictionary<byte[], AddressData> myAddresses = new Dictionary<byte[], AddressData>(new IXICore.Utils.ByteArrayComparer());

        protected byte[] privateKey = null;
        protected byte[] publicKey = null;
        protected byte[] address = null;
        protected byte[] lastAddress = null;

        public WalletStorage()
        {

        }

        protected bool readWallet()
        {
            Logging.error("Wallet: readWallet override not found");
            return false;
        }

        public bool writeWallet(string password)
        {
            Logging.error("Wallet: writeWallet override not found");
            return false;
        }

        public bool backup(string destination)
        {
            Logging.error("Wallet: backup override not found");
            return false;
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
            // TODO TODO TODO TODO TODO improve if possible for v3 wallets
            // Also you have to take into account what happens when loading from file and the difference between v1 and v2 wallets (key related)
            lock (myAddresses)
            {
                return lastAddress;
            }
        }

        public byte[] getSeedHash()
        {
            return seedHash;
        }

        public IxiNumber getMyTotalBalance(byte[] primary_address)
        {
            IxiNumber balance = 0;
            lock (myAddresses)
            {
                foreach (var entry in myAddresses)
                {
                    if (primary_address != null && !entry.Value.keyPair.addressBytes.SequenceEqual(primary_address))
                    {
                        continue;
                    }
                    IxiNumber amount = Node.walletState.getWalletBalance(entry.Key);
                    if (amount == 0)
                    {
                        continue;
                    }
                    balance += amount;
                }
            }
            return balance;
        }

        public Address generateNewAddress(Address key_primary_address, bool write_to_file = true)
        {
            if(walletVersion < 2)
            {
                return generateNewAddress_v0(key_primary_address, write_to_file);
            }
            else
            {
                return generateNewAddress_v1(key_primary_address, write_to_file);
            }
        }

        public Address generateNewAddress_v0(Address key_primary_address, bool write_to_file = true)
        {
            lock (myKeys)
            {
                if (!myKeys.ContainsKey(key_primary_address.address))
                {
                    return null;
                }

                IxianKeyPair kp = myKeys[key_primary_address.address];

                byte[] base_nonce = Crypto.sha512quTrunc(privateKey, publicKey.Length, 64);

                byte[] last_nonce = kp.lastNonceBytes;

                List<byte> new_nonce = base_nonce.ToList();
                if (last_nonce != null)
                {
                    new_nonce.AddRange(last_nonce);
                }
                kp.lastNonceBytes = Crypto.sha512quTrunc(new_nonce.ToArray(), 0, 0, 16);

                Address new_address = new Address(key_primary_address.address, kp.lastNonceBytes);

                lock (myAddresses)
                {
                    AddressData ad = new AddressData() { nonce = kp.lastNonceBytes, keyPair = kp };
                    myAddresses.Add(new_address.address, ad);
                    lastAddress = new_address.address;
                }

                if (write_to_file)
                {
                    writeWallet(walletPassword);
                }

                return new_address;
            }
        }

        public Address generateNewAddress_v1(Address key_primary_address, bool write_to_file = true)
        {
            lock (myKeys)
            {
                if (!myKeys.ContainsKey(key_primary_address.address))
                {
                    return null;
                }

                IxianKeyPair kp = myKeys[key_primary_address.address];

                byte[] base_nonce = Crypto.sha512sqTrunc(privateKey, publicKey.Length, 64);

                byte[] last_nonce = kp.lastNonceBytes;

                List<byte> new_nonce = base_nonce.ToList();
                if (last_nonce != null)
                {
                    new_nonce.AddRange(last_nonce);
                }
                kp.lastNonceBytes = Crypto.sha512sqTrunc(new_nonce.ToArray(), 0, 0, 16);

                Address new_address = new Address(key_primary_address.address, kp.lastNonceBytes);

                lock (myAddresses)
                {
                    AddressData ad = new AddressData() { nonce = kp.lastNonceBytes, keyPair = kp };
                    myAddresses.Add(new_address.address, ad);
                    lastAddress = new_address.address;
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
            if (walletVersion < 3)
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
                        myKeys.Add(addr.address, kp);
                        AddressData ad = new AddressData() { nonce = kp.lastNonceBytes, keyPair = kp };
                        myAddresses.Add(addr.address, ad);
                    }
                    else
                    {
                        if (writeWallet(walletPassword))
                        {
                            myKeys.Add(addr.address, kp);
                            AddressData ad = new AddressData() { nonce = kp.lastNonceBytes, keyPair = kp };
                            myAddresses.Add(addr.address, ad);
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

        public AddressData getAddress(byte[] address)
        {
            lock (myAddresses)
            {
                if (myAddresses.ContainsKey(address))
                {
                    return myAddresses[address];
                }
            }
            return null;
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

        public List<byte[]> extractMyAddressesFromAddressList(SortedDictionary<byte[], IxiNumber> address_list)
        {
            lock (myAddresses)
            {
                List<byte[]> found_address_list = new List<byte[]>();
                foreach (var entry in address_list)
                {
                    if (myAddresses.ContainsKey(entry.Key))
                    {
                        found_address_list.Add(entry.Key);
                    }
                }
                if(found_address_list.Count > 0)
                {
                    return found_address_list;
                }
            }
            return null;
        }

        public List<Address> getMyAddresses()
        {
            lock (myAddresses)
            {
                return myAddresses.Select(x => new Address(x.Key)).ToList();
            }
        }

        public List<string> getMyAddressesBase58()
        {
            lock (myAddresses)
            {
                return myAddresses.Select(x => (new Address(x.Key)).ToString()).ToList();
            }
        }

        public SortedDictionary<byte[], IxiNumber> generateFromListFromAddress(byte[] from_address, IxiNumber total_amount_with_fee, bool full_pubkey = false)
        {
            lock (myAddresses)
            {
                SortedDictionary<byte[], IxiNumber> tmp_from_list = new SortedDictionary<byte[], IxiNumber>(new ByteArrayComparer());
                if (full_pubkey)
                {
                    if (!myAddresses.ContainsKey(from_address))
                    {
                        return null;
                    }
                    AddressData ad = myAddresses[from_address];
                    tmp_from_list.Add(ad.nonce, total_amount_with_fee);
                }
                else
                {
                    tmp_from_list.Add(new byte[1] { 0 }, total_amount_with_fee);
                }
                return tmp_from_list;
            }
        }

        public SortedDictionary<byte[], IxiNumber> generateFromList(byte[] primary_address, IxiNumber total_amount_with_fee, List<byte[]> skip_addresses)
        {
            lock(myAddresses)
            {
                Dictionary<byte[], IxiNumber> tmp_from_list = new Dictionary<byte[], IxiNumber>(new ByteArrayComparer());
                foreach (var entry in myAddresses)
                {
                    if(!entry.Value.keyPair.addressBytes.SequenceEqual(primary_address))
                    {
                        continue;
                    }

                    if (skip_addresses.Contains(entry.Value.keyPair.addressBytes, new ByteArrayComparer()))
                    {
                        continue;
                    }

                    Wallet wallet = Node.walletState.getWallet(entry.Key);
                    if(wallet.type != WalletType.Normal)
                    {
                        continue;
                    }

                    IxiNumber amount = wallet.balance;
                    if(amount == 0)
                    {
                        continue;
                    }

                    tmp_from_list.Add(entry.Value.nonce, amount);
                }

                var tmp_from_list_ordered = tmp_from_list.OrderBy(x => x.Value.getAmount());

                SortedDictionary<byte[], IxiNumber> from_list = new SortedDictionary<byte[], IxiNumber>(new ByteArrayComparer());

                IxiNumber tmp_total_amount = 0;
                foreach (var entry in tmp_from_list_ordered)
                {
                    if (tmp_total_amount + entry.Value >= total_amount_with_fee)
                    {
                        IxiNumber tmp_amount = total_amount_with_fee - tmp_total_amount;
                        from_list.Add(entry.Key, tmp_amount);
                        tmp_total_amount += tmp_amount;
                        break;
                    }
                    from_list.Add(entry.Key, entry.Value);
                    tmp_total_amount += entry.Value;
                }

                if (from_list.Count > 0 && tmp_total_amount == total_amount_with_fee)
                {
                    return from_list;
                }
                return null;
            }
        }

        public byte[] getNonceFromAddress(byte[] address)
        {
            foreach(var addr in myAddresses)
            {
                if(addr.Key.SequenceEqual(address))
                {
                    return addr.Value.nonce;
                }
            }
            return null;
        }
    }
}
