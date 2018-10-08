using DLT.Meta;
using System;
using System.IO;

namespace DLT
{
    public enum WalletType:byte
    {
        Normal,
        Multisig
    }

    public class Wallet
    {
        public string id; // 36 B (18 B)
        public IxiNumber balance; // 16 B
        public WalletType type;
        public byte requiredSigs;
        public string[] allowedSigners;
        public string data; // 0 B
        public ulong nonce;

        // TOTAL: 52 B (34 B). Note: add nonce

        public Wallet()
        {
            id = "";
            balance = new IxiNumber();
            type = WalletType.Normal;
            requiredSigs = 1;
            allowedSigners = null;
            data = "";
            nonce = 0;
        }

        public Wallet(string w_id, IxiNumber w_balance)
        {
            id = w_id;
            balance = w_balance;
            type = WalletType.Normal;
            requiredSigs = 1;
            allowedSigners = null;
            data = "";
            nonce = 0;
        }

        public Wallet(Wallet wallet)
        {
            id = wallet.id;
            balance = wallet.balance;
            type = wallet.type;
            requiredSigs = wallet.requiredSigs;
            if(wallet.allowedSigners != null)
            {
                allowedSigners = new string[wallet.allowedSigners.Length];
                Array.Copy(wallet.allowedSigners, allowedSigners, allowedSigners.Length);
            }
            data = wallet.data;
            nonce = wallet.nonce;
        }

        public Wallet(byte[] bytes)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    try
                    {
                        id = reader.ReadString();
                        string balance_str = reader.ReadString();
                        balance = new IxiNumber(balance_str);
                        data = reader.ReadString();
                        nonce = reader.ReadUInt64();
                        type = (WalletType)reader.ReadByte();
                        requiredSigs = reader.ReadByte();
                        byte num_allowed_sigs = reader.ReadByte();
                        if (num_allowed_sigs > 0)
                        {
                            allowedSigners = new string[num_allowed_sigs];
                            for (int i = 0; i < num_allowed_sigs; i++)
                            {
                                allowedSigners[i] = reader.ReadString();
                            }
                        }
                        else
                        {
                            allowedSigners = null;
                        }
                    }
                    catch(Exception)
                    {
                        
                    }
                }
            }
        }

        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    try
                    {
                        writer.Write(id);
                        writer.Write(balance.ToString());
                        writer.Write(data);
                        writer.Write(nonce);
                        writer.Write((byte)type);
                        writer.Write(requiredSigs);
                        if (allowedSigners != null)
                        {
                            writer.Write(allowedSigners.Length);
                            for (int i = 0; i < allowedSigners.Length; i++)
                            {
                                writer.Write(allowedSigners[i]);
                            }
                        }
                        else
                        {
                            writer.Write((byte)0);
                        }
                    }
                    catch(Exception)
                    {

                    }
                }
                return m.ToArray();
            }
        }

        public string calculateChecksum()
        {
            string baseData = id + balance.ToString() + data + nonce + ((int)type).ToString() + requiredSigs.ToString();
            return Crypto.sha256(baseData);
        }

        public void addSigningAddress(string address)
        {
            lock (id)
            {
                if (allowedSigners == null)
                {
                    allowedSigners = new string[1];
                    allowedSigners[0] = address;
                    Logging.info(String.Format("Converting wallet {0} to a multisig wallet.", id));
                    type = WalletType.Multisig;
                    requiredSigs = 1;
                }
                else
                {
                    if (allowedSigners.Length >= 255)
                    {
                        Logging.warn("Attempted to add a signing address to a wallet that already has 255 signing wallets (max).");
                        return;
                    }
                    string[] tmp = new string[allowedSigners.Length + 1];
                    Array.Copy(allowedSigners, tmp, allowedSigners.Length);
                    tmp[allowedSigners.Length] = address;
                    allowedSigners = tmp;
                }
            }
        }

        public void setMinimumsignatures(byte numSigs)
        {
            if(type != WalletType.Multisig)
            {
                Logging.warn(String.Format("Unable to set minimum signatures for a non-multisig wallet {0}!", id));
                return;
            }
            if(numSigs > allowedSigners.Length+1)
            {
                Logging.warn(String.Format("Attempting to set signature minimum to {0}, but wallet only has {1} pubkeys on the allowed list!",
                    numSigs, allowedSigners.Length + 1));
                return;
            }
            requiredSigs = numSigs;
        }
    }
}