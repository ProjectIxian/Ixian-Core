using DLT.Meta;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

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

        public int matchValidSigners(string[] pubkeys)
        {
            Dictionary<string, bool> matchedSigs = new Dictionary<string, bool>();
            if(allowedSigners == null)
            {
                matchedSigs.Add(id, false);
            } else
            {
                matchedSigs = allowedSigners.ToDictionary(k => k, v => false);
            }
            foreach (string key in pubkeys)
            {
                Address a = new Address(key);
                if(matchedSigs.ContainsKey(a.ToString()))
                {
                    matchedSigs[a.ToString()] = true;
                }
            }
            return matchedSigs.Aggregate(0, (sum, kvp) => sum += kvp.Value ? 1 : 0, sum => sum);
        }
    }
}