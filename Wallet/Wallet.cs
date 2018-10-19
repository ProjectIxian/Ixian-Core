using DLT.Meta;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace DLT
{
    public enum WalletType:byte
    {
        Normal,
        Multisig
    }

    public class Wallet
    {
        public byte[] id;
        public IxiNumber balance;
        public WalletType type;
        public byte requiredSigs;
        public byte[][] allowedSigners;
        public byte[] data;
        public ulong nonce;
        public byte[] publicKey;

        public byte countAllowedSigners
        {
            get
            {
                if (allowedSigners == null) return 0;
                return (byte)allowedSigners.Length;
            }
        }
        

        public Wallet()
        {
            id = null;
            balance = new IxiNumber();
            type = WalletType.Normal;
            requiredSigs = 1;
            allowedSigners = null;
            data = null;
            nonce = 0;
            publicKey = null;
        }

        public Wallet(byte[] w_id, IxiNumber w_balance)
        {
            id = w_id;
            balance = w_balance;
            type = WalletType.Normal;
            requiredSigs = 1;
            allowedSigners = null;
            data = null;
            nonce = 0;
            publicKey = null;
        }

        public Wallet(Wallet wallet)
        {
            id = wallet.id;
            balance = wallet.balance;
            type = wallet.type;
            requiredSigs = wallet.requiredSigs;
            if(wallet.allowedSigners != null)
            {
                allowedSigners = new byte[wallet.allowedSigners.Length][];
                for (int i = 0; i < wallet.allowedSigners.Length; i++)
                {
                    allowedSigners[i] = new byte[wallet.allowedSigners[i].Length];
                    Array.Copy(wallet.allowedSigners[i], allowedSigners[i], allowedSigners[i].Length);
                }
            }
            data = wallet.data;
            nonce = wallet.nonce;
            publicKey = wallet.publicKey;
        }

        public Wallet(byte[] bytes, bool legacy = false)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    try
                    {
                        int idLen = reader.ReadInt32();
                        id = reader.ReadBytes(idLen);
                        string balance_str = reader.ReadString();
                        balance = new IxiNumber(balance_str);
                        int dataLen = reader.ReadInt32();
                        data = reader.ReadBytes(dataLen);
                        nonce = reader.ReadUInt64();
                        type = (WalletType)reader.ReadByte();
                        requiredSigs = reader.ReadByte();
                        byte num_allowed_sigs = reader.ReadByte();
                        if (num_allowed_sigs > 0)
                        {
                            allowedSigners = new byte[num_allowed_sigs][];
                            for (int i = 0; i < num_allowed_sigs; i++)
                            {
                                int signerLen = reader.ReadInt32();
                                allowedSigners[i] = reader.ReadBytes(signerLen);
                            }
                        }
                        else
                        {
                            allowedSigners = null;
                        }

                        int pkLen = reader.ReadInt32();
                        publicKey = reader.ReadBytes(pkLen);
                    }
                    catch (Exception)
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
                        writer.Write(id.Length);
                        writer.Write(id);
                        writer.Write(balance.ToString());
                        writer.Write(data.Length);
                        writer.Write(data);
                        writer.Write(nonce);
                        writer.Write((byte)type);
                        writer.Write(requiredSigs);
                        if (allowedSigners != null)
                        {
                            writer.Write(allowedSigners.Length);
                            for (int i = 0; i < allowedSigners.Length; i++)
                            {
                                writer.Write(allowedSigners[i].Length);
                                writer.Write(allowedSigners[i]);
                            }
                        }
                        else
                        {
                            writer.Write((byte)0);
                        }
                        writer.Write(publicKey.Length);
                        writer.Write(publicKey);
                    }
                    catch (Exception)
                    {

                    }
                }
                return m.ToArray();
            }
        }

        public byte[] calculateChecksum()
        {
            List<byte> rawData = new List<byte>();
            rawData.AddRange(id);
            rawData.AddRange(Encoding.UTF8.GetBytes(balance.ToString()));
            if (data != null)
            {
                rawData.AddRange(data);
            }
            rawData.AddRange(BitConverter.GetBytes(nonce));
            if (publicKey != null)
            {
                rawData.AddRange(publicKey);
            }
            rawData.AddRange(BitConverter.GetBytes((int)type));
            rawData.AddRange(BitConverter.GetBytes(requiredSigs));
            return Crypto.sha256(rawData.ToArray());
        }

        public bool isValidSigner(byte[] address)
        {
            if (address.SequenceEqual(id)) return true;
            foreach(var accepted_pubkey in allowedSigners)
            {
                if (address.SequenceEqual(accepted_pubkey)) return true;
            }
            return false;
        }

        public void addValidSigner(byte[] address)
        {
            if (isValidSigner(address)) return;
            byte[][] tmp = new byte[allowedSigners.Length + 1][];
            for(int i=0;i<allowedSigners.Length;i++)
            {
                tmp[i] = allowedSigners[i];
            }
            tmp[allowedSigners.Length] = address;
            allowedSigners = tmp;
        }

        public void delValidSigner(byte[] address)
        {
            if (!isValidSigner(address)) return;
            if (id.SequenceEqual(address)) return; // can't remove self
            byte[][] tmp = new byte[allowedSigners.Length - 1][];
            int idx = 0;
            foreach(var allowed_signer in allowedSigners)
            {
                if (allowed_signer.SequenceEqual(address)) continue;
                tmp[idx] = allowed_signer;
                idx++;
            }
            allowedSigners = tmp;
        }
    }
}