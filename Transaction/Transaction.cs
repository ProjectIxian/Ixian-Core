using DLT.Meta;
using IXICore;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace DLT
{
    public class Transaction
    {

        public enum Type:int
        {
            Normal = 0,
            PoWSolution = 1,
            StakingReward = 2,
            Genesis = 3,
            MultisigTX = 4,
            ChangeMultisigWallet = 5
        }

        public enum MultisigWalletChangeType:byte
        {
            AddSigner = 1, 
            DelSigner = 2, 
            ChangeReqSigs = 3
        }

        public struct MultisigAddrAdd
        {
            public string origTXId;
            public byte[] addrToAdd;
        }

        public struct MultisigAddrDel
        {
            public string origTXId;
            public byte[] addrToDel;
        }

        public struct MultisigChSig
        {
            public string origTXId;
            public byte reqSigs;
        }
        public int version; // 4
        public string id; //  not sent as part of the tx but around 50 bytes
        public int type; // 4
        public IxiNumber amount; // 32
        public IxiNumber fee; // 32
        public byte[] to; // 36
        public byte[] from; // 36
        public byte[] data; // 0
        public ulong blockHeight; // 8
        public int nonce; // 4
        public long timeStamp; // 8
        public byte[] checksum; // 32
        public byte[] signature; // 512
        public byte[] pubKey; // 0 or 512
        public ulong applied;

        private readonly static byte[] multisigStartMarker = { 0x4d, 0x73 };

        public Transaction()
        {
            version = 0;
            // This constructor is used only for development purposes
            id = Guid.NewGuid().ToString();
            type = (int) Type.Normal;
            timeStamp = Core.getCurrentTimestamp();
            fee = new IxiNumber("0");
            blockHeight = 0;

            Random r = new Random();
            nonce = (int)((DateTimeOffset.Now.ToUnixTimeMilliseconds() - (DateTimeOffset.Now.ToUnixTimeSeconds() * 1000)) * 100) + r.Next(100);

            applied = 0;
        }

        public Transaction(IxiNumber tx_amount, IxiNumber tx_fee, byte[] tx_to, byte[] tx_from, byte[] tx_data, byte[] tx_pubKey, ulong tx_blockHeight)
        {
            version = 0;

            //id = Guid.NewGuid().ToString();
            type = (int)Transaction.Type.Normal;

            amount = tx_amount;
            fee = tx_fee;
            to = tx_to;
            from = tx_from;

            data = tx_data;

            blockHeight = tx_blockHeight;

            Random r = new Random();
            nonce = (int) ((DateTimeOffset.Now.ToUnixTimeMilliseconds() - (DateTimeOffset.Now.ToUnixTimeSeconds() * 1000))*100) + r.Next(100);

            timeStamp = Core.getCurrentTimestamp();

            pubKey = tx_pubKey;

            id = generateID();
            checksum = calculateChecksum(this);
            signature = getSignature(checksum);

        }

        public Transaction(Transaction tx_transaction)
        {
            version = tx_transaction.version;
            id = tx_transaction.id;
            type = tx_transaction.type;
            amount = tx_transaction.amount;
            fee = tx_transaction.fee;

            to = new byte[tx_transaction.to.Length];
            Array.Copy(tx_transaction.to, to, to.Length);

            from = new byte[tx_transaction.from.Length];
            Array.Copy(tx_transaction.from, from, from.Length);

            data = new byte[tx_transaction.data.Length];
            Array.Copy(tx_transaction.data, data, data.Length);

            blockHeight = tx_transaction.blockHeight;
            nonce = tx_transaction.nonce;
            timeStamp = tx_transaction.timeStamp;

            checksum = new byte[tx_transaction.checksum.Length];
            Array.Copy(tx_transaction.checksum, checksum, checksum.Length);

            signature = new byte[tx_transaction.signature.Length];
            Array.Copy(tx_transaction.signature, signature, signature.Length);

            pubKey = new byte[tx_transaction.pubKey.Length];
            Array.Copy(tx_transaction.pubKey, pubKey, pubKey.Length);

        }

        public Transaction(byte[] bytes)
        {
            try
            {
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        version = reader.ReadInt32();

                        type = reader.ReadInt32();
                        amount = new IxiNumber(reader.ReadString());
                        fee = new IxiNumber(reader.ReadString());

                        int toLen = reader.ReadInt32();
                        to = reader.ReadBytes(toLen);

                        int fromLen = reader.ReadInt32();
                        from = reader.ReadBytes(fromLen);

                        int  dataLen = reader.ReadInt32();
                        if (dataLen > 0)
                        {
                            data = reader.ReadBytes(dataLen);
                        }

                        blockHeight = reader.ReadUInt64();

                        nonce = reader.ReadInt32();

                        timeStamp = reader.ReadInt64();

                        int crcLen = reader.ReadInt32();
                        checksum = reader.ReadBytes(crcLen);

                        int sigLen = reader.ReadInt32();
                        if (sigLen > 0)
                        {
                            signature = reader.ReadBytes(sigLen);
                        }

                        int pkLen = reader.ReadInt32();
                        if (pkLen > 0)
                        {
                            pubKey = reader.ReadBytes(pkLen);
                        }

                        id = generateID();
                    }
                }
            }
            catch(Exception e)
            {              
                Logging.error("Exception occured while trying to construct Transaction from bytes: " + e);
                throw;
            }
        }

        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(version);

                    writer.Write(type);
                    writer.Write(amount.ToString());
                    writer.Write(fee.ToString());
                    writer.Write(to.Length);
                    writer.Write(to);
                    writer.Write(from.Length);
                    writer.Write(from);
                    if (data != null)
                    {
                        writer.Write(data.Length);
                        writer.Write(data);
                    }else
                    {
                        writer.Write((int)0);
                    }
                    writer.Write(blockHeight);
                    writer.Write(nonce);

                    writer.Write(timeStamp);

                    writer.Write(checksum.Length);
                    writer.Write(checksum);

                    if (signature != null)
                    {
                        writer.Write(signature.Length);
                        writer.Write(signature);
                    }else
                    {
                        writer.Write((int)0);
                    }

                    if (pubKey != null)
                    {
                        writer.Write(pubKey.Length);
                        writer.Write(pubKey);
                    }else
                    {
                        writer.Write((int)0);
                    }
                }
                return m.ToArray();
            }
        }

        // Checks two transactions for duplicates
        public bool equals(Transaction tx)
        {
            byte[] a1 = getBytes();
            byte[] a2 = tx.getBytes();

            return a1.SequenceEqual(a2);
        }

        // Verifies the transaction signature and returns true if valid
        public bool verifySignature(byte[] pubkey)
        {
            if(pubkey == null)
            {
                return false;
            }

            // Skip signature verification for staking rewards
            if (type == (int)Type.StakingReward || type == (int)Type.Genesis)
            {
                return true;
            }

            Address p_address = new Address(pubkey);
            bool allowed = false;
            Wallet from_wallet = Node.walletState.getWallet(from);
            if(from_wallet != null && from_wallet.id.SequenceEqual(p_address.address))
            {
                allowed = true;
            } else if (type==(int)Transaction.Type.MultisigTX || type == (int)Transaction.Type.ChangeMultisigWallet)
            {
                // pubkey must be one of the allowed signers on wallet
                if(from_wallet.allowedSigners != null)
                {
                    foreach(var allowed_signer in from_wallet.allowedSigners)
                    {
                        if(allowed_signer.SequenceEqual(p_address.address))
                        {
                            allowed = true;
                        }
                    }
                }
            }

            if (!allowed) return false;

            // Verify the signature
            return CryptoManager.lib.verifySignature(checksum, pubkey, signature);
        }

        // Generates the transaction ID
        public string generateID()
        {
            string txid = "";

            if(type == (int)Type.StakingReward)
            {

                if (data != null)
                {
                    ulong blockNum = BitConverter.ToUInt64(data, 0);
                    if (blockNum > 0)
                    {
                        txid = "stk-" + blockNum + "-";
                    }
                }
            }

            txid += blockHeight + "-";

            List<byte> rawData = new List<byte>();
            rawData.AddRange(BitConverter.GetBytes(type));
            rawData.AddRange(Encoding.UTF8.GetBytes(amount.ToString()));
            rawData.AddRange(Encoding.UTF8.GetBytes(fee.ToString()));
            rawData.AddRange(to);
            rawData.AddRange(from);
            rawData.AddRange(BitConverter.GetBytes(blockHeight));
            rawData.AddRange(BitConverter.GetBytes(nonce));
            rawData.AddRange(BitConverter.GetBytes(version));
            string chk = Base58Check.Base58CheckEncoding.EncodePlain(Crypto.sha512sqTrunc(rawData.ToArray()));

            txid += chk;

            return txid;
        }

        public static bool verifyTransactionID(Transaction transaction)
        {
            string txid = "";

            if (transaction.type == (int)Type.StakingReward)
            {
                if (transaction.data != null)
                {
                    ulong blockNum = BitConverter.ToUInt64(transaction.data, 0);
                    if (blockNum > 0)
                    {
                        txid = "stk-" + blockNum + "-";
                    }
                }
            }

            txid += transaction.blockHeight + "-";

            List<byte> rawData = new List<byte>();
            rawData.AddRange(BitConverter.GetBytes(transaction.type));
            rawData.AddRange(Encoding.UTF8.GetBytes(transaction.amount.ToString()));
            rawData.AddRange(Encoding.UTF8.GetBytes(transaction.fee.ToString()));
            rawData.AddRange(transaction.to);
            rawData.AddRange(transaction.from);
            rawData.AddRange(BitConverter.GetBytes(transaction.blockHeight));
            rawData.AddRange(BitConverter.GetBytes(transaction.nonce));
            rawData.AddRange(BitConverter.GetBytes(transaction.version));
            string chk = Base58Check.Base58CheckEncoding.EncodePlain(Crypto.sha512sqTrunc(rawData.ToArray()));

            txid += chk;

            if (transaction.id.Equals(txid, StringComparison.Ordinal))
            {
                return true;
            }

            return false;
        }

        // Calculate a transaction checksum 
        public static byte[] calculateChecksum(Transaction transaction)
        {
            List<byte> rawData = new List<byte>();
            rawData.AddRange(CoreConfig.ixianChecksumLock);
            rawData.AddRange(Encoding.UTF8.GetBytes(transaction.id));
            rawData.AddRange(BitConverter.GetBytes(transaction.type));
            rawData.AddRange(Encoding.UTF8.GetBytes(transaction.amount.ToString()));
            rawData.AddRange(Encoding.UTF8.GetBytes(transaction.fee.ToString()));
            rawData.AddRange(transaction.to);
            rawData.AddRange(transaction.from);
            if (transaction.data != null)
            {
                rawData.AddRange(transaction.data);
            }
            rawData.AddRange(BitConverter.GetBytes(transaction.blockHeight));
            rawData.AddRange(BitConverter.GetBytes(transaction.nonce));
            rawData.AddRange(BitConverter.GetBytes(transaction.timeStamp));
            rawData.AddRange(BitConverter.GetBytes(transaction.version));
            if(transaction.pubKey != null)
            {
                rawData.AddRange(transaction.pubKey);
            }
            return Crypto.sha512sqTrunc(rawData.ToArray());
        }

        public static byte[] getSignature(byte[] checksum)
        {
            return CryptoManager.lib.getSignature(checksum, Node.walletStorage.privateKey);
        }

        private void AddMultisigOrig(string orig_txid)
        {
            byte[] orig_txid_bytes = Encoding.UTF8.GetBytes(orig_txid);
            using (MemoryStream ms = new MemoryStream(4 + orig_txid_bytes.Length))
            {
                using (BinaryWriter bw = new BinaryWriter(ms))
                {
                    bw.Write(multisigStartMarker[0]);
                    bw.Write(multisigStartMarker[1]);
                    if (orig_txid == null || orig_txid == "")
                    {
                        bw.Write((int)0);
                    }
                    else
                    {
                        bw.Write(orig_txid_bytes.Length);
                        bw.Write(orig_txid_bytes);
                    }
                    data = ms.ToArray();
                }
            }
        }

        private void AddMultisigChWallet (string orig_txid, byte[] addr, MultisigWalletChangeType change_type)
        {
            byte[] orig_txid_bytes = Encoding.UTF8.GetBytes(orig_txid);
            using (MemoryStream ms = new MemoryStream(4 + orig_txid_bytes.Length))
            {
                using (BinaryWriter bw = new BinaryWriter(ms))
                {
                    bw.Write(multisigStartMarker[0]);
                    bw.Write(multisigStartMarker[1]);
                    if (orig_txid == null || orig_txid == "")
                    {
                        bw.Write((int)0);
                    }
                    else
                    {
                        bw.Write(orig_txid_bytes.Length);
                        bw.Write(orig_txid_bytes);
                    }
                    bw.Write((byte)change_type);
                    bw.Write(addr.Length);
                    bw.Write(addr);
                    data = ms.ToArray();
                }
            }
        }

        private void AddMultisigChReqSigs(string orig_txid, byte num_sigs)
        {
            byte[] orig_txid_bytes = Encoding.UTF8.GetBytes(orig_txid);
            using (MemoryStream ms = new MemoryStream(4 + orig_txid_bytes.Length))
            {
                using (BinaryWriter bw = new BinaryWriter(ms))
                {
                    bw.Write(multisigStartMarker[0]);
                    bw.Write(multisigStartMarker[1]);
                    if (orig_txid == null || orig_txid == "")
                    {
                        bw.Write((int)0);
                    }
                    else
                    {
                        bw.Write(orig_txid_bytes.Length);
                        bw.Write(orig_txid_bytes);
                    }
                    bw.Write((byte)MultisigWalletChangeType.ChangeReqSigs);
                    bw.Write(num_sigs);
                    data = ms.ToArray();
                }
            }
        }

        public object GetMultisigData()
        {
            if (type == (int)Transaction.Type.MultisigTX)
            {
                if (data == null || data.Length < 6)
                {
                    return null;
                }
                using (MemoryStream ms = new MemoryStream(data))
                {
                    using (BinaryReader rd = new BinaryReader(ms))
                    {
                        try
                        {
                            byte start_marker_1 = rd.ReadByte();
                            byte start_marker_2 = rd.ReadByte();
                            if (start_marker_1 != multisigStartMarker[0] || start_marker_2 != multisigStartMarker[1])
                            {
                                Logging.warn(String.Format("Multisig transaction: Invalid multisig transaction: Data start marker does not match! ({0}, {1})", start_marker_1, start_marker_2));
                                return null;
                            }
                            int orig_tx_len = rd.ReadInt32();
                            if (orig_tx_len < 0 || orig_tx_len > 100)
                            {
                                Logging.warn(String.Format("Multisig transaction: Invalid origin TXID length stored in data: {0}", orig_tx_len));
                                return null;
                            }
                            if (orig_tx_len == 0)
                            {
                                return "";
                            }
                            byte[] orig_txid = rd.ReadBytes(orig_tx_len);
                            if (orig_txid == null || orig_txid.Length < orig_tx_len)
                            {
                                Logging.warn(String.Format("Multisig transaction: Invalid or missing origin txid!"));
                                return null;
                            }
                            return Encoding.UTF8.GetString(orig_txid);
                        } catch(Exception)
                        {
                            // early EOF or some strange data error
                            return null;
                        }
                    }
                }
            }
            else if (type == (int)Transaction.Type.ChangeMultisigWallet)
            {
                if (data == null || data.Length < 6)
                {
                    return null;
                }
                string orig_txid = "";
                using (MemoryStream ms = new MemoryStream(data))
                {
                    using (BinaryReader rd = new BinaryReader(ms))
                    {
                        try
                        {
                            byte start_marker_1 = rd.ReadByte();
                            byte start_marker_2 = rd.ReadByte();
                            if (start_marker_1 != multisigStartMarker[0] || start_marker_2 != multisigStartMarker[1])
                            {
                                Logging.warn(String.Format("Multisig change transaction: Invalid multisig transaction: Data start marker does not match! ({0}, {1})", start_marker_1, start_marker_2));
                                return null;
                            }
                            int orig_tx_len = rd.ReadInt32();
                            if (orig_tx_len < 0 || orig_tx_len > 100)
                            {
                                Logging.warn(String.Format("Multisig change transaction: Invalid origin TXID length stored in data: {0}", orig_tx_len));
                                return null;
                            }
                            if (orig_tx_len == 0)
                            {
                                orig_txid = "";
                            }
                            else
                            {
                                byte[] orig_txid_bytes = rd.ReadBytes(orig_tx_len);
                                if (orig_txid == null || orig_txid_bytes.Length < orig_tx_len)
                                {
                                    Logging.warn(String.Format("Multisig change transaction: Invalid or missing origin txid!"));
                                    return null;
                                }
                                orig_txid = Encoding.UTF8.GetString(orig_txid_bytes);
                            }
                            // multisig change type
                            MultisigWalletChangeType change_type = (MultisigWalletChangeType)rd.ReadByte();
                            switch(change_type)
                            {
                                case MultisigWalletChangeType.AddSigner:
                                    int ch_addr_len = rd.ReadInt32();
                                    if(ch_addr_len <=0|| ch_addr_len > 36)
                                    {
                                        Logging.warn("Multisig change transaction: Adding signer, but the data does not contain a valid address!");
                                        return null;
                                    }
                                    byte[] ch_addr = rd.ReadBytes(ch_addr_len);
                                    if(ch_addr == null || ch_addr.Length < ch_addr_len)
                                    {
                                        Logging.warn("Multisig change transaction: Adding signer, but the address data was corrupted.");
                                        return null;
                                    }
                                    return new MultisigAddrAdd
                                    {
                                        origTXId = orig_txid,
                                        addrToAdd = ch_addr
                                    };
                                case MultisigWalletChangeType.DelSigner:
                                    ch_addr_len = rd.ReadInt32();
                                    if (ch_addr_len <= 0 || ch_addr_len > 36)
                                    {
                                        Logging.warn("Multisig change transaction: Deleting signer, but the data does not contain a valid address!");
                                        return null;
                                    }
                                    ch_addr = rd.ReadBytes(ch_addr_len);
                                    if (ch_addr == null || ch_addr.Length < ch_addr_len)
                                    {
                                        Logging.warn("Multisig change transaction: Deleting signer, but the address data was corrupted.");
                                        return null;
                                    }
                                    return new MultisigAddrDel
                                    {
                                        origTXId = orig_txid,
                                        addrToDel = ch_addr
                                    };
                                case MultisigWalletChangeType.ChangeReqSigs:
                                    byte new_req_sigs = rd.ReadByte();
                                    return new MultisigChSig
                                    {
                                        origTXId = orig_txid,
                                        reqSigs = new_req_sigs
                                    };
                                default:
                                    Logging.warn(String.Format("Invalid MultisigWalletChangeType for a multisig change transaction {{ {0} }}.", id));
                                    return null;
                            }
                        } catch(Exception)
                        {
                            // early EOL or strange data error
                            return null;
                        }
                    }
                }
            }
            else
            {
                Logging.info(String.Format("Transaction {{ {0} }} is not a multisig transaction, so MultisigData cannot be retrieved.", id));
                return null;
            }
        }

        public static Transaction multisigTransaction(string orig_txid, IxiNumber tx_amount, IxiNumber tx_fee, byte[] tx_to, byte[] tx_from, ulong tx_blockHeight)
        {
            Transaction t = new Transaction(tx_amount, tx_fee, tx_to, tx_from, null, Node.walletStorage.publicKey, tx_blockHeight);
            t.type = (int)Transaction.Type.MultisigTX;
            t.AddMultisigOrig(orig_txid);
            // overwrite invalid values where were calcualted before the multisig flag was set
            t.id = t.generateID();
            t.checksum = calculateChecksum(t);
            t.signature = getSignature(t.checksum);
            return t;
        }

        public static Transaction multisigAddKeyTransaction(string orig_txid, byte[] allowed_address,  IxiNumber tx_fee, byte[] tx_from, ulong tx_blockHeight)
        {
            Transaction t = new Transaction
            {
                type = (int)Transaction.Type.ChangeMultisigWallet,
                amount = new IxiNumber(0),
                fee = tx_fee,
                from = tx_from,
                to = tx_from,
                blockHeight = tx_blockHeight
            };
            t.AddMultisigChWallet(orig_txid, allowed_address, MultisigWalletChangeType.AddSigner);
            //
            t.pubKey = Node.walletStorage.publicKey;
            t.id = t.generateID();
            t.checksum = calculateChecksum(t);
            t.signature = getSignature(t.checksum);
            return t;
        }

        public static Transaction multisigDelKeyTransaction(string orig_txid, byte[] disallowed_address, IxiNumber tx_fee, byte[] tx_from, ulong tx_blockHeight)
        {
            Transaction t = new Transaction
            {
                type = (int)Transaction.Type.ChangeMultisigWallet,
                amount = new IxiNumber(0),
                fee = tx_fee,
                from = tx_from,
                to = tx_from,
                blockHeight = tx_blockHeight
            };
            t.AddMultisigChWallet(orig_txid, disallowed_address, MultisigWalletChangeType.DelSigner);
            //
            t.pubKey = Node.walletStorage.publicKey;
            t.id = t.generateID();
            t.checksum = calculateChecksum(t);
            t.signature = getSignature(t.checksum);
            return t;
        }

        public static Transaction multisigChangeReqSigs(string orig_txid, byte sigs, IxiNumber tx_fee, byte[] tx_from, ulong tx_blockHeight)
        {
            Transaction t = new Transaction
            {
                type = (int)Transaction.Type.ChangeMultisigWallet,
                amount = new IxiNumber(0),
                fee = tx_fee,
                from = tx_from,
                to = tx_from,
                blockHeight = tx_blockHeight
            };
            t.AddMultisigChReqSigs(orig_txid, sigs);
            //
            t.pubKey = Node.walletStorage.publicKey;
            t.id = t.generateID();
            t.checksum = calculateChecksum(t);
            t.signature = getSignature(t.checksum);
            return t;
        }
    }
}