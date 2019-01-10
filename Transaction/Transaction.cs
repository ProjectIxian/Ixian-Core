using DLT.Meta;
using IXICore;
using IXICore.Utils;
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
            public byte[] signerPubKey;
            public byte[] signerNonce;
        }

        public struct MultisigAddrDel
        {
            public string origTXId;
            public byte[] addrToDel;
            public byte[] signerPubKey;
            public byte[] signerNonce;
        }

        public struct MultisigChSig
        {
            public string origTXId;
            public byte reqSigs;
            public byte[] signerPubKey;
            public byte[] signerNonce;
        }

        public struct MultisigTxData
        {
            public string origTXId;
            public byte[] signerPubKey;
            public byte[] signerNonce;
        }

        public int version; // 4
        public string id; //  not sent as part of the tx but around 50 bytes
        public int type; // 4
        public IxiNumber amount = new IxiNumber("0"); // 32
        public IxiNumber fee = new IxiNumber("0"); // 32

        public SortedDictionary<byte[], IxiNumber> fromList = new SortedDictionary<byte[], IxiNumber>(new ByteArrayComparer());
        public SortedDictionary<byte[], IxiNumber> toList = new SortedDictionary<byte[], IxiNumber>(new ByteArrayComparer());

        public byte[] data; // 0
        public ulong blockHeight; // 8
        public int nonce; // 4
        public long timeStamp; // 8
        public byte[] checksum; // 32
        public byte[] signature; // 512
        public byte[] pubKey; // 0 or 512
        public ulong applied;

        public bool fromLocalStorage = false;

        private readonly static byte[] multisigStartMarker = { 0x4d, 0x73 };

        public static int maxVersion = 2;

        public Transaction(int tx_type)
        {
            version = 1;

            type = tx_type;

            timeStamp = Core.getCurrentTimestamp();
            amount = new IxiNumber("0");
            fee = new IxiNumber("0");
            blockHeight = 0;

            Random r = new Random();
            nonce = (int)((DateTimeOffset.Now.ToUnixTimeMilliseconds() - (DateTimeOffset.Now.ToUnixTimeSeconds() * 1000)) * 100) + r.Next(100);

            applied = 0;
        }

        public Transaction(int tx_type, IxiNumber tx_amount, IxiNumber tx_feePerKb, byte[] tx_to, byte[] tx_from, byte[] tx_data, byte[] tx_pubKey, ulong tx_blockHeight, int tx_nonce = -1)
        {
            version = 1;

            type = tx_type;

            amount = tx_amount;
            toList.Add(tx_to, amount);
            fromList.Add(new byte[1] { 0 }, amount);

            data = tx_data;

            blockHeight = tx_blockHeight;

            if (tx_nonce == -1)
            {
                Random r = new Random();
                nonce = (int)((DateTimeOffset.Now.ToUnixTimeMilliseconds() - (DateTimeOffset.Now.ToUnixTimeSeconds() * 1000)) * 100) + r.Next(100);
            }else
            {
                nonce = tx_nonce;
            }

            timeStamp = Core.getCurrentTimestamp();

            pubKey = tx_pubKey;
            if(pubKey == null)
            {
                pubKey = tx_from;
            }

            fee = calculateMinimumFee(tx_feePerKb);
            fromList[fromList.First().Key] = amount + fee;

            generateChecksums();

            if(type == (int)Transaction.Type.StakingReward)
            {
                signature = Encoding.UTF8.GetBytes("Stake");
            }
            else
            {
                signature = getSignature(checksum);
            }
        }

        public Transaction(int tx_type, IxiNumber tx_feePerKb, SortedDictionary<byte[], IxiNumber> tx_toList, byte[] tx_from, byte[] tx_data, byte[] tx_pubKey, ulong tx_blockHeight, int tx_nonce = -1)
        {
            version = 1;

            type = tx_type;


            toList = tx_toList;

            amount = calculateTotalAmount();

            fromList.Add(new byte[1] { 0 }, amount);

            data = tx_data;

            blockHeight = tx_blockHeight;

            if (tx_nonce == -1)
            {
                Random r = new Random();
                nonce = (int)((DateTimeOffset.Now.ToUnixTimeMilliseconds() - (DateTimeOffset.Now.ToUnixTimeSeconds() * 1000)) * 100) + r.Next(100);
            }
            else
            {
                nonce = tx_nonce;
            }

            timeStamp = Core.getCurrentTimestamp();

            pubKey = tx_pubKey;
            if (pubKey == null)
            {
                pubKey = tx_from;
            }

            fee = calculateMinimumFee(tx_feePerKb);
            fromList[fromList.First().Key] = amount + fee;

            generateChecksums();

            if (type == (int)Transaction.Type.StakingReward)
            {
                signature = Encoding.UTF8.GetBytes("Stake");
            }
            else
            {
                signature = getSignature(checksum);
            }
        }


        public Transaction(int tx_type, IxiNumber tx_feePerKb, SortedDictionary<byte[], IxiNumber> tx_toList, SortedDictionary<byte[], IxiNumber> tx_fromList, byte[] tx_data, byte[] tx_pubKey, ulong tx_blockHeight, int tx_nonce = -1, int tmp_version = 1)
        {
            version = tmp_version;

            type = tx_type;


            toList = tx_toList;

            amount = calculateTotalAmount();

            fromList = tx_fromList;

            data = tx_data;

            blockHeight = tx_blockHeight;

            if (tx_nonce == -1)
            {
                Random r = new Random();
                nonce = (int)((DateTimeOffset.Now.ToUnixTimeMilliseconds() - (DateTimeOffset.Now.ToUnixTimeSeconds() * 1000)) * 100) + r.Next(100);
            }
            else
            {
                nonce = tx_nonce;
            }

            timeStamp = Core.getCurrentTimestamp();

            pubKey = tx_pubKey;

            fee = calculateMinimumFee(tx_feePerKb);

            generateChecksums();

            if (type == (int)Transaction.Type.StakingReward)
            {
                signature = Encoding.UTF8.GetBytes("Stake");
            }
            else
            {
                signature = getSignature(checksum);
            }
        }

        public Transaction(Transaction tx_transaction)
        {
            version = tx_transaction.version;
            id = tx_transaction.id;
            type = tx_transaction.type;
            amount = new IxiNumber(tx_transaction.amount.getAmount());
            fee = new IxiNumber(tx_transaction.fee.getAmount());

            toList = new SortedDictionary<byte[], IxiNumber>(new ByteArrayComparer());

            foreach (var entry in tx_transaction.toList)
            {
                byte[] address = new byte[entry.Key.Length];
                Array.Copy(entry.Key, address, address.Length);
                toList.Add(address, new IxiNumber(entry.Value.getAmount()));
            }

            fromList = new SortedDictionary<byte[], IxiNumber>(new ByteArrayComparer());

            foreach (var entry in tx_transaction.fromList)
            {
                byte[] address = new byte[entry.Key.Length];
                Array.Copy(entry.Key, address, address.Length);
                fromList.Add(address, new IxiNumber(entry.Value.getAmount()));
            }


            if (tx_transaction.data != null)
            {
                data = new byte[tx_transaction.data.Length];
                Array.Copy(tx_transaction.data, data, data.Length);
            }

            blockHeight = tx_transaction.blockHeight;
            nonce = tx_transaction.nonce;
            timeStamp = tx_transaction.timeStamp;

            if (tx_transaction.checksum != null)
            {
                checksum = new byte[tx_transaction.checksum.Length];
                Array.Copy(tx_transaction.checksum, checksum, checksum.Length);
            }

            if (tx_transaction.signature != null)
            {
                signature = new byte[tx_transaction.signature.Length];
                Array.Copy(tx_transaction.signature, signature, signature.Length);
            }

            if (tx_transaction.pubKey != null)
            {
                pubKey = new byte[tx_transaction.pubKey.Length];
                Array.Copy(tx_transaction.pubKey, pubKey, pubKey.Length);
            }

            applied = tx_transaction.applied;

            fromLocalStorage = tx_transaction.fromLocalStorage;
        }

        public Transaction(byte[] bytes)
        {
            try
            {
                if (bytes.Length > 102400)
                {
                    throw new Exception("Transaction size is bigger then 100kB.");
                }
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        version = reader.ReadInt32();

                        if (version <= maxVersion)
                        {

                            type = reader.ReadInt32();
                            amount = new IxiNumber(reader.ReadString());
                            fee = new IxiNumber(reader.ReadString());

                            int toListLen = reader.ReadInt32();
                            for (int i = 0; i < toListLen; i++)
                            {
                                int addrLen = reader.ReadInt32();
                                byte[] address = reader.ReadBytes(addrLen);
                                IxiNumber amount = new IxiNumber(reader.ReadString());
                                toList.Add(address, amount);
                            }

                            if (version <= 1)
                            {
                                int fromLen = reader.ReadInt32();
                                pubKey = reader.ReadBytes(fromLen);
                                fromList.Add(new byte[1] { 0 }, amount + fee);
                            }
                            else
                            {
                                int fromListLen = reader.ReadInt32();
                                for (int i = 0; i < fromListLen; i++)
                                {
                                    int addrLen = reader.ReadInt32();
                                    byte[] address = reader.ReadBytes(addrLen);
                                    IxiNumber amount = new IxiNumber(reader.ReadString());
                                    fromList.Add(address, amount);
                                }
                            }

                            int dataLen = reader.ReadInt32();
                            if (dataLen > 0)
                            {
                                data = reader.ReadBytes(dataLen);
                            }

                            blockHeight = reader.ReadUInt64();

                            nonce = reader.ReadInt32();

                            timeStamp = reader.ReadInt64();

                            int crcLen = reader.ReadInt32();
                            if (crcLen > 0)
                            {
                                checksum = reader.ReadBytes(crcLen);
                            }

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

                    writer.Write(toList.Count);
                    foreach (var entry in toList)
                    {
                        writer.Write(entry.Key.Length);
                        writer.Write(entry.Key);
                        writer.Write(entry.Value.ToString());
                    }

                    if (version <= 1)
                    {
                        byte[] tmp_address = (new Address(pubKey)).address;
                        writer.Write(tmp_address.Length);
                        writer.Write(tmp_address);
                    }else
                    {
                        writer.Write(fromList.Count);
                        foreach (var entry in fromList)
                        {
                            writer.Write(entry.Key.Length);
                            writer.Write(entry.Key);
                            writer.Write(entry.Value.ToString());
                        }
                    }

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

                    if (checksum != null)
                    {
                        writer.Write(checksum.Length);
                        writer.Write(checksum);
                    }
                    else
                    {
                        writer.Write((int)0);
                    }

                    if (signature != null)
                    {
                        writer.Write(signature.Length);
                        writer.Write(signature);
                    }else
                    {
                        writer.Write((int)0);
                    }

                    if ((version <= 1 && pubKey != null && pubKey.Length > 36)
                        || version >= 2)
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
        public bool verifySignature(byte[] pubkey, byte[] nonce)
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

            Address p_address = new Address(pubkey, nonce);
            bool allowed = false;
            Wallet from_wallet = Node.walletState.getWallet((new Address(this.pubKey)).address);
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

            if(signature == null || pubkey == null)
            {
                Logging.warn("Signature or pubkey for received txid {0} was null, verification failed.", id);
                return false;
            }

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

            if (toList.Count == 1)
            {
                rawData.AddRange(toList.ToArray()[0].Key);
            }
            else
            {
                foreach (var entry in toList)
                {
                    rawData.AddRange(entry.Key);
                    rawData.AddRange(entry.Value.getAmount().ToByteArray());
                }
            }

            if (fromList.Count == 1)
            {
                rawData.AddRange(new Address(pubKey).address);
            }
            else
            {
                foreach (var entry in fromList)
                {
                    rawData.AddRange(entry.Key);
                    rawData.AddRange(entry.Value.getAmount().ToByteArray());
                }
                rawData.AddRange(new Address(pubKey).address);
            }

            rawData.AddRange(BitConverter.GetBytes(blockHeight));
            rawData.AddRange(BitConverter.GetBytes(nonce));
            rawData.AddRange(BitConverter.GetBytes((int)0)); // version was replaced with this, as it's tx metadata and shouldn't be part of the ID
            string chk = Base58Check.Base58CheckEncoding.EncodePlain(Crypto.sha512sqTrunc(rawData.ToArray()));

            txid += chk;

            return txid;
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
            if (transaction.toList.Count == 1)
            {
                rawData.AddRange(transaction.toList.ToArray()[0].Key);
            }
            else
            {
                foreach (var entry in transaction.toList)
                {
                    rawData.AddRange(entry.Key);
                    rawData.AddRange(entry.Value.getAmount().ToByteArray());
                }
            }

            if (transaction.fromList.Count == 1)
            {
                rawData.AddRange(new Address(transaction.pubKey).address);
            }else
            {
                foreach (var entry in transaction.fromList)
                {
                    rawData.AddRange(entry.Key);
                    rawData.AddRange(entry.Value.getAmount().ToByteArray());
                }
            }

            if (transaction.data != null)
            {
                rawData.AddRange(transaction.data);
            }

            rawData.AddRange(BitConverter.GetBytes(transaction.blockHeight));
            rawData.AddRange(BitConverter.GetBytes(transaction.nonce));
            rawData.AddRange(BitConverter.GetBytes(transaction.timeStamp));
            rawData.AddRange(BitConverter.GetBytes(transaction.version));
            if((transaction.version <= 1 && transaction.pubKey != null && transaction.pubKey.Length > 36)
                || transaction.version >= 2)
            {
                rawData.AddRange(transaction.pubKey);
            }
            return Crypto.sha512sqTrunc(rawData.ToArray());
        }

        public byte[] getSignature(byte[] checksum, byte[] private_key = null)
        {
            if(private_key != null)
            {
                return CryptoManager.lib.getSignature(checksum, private_key);
            }

            byte[] address = null;
            if(pubKey.Length == 36)
            {
                address = pubKey;
            }else
            {
                address = new Address(pubKey).address;
            }
            IxianKeyPair kp = Node.walletStorage.getKeyPair(address);
            if (kp != null)
            {
                return CryptoManager.lib.getSignature(checksum, kp.privateKeyBytes);
            }
            return null;
        }


        public IxiNumber calculateTotalAmount()
        {
            IxiNumber total = new IxiNumber(0);
            foreach(var entry in toList)
            {
                total += entry.Value;
            }
            return total;
        }

        public void generateChecksums()
        {
            id = generateID();
            checksum = calculateChecksum(this);
        }

        public IxiNumber calculateMinimumFee(IxiNumber pricePerKb)
        {
            int bytesLen = getBytes().Length;
            if (checksum == null)
            {
                bytesLen += 32;
            }
            if (signature == null)
            {
                bytesLen += 512;
            }
            IxiNumber expectedFee = pricePerKb * (ulong)Math.Ceiling((double)bytesLen / 1000);
            return expectedFee;
        }


        private void AddMultisigOrig(string orig_txid, byte[] signer_pub_key, byte[] signer_nonce)
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

                    bw.Write(signer_pub_key.Length);
                    bw.Write(signer_pub_key);

                    bw.Write(signer_nonce.Length);
                    bw.Write(signer_nonce);

                    data = ms.ToArray();
                }
            }
        }

        private void AddMultisigChWallet (string orig_txid, byte[] addr, MultisigWalletChangeType change_type, byte[] signer_pub_key, byte[] signer_nonce)
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

                    bw.Write(signer_pub_key.Length);
                    bw.Write(signer_pub_key);

                    bw.Write(signer_nonce.Length);
                    bw.Write(signer_nonce);

                    data = ms.ToArray();
                }
            }
        }

        private void AddMultisigChReqSigs(string orig_txid, byte num_sigs, byte[] signer_pub_key, byte[] signer_nonce)
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

                    bw.Write(signer_pub_key.Length);
                    bw.Write(signer_pub_key);

                    bw.Write(signer_nonce.Length);
                    bw.Write(signer_nonce);

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
                            byte[] orig_txid = null;
                            if (orig_tx_len > 0)
                            {
                                orig_txid = rd.ReadBytes(orig_tx_len);
                                if (orig_txid == null || orig_txid.Length < orig_tx_len)
                                {
                                    Logging.warn(String.Format("Multisig transaction: Invalid or missing origin txid!"));
                                    return null;
                                }
                            }else
                            {
                                orig_txid = Encoding.UTF8.GetBytes("");
                            }

                            int signer_pub_key_len = rd.ReadInt32();
                            if (signer_pub_key_len < 0 || (signer_pub_key_len != 523 && signer_pub_key_len != 36))
                            {
                                Logging.warn(String.Format("Multisig transaction: Invalid signer pub key length stored in data: {0}", orig_tx_len));
                                return null;
                            }
                            if (signer_pub_key_len == 0)
                            {
                                return null;
                            }
                            byte[] signer_pub_key = rd.ReadBytes(signer_pub_key_len);
                            if (signer_pub_key == null || signer_pub_key.Length < signer_pub_key_len)
                            {
                                Logging.warn(String.Format("Multisig transaction: Invalid or missing signer pub key!"));
                                return null;
                            }

                            int signer_nonce_len = rd.ReadInt32();
                            byte[] signer_nonce = rd.ReadBytes(signer_nonce_len);

                            return new MultisigTxData
                            {
                                origTXId = Encoding.UTF8.GetString(orig_txid),
                                signerPubKey = signer_pub_key,
                                signerNonce = signer_nonce
                            };
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

                                    int signer_pub_key_len = rd.ReadInt32();
                                    byte[] signer_pub_key = rd.ReadBytes(signer_pub_key_len);

                                    int signer_nonce_len = rd.ReadInt32();
                                    byte[] signer_nonce = rd.ReadBytes(signer_nonce_len);

                                    return new MultisigAddrAdd
                                    {
                                        origTXId = orig_txid,
                                        addrToAdd = ch_addr,
                                        signerPubKey = signer_pub_key,
                                        signerNonce = signer_nonce
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

                                    signer_pub_key_len = rd.ReadInt32();
                                    signer_pub_key = rd.ReadBytes(signer_pub_key_len);

                                    signer_nonce_len = rd.ReadInt32();
                                    signer_nonce = rd.ReadBytes(signer_nonce_len);

                                    return new MultisigAddrDel
                                    {
                                        origTXId = orig_txid,
                                        addrToDel = ch_addr,
                                        signerPubKey = signer_pub_key,
                                        signerNonce = signer_nonce
                                    };
                                case MultisigWalletChangeType.ChangeReqSigs:
                                    byte new_req_sigs = rd.ReadByte();

                                    signer_pub_key_len = rd.ReadInt32();
                                    signer_pub_key = rd.ReadBytes(signer_pub_key_len);

                                    signer_nonce_len = rd.ReadInt32();
                                    signer_nonce = rd.ReadBytes(signer_nonce_len);

                                    return new MultisigChSig
                                    {
                                        origTXId = orig_txid,
                                        reqSigs = new_req_sigs,
                                        signerPubKey = signer_pub_key,
                                        signerNonce = signer_nonce
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

        public static AddressData findMyMultisigAddressData(byte[] multisig_address)
        {
            AddressData ad = Node.walletStorage.getAddress(multisig_address);
            if (ad != null)
            {
                return ad;
            }

            Wallet w = Node.walletState.getWallet(multisig_address);
            if (w == null)
            {
                return null;
            }

            if (w.allowedSigners == null)
            {
                return Node.walletStorage.getAddress(multisig_address);
            }

            foreach(var entry in w.allowedSigners)
            {
                AddressData tmp_ad = Node.walletStorage.getAddress(entry);
                if(tmp_ad != null)
                {
                    return tmp_ad;
                }
            }
            return null;
        }

        public static Transaction multisigTransaction(string orig_txid, IxiNumber tx_amount, IxiNumber tx_fee, byte[] tx_to, byte[] tx_from, ulong tx_blockHeight)
        {
            Transaction t = new Transaction((int)Transaction.Type.MultisigTX, tx_amount, tx_fee, tx_to, tx_from, null, tx_from, tx_blockHeight);

            t.version = 2;

            // TODO TODO TODO TODO TODO TODO make this compatible with wallet v2

            AddressData ad = findMyMultisigAddressData(tx_from);
            if(ad == null)
            {
                return null;
            }

            t.AddMultisigOrig(orig_txid, ad.keyPair.publicKeyBytes, ad.nonce);

            t.fee = t.calculateMinimumFee(tx_fee);
            t.fromList[t.fromList.First().Key] = tx_amount + t.fee;

            t.generateChecksums();

            t.signature = t.getSignature(t.checksum);

            return t;
        }

        public static Transaction multisigTransaction(string orig_txid, IxiNumber tx_fee, SortedDictionary<byte[], IxiNumber> tx_to_list, byte[] tx_from, ulong tx_blockHeight)
        {
            Transaction t = new Transaction((int)Transaction.Type.MultisigTX, tx_fee, tx_to_list, tx_from, null, tx_from, tx_blockHeight);

            t.version = 2;

            // TODO TODO TODO TODO TODO TODO make this compatible with wallet v2

            AddressData ad = findMyMultisigAddressData(tx_from);
            if (ad == null)
            {
                return null;
            }

            t.AddMultisigOrig(orig_txid, ad.keyPair.publicKeyBytes, ad.nonce);

            t.fee = t.calculateMinimumFee(tx_fee);
            t.fromList[t.fromList.First().Key] = t.amount + t.fee;

            t.generateChecksums();

            t.signature = t.getSignature(t.checksum, ad.keyPair.privateKeyBytes);

            return t;
        }

        public static Transaction multisigAddKeyTransaction(string orig_txid, byte[] allowed_address,  IxiNumber tx_fee, byte[] tx_from, ulong tx_blockHeight)
        {
            Transaction t = new Transaction((int)Transaction.Type.ChangeMultisigWallet, new IxiNumber(0), tx_fee, tx_from, tx_from, null, tx_from, tx_blockHeight);

            t.version = 2;

            // TODO TODO TODO TODO TODO TODO make this compatible with wallet v2

            AddressData ad = findMyMultisigAddressData(tx_from);
            if (ad == null)
            {
                return null;
            }

            t.AddMultisigChWallet(orig_txid, allowed_address, MultisigWalletChangeType.AddSigner, ad.keyPair.publicKeyBytes, ad.nonce);

            t.fee = t.calculateMinimumFee(tx_fee);
            t.fromList[t.fromList.First().Key] = t.fee;

            t.generateChecksums();

            t.signature = t.getSignature(t.checksum, ad.keyPair.privateKeyBytes);

            return t;
        }

        public static Transaction multisigDelKeyTransaction(string orig_txid, byte[] disallowed_address, IxiNumber tx_fee, byte[] tx_from, ulong tx_blockHeight)
        {
            Transaction t = new Transaction((int)Transaction.Type.ChangeMultisigWallet, new IxiNumber(0), tx_fee, tx_from, tx_from, null, tx_from, tx_blockHeight);

            t.version = 2;

            // TODO TODO TODO TODO TODO TODO make this compatible with wallet v2

            AddressData ad = findMyMultisigAddressData(tx_from);
            if (ad == null)
            {
                return null;
            }

            t.AddMultisigChWallet(orig_txid, disallowed_address, MultisigWalletChangeType.DelSigner, ad.keyPair.publicKeyBytes, ad.nonce);

            t.fee = t.calculateMinimumFee(tx_fee);
            t.fromList[t.fromList.First().Key] = t.fee;

            t.generateChecksums();

            t.signature = t.getSignature(t.checksum, ad.keyPair.privateKeyBytes);

            return t;
        }

        public static Transaction multisigChangeReqSigs(string orig_txid, byte sigs, IxiNumber tx_fee, byte[] tx_from, ulong tx_blockHeight)
        {
            Transaction t = new Transaction((int)Transaction.Type.ChangeMultisigWallet, new IxiNumber(0), tx_fee, tx_from, tx_from, null, tx_from, tx_blockHeight);

            t.version = 2;

            // TODO TODO TODO TODO TODO TODO make this compatible with wallet v2

            AddressData ad = findMyMultisigAddressData(tx_from);
            if (ad == null)
            {
                return null;
            }

            t.AddMultisigChReqSigs(orig_txid, sigs, ad.keyPair.publicKeyBytes, ad.nonce);

            t.fee = t.calculateMinimumFee(tx_fee);
            t.fromList[t.fromList.First().Key] = t.fee;

            t.generateChecksums();

            t.signature = t.getSignature(t.checksum, ad.keyPair.privateKeyBytes);

            return t;
        }

        public Dictionary<string, object> toDictionary()
        {
            Dictionary<string, object> tDic = new Dictionary<string, object>();
            tDic.Add("id", id);
            tDic.Add("version", version);
            tDic.Add("blockHeight", blockHeight.ToString());
            tDic.Add("nonce", nonce.ToString());

            if (signature != null)
            {
                tDic.Add("signature", Crypto.hashToString(signature));
            }

            if (pubKey != null)
            {
                tDic.Add("pubKey", Base58Check.Base58CheckEncoding.EncodePlain(pubKey));
            }

            if (data != null)
            {
                tDic.Add("data", Crypto.hashToString(data));
            }

            tDic.Add("timeStamp", timeStamp.ToString());
            tDic.Add("type", type.ToString());
            tDic.Add("amount", amount.ToString());
            tDic.Add("applied", applied.ToString());
            tDic.Add("checksum", Crypto.hashToString(checksum));

            Dictionary<string, string> fromListDic = new Dictionary<string, string>();
            foreach (var entry in fromList)
            {
                fromListDic.Add(Base58Check.Base58CheckEncoding.EncodePlain(entry.Key), entry.Value.ToString());
            }
            tDic.Add("from", fromListDic);

            Dictionary<string, string> toListDic = new Dictionary<string, string>();
            foreach (var entry in toList)
            {
                toListDic.Add(Base58Check.Base58CheckEncoding.EncodePlain(entry.Key), entry.Value.ToString());
            }
            tDic.Add("to", toListDic);

            tDic.Add("fee", fee.ToString());

            return tDic;
        }
    }
}