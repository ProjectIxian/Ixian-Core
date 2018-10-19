using DLT.Meta;
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
            AddSigner = 1, // data is appended by :MS1:pubkey
            DelSigner = 2, // data is appended by :MS2:pubkey
            ChangeReqSigs = 3 // data is appended by :MS3:NUMBER ; where 0 < NUMBER < 256
        }

        public string id;           //  36 B
        public int type;            //   4 B
        public IxiNumber amount;    // ~16 B
        public IxiNumber fee;       // ~16 B
        public byte[] to;           //  36 B
        public byte[] from;         //  36 B
        public byte[] data;         //   0 B
        public ulong blockHeight;   //   8 B
        public int nonce;           //   4 B
        public long timeStamp;    // ~12 B
        public byte[] checksum;     //  32 B
        public byte[] signature;    //  32 B
        public byte[] pubKey;    //  32 B
        public ulong applied;        

        /* TX RAM savings:
         * id -> guid binary (36B -> 16B)
         * type -> single byte (4B -> 1B) - MAX 255 types!! (should be plenty)
         * amount -> binary (16B -> 8B)
         * to, from -> binary (36B -> 16B)
         * timestamp -> fix precision to ms, get it out of double(string) into int64 (~12B -> 8B)
         * checksum -> binary (32B -> 16B)
         * sig -> binary (32B -> 16B)
         * NEW TXsize estimate: 97B
         * Additional measures: Huffman code (need training data to estimate entropy before I can predict savings)
         */


        public Transaction()
        {
            // This constructor is used only for development purposes
            id = Guid.NewGuid().ToString();
            type = (int) Type.Normal;
            timeStamp = Node.getCurrentTimestamp();
            fee = new IxiNumber("0");
            blockHeight = 0;
            nonce = 0;
            applied = 0;
        }

        public Transaction(IxiNumber tx_amount, IxiNumber tx_fee, byte[] tx_to, byte[] tx_from, byte[] tx_data, byte[] tx_pubKey, ulong tx_blockHeight)
        {
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

            timeStamp = Node.getCurrentTimestamp();

            id = generateID();
            checksum = calculateChecksum(this);
            signature = getSignature(checksum);
            pubKey = tx_pubKey;
        }

        public Transaction(Transaction tx_transaction)
        {
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
                        //id = reader.ReadString();
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
                        signature = reader.ReadBytes(sigLen);
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
                    //writer.Write(id);
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

                    writer.Write(signature.Length);
                    writer.Write(signature);

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
            // Skip signature verification for staking rewards
            if (type == (int)Type.StakingReward || type == (int)Type.Genesis)
            {
                return true;
            }

            Address p_address = new Address(pubkey);
            if (from.SequenceEqual(p_address.address) == false)
                return false;

            // Verify the signature
            return CryptoManager.lib.verifySignature(checksum, pubkey, signature);
        }

        // Generates the transaction ID
        public string generateID()
        {
            string txid = "";

            if(type == (int)Type.StakingReward)
            {

                if (data.Length > 0)
                {
                    ulong blockNum = BitConverter.ToUInt64(data, 0);
                    if (blockNum > 0)
                    {
                        txid = "stk-" + blockNum + "-";
                    }
                }
            }

            txid += blockHeight + "-" + nonce + "-";

            List<byte> rawData = new List<byte>();
            rawData.AddRange(BitConverter.GetBytes(type));
            rawData.AddRange(Encoding.UTF8.GetBytes(amount.ToString()));
            rawData.AddRange(Encoding.UTF8.GetBytes(fee.ToString()));
            rawData.AddRange(to);
            rawData.AddRange(from);
            rawData.AddRange(BitConverter.GetBytes(blockHeight));
            rawData.AddRange(BitConverter.GetBytes(nonce));
            string chk = Crypto.hashToString(Crypto.sha256(rawData.ToArray()));

            txid += chk;

            return txid;
        }

        public static bool verifyTransactionID(Transaction transaction)
        {
            string txid = "";

            if (transaction.type == (int)Type.StakingReward)
            {
                if (transaction.data.Length > 0)
                {
                    ulong blockNum = BitConverter.ToUInt64(transaction.data, 0);
                    if (blockNum > 0)
                    {
                        txid = "stk-" + blockNum + "-";
                    }
                }
            }

            txid += transaction.blockHeight + "-" + transaction.nonce + "-";

            List<byte> rawData = new List<byte>();
            rawData.AddRange(BitConverter.GetBytes(transaction.type));
            rawData.AddRange(Encoding.UTF8.GetBytes(transaction.amount.ToString()));
            rawData.AddRange(Encoding.UTF8.GetBytes(transaction.fee.ToString()));
            rawData.AddRange(transaction.to);
            rawData.AddRange(transaction.from);
            rawData.AddRange(BitConverter.GetBytes(transaction.blockHeight));
            rawData.AddRange(BitConverter.GetBytes(transaction.nonce));
            string chk = Crypto.hashToString(Crypto.sha256(rawData.ToArray()));

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
            return Crypto.sha256(rawData.ToArray());
        }

        public static byte[] getSignature(byte[] checksum)
        {
            return CryptoManager.lib.getSignature(checksum, Node.walletStorage.privateKey);
        }

        public static Transaction multisigTransaction(IxiNumber tx_amount, IxiNumber tx_fee, byte[] tx_to, byte[] tx_from, byte[] tx_data, ulong tx_blockHeight)
        {
            Transaction t = new Transaction(tx_amount, tx_fee, tx_to, tx_from, tx_data, Node.walletStorage.publicKey, tx_blockHeight);
            t.type = (int)Transaction.Type.MultisigTX;
            // overwrite invalid values where were calcualted before the multisig flag was set
            t.id = t.generateID();
            t.checksum = calculateChecksum(t);
            t.signature = getSignature(t.checksum);
            return t;
        }

        public static Transaction multisigAddKeyTransaction(string signer,  IxiNumber tx_fee, byte[] tx_from, ulong tx_blockHeight, int tx_nonce)
        {
            Transaction t = new Transaction
            {
                type = (int)Transaction.Type.ChangeMultisigWallet,
                amount = new IxiNumber(0),
                fee = tx_fee,
                from = tx_from,
                to = tx_from,
                blockHeight = tx_blockHeight,
                nonce = tx_nonce,
                data = Encoding.UTF8.GetBytes("MS1:" + signer)
            };
            //
            t.id = t.generateID();
            t.checksum = calculateChecksum(t);
            t.pubKey = Node.walletStorage.publicKey;
            t.signature = getSignature(t.checksum);
            return t;
        }

        public static Transaction multisigDelKeyTransaction(string signer, IxiNumber tx_fee, byte[] tx_from, ulong tx_blockHeight, int tx_nonce)
        {
            Transaction t = new Transaction
            {
                type = (int)Transaction.Type.ChangeMultisigWallet,
                amount = new IxiNumber(0),
                fee = tx_fee,
                from = tx_from,
                to = tx_from,
                blockHeight = tx_blockHeight,
                nonce = tx_nonce,
                data = Encoding.UTF8.GetBytes("MS2:" + signer)
            };
            //
            t.id = t.generateID();
            t.checksum = calculateChecksum(t);
            t.pubKey = Node.walletStorage.publicKey;
            t.signature = getSignature(t.checksum);
            return t;
        }

        public static Transaction multisigChangeReqSigs(byte sigs, IxiNumber tx_fee, byte[] tx_from, ulong tx_blockHeight, int tx_nonce)
        {
            Transaction t = new Transaction
            {
                type = (int)Transaction.Type.ChangeMultisigWallet,
                amount = new IxiNumber(0),
                fee = tx_fee,
                from = tx_from,
                to = tx_from,
                blockHeight = tx_blockHeight,
                nonce = tx_nonce,
                data = Encoding.UTF8.GetBytes("MS3:" + sigs.ToString())
            };
            //
            t.id = t.generateID();
            t.checksum = calculateChecksum(t);
            t.pubKey = Node.walletStorage.publicKey;
            t.signature = getSignature(t.checksum);
            return t;
        }


    }
}