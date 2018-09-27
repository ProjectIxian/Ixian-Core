using DLT.Meta;
using System;
using System.IO;

namespace DLT
{
    public class Transaction
    {

        public enum Type:int
        {
            Normal = 0,
            PoWSolution = 1,
            StakingReward = 2,
            Genesis = 3
        }

        public string id;           //  36 B
        public int type;            //   4 B
        public IxiNumber amount;    // ~16 B
        public IxiNumber fee;       // ~16 B
        public string to;           //  36 B
        public string from;         //  36 B
        public string data;         //   0 B
        public ulong nonce;
        public string timeStamp;    // ~12 B
        public string checksum;     //  32 B
        public string signature;    //  32 B
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
            timeStamp = Clock.getTimestamp(DateTime.Now);
            fee = new IxiNumber("0");
            nonce = 0;
            applied = 0;
        }

        public Transaction(IxiNumber tx_amount, IxiNumber tx_fee, string tx_to, string tx_from, ulong tx_nonce = 0)
        {
            //id = Guid.NewGuid().ToString();
            type = (int) Type.Normal;

            amount = tx_amount;
            fee = tx_fee;
            to = tx_to;
            from = tx_from;
            data = Node.walletStorage.publicKey;

            nonce = tx_nonce;

            timeStamp = Clock.getTimestamp(DateTime.Now);

            id = generateID();
            checksum = Transaction.calculateChecksum(this);
            signature = Transaction.getSignature(checksum);
        }

        public Transaction(Transaction tx_transaction)
        {
            id = tx_transaction.id;
            type = tx_transaction.type;
            amount = tx_transaction.amount;
            fee = tx_transaction.fee;
            to = tx_transaction.to;
            from = tx_transaction.from;
            data = tx_transaction.data;
            nonce = tx_transaction.nonce;

            timeStamp = tx_transaction.timeStamp;
            //id = generateID();
            checksum = tx_transaction.checksum;
            signature = tx_transaction.signature;
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
                        to = reader.ReadString();
                        from = reader.ReadString();
                        data = reader.ReadString();
                        nonce = reader.ReadUInt64();

                        timeStamp = reader.ReadString();
                        checksum = reader.ReadString();
                        signature = reader.ReadString();
                        id = generateID();
                    }
                }
            }
            catch(Exception e)
            {
                Logging.error("Exception occured while trying to construct Transaction from bytes: " + e);
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
                    writer.Write(to);
                    writer.Write(from);
                    writer.Write(data);
                    writer.Write(nonce);

                    writer.Write(timeStamp);
                    writer.Write(checksum);
                    writer.Write(signature);
                }
                return m.ToArray();
            }
        }

        // Checks two transactions for duplicates
        public bool equals(Transaction tx)
        {
            byte[] a1 = getBytes();
            byte[] a2 = tx.getBytes();

            if (a1.Length != a2.Length)
                return false;

            for (int i = 0; i < a1.Length; i++)
                if (a1[i] != a2[i])
                    return false;

            return true;
        }

        // Verifies the transaction signature and returns true if valid
        public bool verifySignature()
        {
            // Skip signature verification for staking rewards
            if (type == (int)Type.StakingReward || type == (int)Type.Genesis)
            {
                return true;
            }
            
            // Generate an address from the public key and compare it with the sender
            string pubkey = data;

            // If this is a PoWSolution transaction, extract the public key from the data section first
            if(type == (int)Transaction.Type.PoWSolution || type == (int)Transaction.Type.StakingReward)
            {
                string[] split = data.Split(new string[] { "||" }, StringSplitOptions.None);
                if (split.Length < 1)
                    return false;

                pubkey = split[0];
            }

            Address p_address = new Address(pubkey);
            if (from.Equals(p_address.ToString(), StringComparison.Ordinal) == false)
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
                ulong blockNum = 0;

                var dataSplit = data.Split(new string[] { "||" }, StringSplitOptions.None);
                if (dataSplit.Length > 0 && ulong.TryParse(dataSplit[1], out blockNum))
                {
                    txid = "stk-" + blockNum + "-";
                }
            }

            txid += nonce + "-";

            string chk = Crypto.sha256(type + amount.ToString() + fee.ToString() + to + from + nonce);
            txid += chk;

            return txid;
        }

        public static bool verifyTransactionID(Transaction transaction)
        {
            string txid = "";

            if (transaction.type == (int)Type.StakingReward)
            {
                ulong blockNum = 0;

                var dataSplit = transaction.data.Split(new string[] { "||" }, StringSplitOptions.None);
                if (dataSplit.Length > 0 && ulong.TryParse(dataSplit[1], out blockNum))
                {
                    txid = "stk-" + blockNum + "-";
                }
            }

            txid += transaction.nonce + "-";

            string chk = Crypto.sha256(transaction.type + transaction.amount.ToString() + transaction.fee.ToString() + transaction.to +
                transaction.from + transaction.nonce);
            txid += chk;

            if(transaction.id.Equals(txid, StringComparison.Ordinal))
            {
                return true;
            }

            return false;
        }

        // Calculate a transaction checksum 
        public static string calculateChecksum(Transaction transaction)
        {
            return Crypto.sha256(transaction.id + transaction.type + transaction.amount.ToString() + transaction.fee.ToString() + transaction.to + transaction.from + transaction.data + transaction.nonce + transaction.timeStamp);
        }

        public static string getSignature(string checksum)
        {
            string private_key = Node.walletStorage.privateKey;
            return CryptoManager.lib.getSignature(checksum, private_key);
        }

    }
}