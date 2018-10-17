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
        public string to;           //  36 B
        public string from;         //  36 B
        public string data;         //   0 B
        public ulong blockHeight;   //   8 B
        public int nonce;           //   4 B
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
            timeStamp = Node.getCurrentTimestamp().ToString();
            fee = new IxiNumber("0");
            blockHeight = 0;
            nonce = 0;
            applied = 0;
        }

        public Transaction(IxiNumber tx_amount, IxiNumber tx_fee, string tx_to, string tx_from, string tx_data, ulong tx_blockHeight, int tx_nonce)
        {
            //id = Guid.NewGuid().ToString();
            type = (int)Transaction.Type.Normal;

            amount = tx_amount;
            fee = tx_fee;
            to = tx_to;
            from = tx_from;

            data = tx_data;

            blockHeight = tx_blockHeight;

            nonce = tx_nonce;

            timeStamp = Node.getCurrentTimestamp().ToString();

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
            blockHeight = tx_transaction.blockHeight;
            nonce = tx_transaction.nonce;
            timeStamp = tx_transaction.timeStamp;
            checksum = tx_transaction.checksum;
            signature = tx_transaction.signature;
        }

        public Transaction(byte[] bytes, bool legacy = false)
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

                        // Handle reading of legacy transactions
                        if (legacy == true)
                        {
                            blockHeight = 0;
                        }
                        else
                        {
                            blockHeight = reader.ReadUInt64();
                        }

                        nonce = reader.ReadInt32();

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
                    writer.Write(to);
                    writer.Write(from);
                    writer.Write(data);
                    writer.Write(blockHeight);
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
        public bool verifySignature(string pubkey)
        {
            // Skip signature verification for staking rewards
            if (type == (int)Type.StakingReward || type == (int)Type.Genesis)
            {
                return true;
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

                if (data.Length > 0 && ulong.TryParse(data, out blockNum))
                {
                    txid = "stk-" + blockNum + "-";
                }
            }

            if(Legacy.isLegacy(blockHeight))
            {
                // legacy, do not remove
                txid += nonce + "-";

                string chk = Crypto.sha256(type + amount.ToString() + fee.ToString() + to + from + nonce);
                txid += chk;
            }
            else
            {
                txid += blockHeight + "-" + nonce + "-";

                string chk = Crypto.sha256(type + amount.ToString() + fee.ToString() + to + from + blockHeight + nonce);
                txid += chk;
            }

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

            if (Legacy.isLegacy(transaction.blockHeight))
            {
                // legacy, do not remove

                txid += transaction.nonce + "-";

                string chk = Crypto.sha256(transaction.type + transaction.amount.ToString() + transaction.fee.ToString() + transaction.to +
                    transaction.from + transaction.nonce);
                txid += chk;
            }
            else
            {
                txid += transaction.blockHeight + "-" + transaction.nonce + "-";

                string chk = Crypto.sha256(transaction.type + transaction.amount.ToString() + transaction.fee.ToString() + transaction.to +
                    transaction.from + transaction.blockHeight + transaction.nonce);
                txid += chk;
            }

            if (transaction.id.Equals(txid, StringComparison.Ordinal))
            {
                return true;
            }

            return false;
        }

        // Calculate a transaction checksum 
        public static string calculateChecksum(Transaction transaction)
        {
            if (Legacy.isLegacy(transaction.blockHeight))
                return Crypto.sha256(transaction.id + transaction.type + transaction.amount.ToString() + transaction.fee.ToString() + transaction.to + transaction.from + transaction.data + transaction.nonce + transaction.timeStamp);

            return Crypto.sha256(transaction.id + transaction.type + transaction.amount.ToString() + transaction.fee.ToString() + transaction.to + transaction.from + transaction.data + transaction.blockHeight + transaction.nonce + transaction.timeStamp);
        }

        public static string getSignature(string checksum)
        {
            string private_key = Node.walletStorage.privateKey;
            return CryptoManager.lib.getSignature(checksum, private_key);
        }

        public static Transaction multisigTransaction(IxiNumber tx_amount, IxiNumber tx_fee, string tx_to, string tx_from, string tx_data, ulong tx_blockHeight, int tx_nonce)
        {
            Transaction t = new Transaction(tx_amount, tx_fee, tx_to, tx_from, tx_data, tx_blockHeight, tx_nonce);
            t.type = (int)Transaction.Type.MultisigTX;
            // overwrite invalid values where were calcualted before the multisig flag was set
            t.id = t.generateID();
            t.checksum = Transaction.calculateChecksum(t);
            t.signature = Transaction.getSignature(t.checksum);
            return t;
        }

        public static Transaction multisigAddKeyTransaction(string signer,  IxiNumber tx_fee, string tx_from, ulong tx_blockHeight, int tx_nonce)
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
                data = "MS1:" + signer
            };
            //
            t.id = t.generateID();
            t.checksum = Transaction.calculateChecksum(t);
            t.signature = Node.walletStorage.publicKey + ":" + Transaction.getSignature(t.checksum);
            return t;
        }

        public static Transaction multisigDelKeyTransaction(string signer, IxiNumber tx_fee, string tx_from, ulong tx_blockHeight, int tx_nonce)
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
                data = "MS2:" + signer
            };
            //
            t.id = t.generateID();
            t.checksum = Transaction.calculateChecksum(t);
            t.signature = Node.walletStorage.publicKey + ":" + Transaction.getSignature(t.checksum);
            return t;
        }

        public static Transaction multisigChangeReqSigs(byte sigs, IxiNumber tx_fee, string tx_from, ulong tx_blockHeight, int tx_nonce)
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
                data = "MS3:" + sigs.ToString()
            };
            //
            t.id = t.generateID();
            t.checksum = Transaction.calculateChecksum(t);
            t.signature = Node.walletStorage.publicKey + ":" + Transaction.getSignature(t.checksum);
            return t;
        }


    }
}