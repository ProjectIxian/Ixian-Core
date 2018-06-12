using DLT.Meta;
using System;
using System.IO;

namespace DLT
{
    public class Transaction
    {
        public string id;
        public int type;
        public ulong amount;
        public string to;
        public string from;
        public string data;
        public string timeStamp;
        public string checksum;
        public string signature;


        public Transaction()
        {
            // This constructor is used only for development purposes
            id = Guid.NewGuid().ToString();
            type = 0;
            timeStamp = Clock.getTimestamp(DateTime.Now);
        }

        public Transaction(ulong tx_amount, string tx_to, string tx_from)
        {
            id = Guid.NewGuid().ToString();
            type = 0;

            amount = tx_amount;
            to = tx_to;
            from = tx_from;
            data = Node.walletStorage.publicKey; 

            timeStamp = Clock.getTimestamp(DateTime.Now);
            checksum = Transaction.calculateChecksum(this);
            signature = Transaction.getSignature(checksum);
        }

        public Transaction(Transaction tx_transaction)
        {
            id = tx_transaction.id;
            type = tx_transaction.type;
            amount = tx_transaction.amount;
            to = tx_transaction.to;
            from = tx_transaction.from;
            data = tx_transaction.data;

            timeStamp = tx_transaction.timeStamp;
            checksum = tx_transaction.checksum;
            signature = tx_transaction.signature;
        }

        public Transaction(byte[] bytes)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    id = reader.ReadString();
                    type = reader.ReadInt32();
                    amount = reader.ReadUInt64();
                    to = reader.ReadString();
                    from = reader.ReadString();
                    data = reader.ReadString();

                    timeStamp = reader.ReadString();
                    checksum = reader.ReadString();
                    signature = reader.ReadString();
                }
            }
        }

        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(id);
                    writer.Write(type);
                    writer.Write(amount);
                    writer.Write(to);
                    writer.Write(from);
                    writer.Write(data);

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
            // Generate an address from the public key and compare it with the sender
            Address p_address = new Address(data);
            if (from.Equals(p_address.ToString(), StringComparison.Ordinal) == false)
                return false;

            // Verify the signature
            return CryptoManager.lib.verifySignature(checksum, data, signature);
        }

        // Calculate a transaction checksum 
        public static string calculateChecksum(Transaction transaction)
        {
            return Crypto.sha256(transaction.id + transaction.type + transaction.amount + transaction.to + transaction.from + transaction.data + transaction.timeStamp);
        }

        public static string getSignature(string checksum)
        {
            string private_key = Node.walletStorage.privateKey;
            return CryptoManager.lib.getSignature(checksum, private_key);
        }

    }
}