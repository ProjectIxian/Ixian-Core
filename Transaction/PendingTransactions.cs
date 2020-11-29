using System.Collections.Generic;
using System.Linq;
using System.Xml;

namespace IXICore
{
    public class PendingTransaction
    {
        public Transaction transaction;
        public long addedTimestamp;
        public List<byte[]> confirmedNodeList = new List<byte[]>();
        public byte[] messageId;

        public PendingTransaction(Transaction t, long addedTimestamp, byte[] message_id)
        {
            transaction = t;
            this.addedTimestamp = addedTimestamp;
            messageId = message_id;
        }
    }

    // TODO TODO TODO make PendingTransactions persistent
    public class PendingTransactions
    {
        public static List<PendingTransaction> pendingTransactions = new List<PendingTransaction>();

        public static void addPendingLocalTransaction(Transaction t, byte[] message_id = null)
        {
            lock (pendingTransactions)
            {
                if (pendingTransactions.Find(x => x.transaction.id.SequenceEqual(t.id)) == null)
                {
                    pendingTransactions.Add(new PendingTransaction( t, Clock.getTimestamp(), message_id));
                }
            }
        }



        public static long pendingTransactionCount()
        {
            lock (pendingTransactions)
            {
                return pendingTransactions.LongCount();
            }
        }

        public static IxiNumber getPendingSendingTransactionsAmount(byte[] primary_address)
        {
            IxiNumber amount = 0;
            lock (pendingTransactions)
            {
                List<PendingTransaction> txs = pendingTransactions.FindAll(x => x.transaction.type == (int)Transaction.Type.Normal);
                foreach (var entry in txs)
                {
                    Transaction tx = entry.transaction;
                    if (primary_address == null || (new Address(tx.pubKey)).address.SequenceEqual(primary_address))
                    {
                        amount += tx.amount + tx.fee;
                    }
                }
            }
            return amount;
        }

        public static void remove(byte[] txid)
        {
            lock (pendingTransactions)
            {
                pendingTransactions.RemoveAll(x => x.transaction.id.SequenceEqual(txid));
            }
        }

        public static PendingTransaction getPendingTransaction(byte[] txid)
        {
            lock (pendingTransactions)
            {
                return pendingTransactions.Find(x => x.transaction.id.SequenceEqual(txid));
            }
        }

        public static void increaseReceivedCount(byte[] txid, byte[] address)
        {
            lock (pendingTransactions)
            {
                PendingTransaction pending = pendingTransactions.Find(x => x.transaction.id.SequenceEqual(txid));
                if (pending != null)
                {
                    if(pending.confirmedNodeList.Find(x => x.SequenceEqual(address)) == null)
                    {
                        pending.confirmedNodeList.Add(address);
                    }
                }
            }
        }
    }
}
