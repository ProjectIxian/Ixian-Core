using System.Collections.Generic;
using System.Linq;

namespace IXICore
{
    // TODO TODO TODO make PendingTransactions persistent
    public class PendingTransactions
    {
        public static List<object[]> pendingTransactions = new List<object[]>();

        public static void addPendingLocalTransaction(Transaction t)
        {
            lock (pendingTransactions)
            {
                if (!pendingTransactions.Exists(x => ((Transaction)x[0]).id.SequenceEqual(t.id)))
                {
                    pendingTransactions.Add(new object[4] { t, Clock.getTimestamp(), 0, false });
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
                List<object[]> txs = pendingTransactions.FindAll(x => ((Transaction)x[0]).type == (int)Transaction.Type.Normal);
                foreach (var entry in txs)
                {
                    Transaction tx = (Transaction)entry[0];
                    if (primary_address == null || (new Address(tx.pubKey)).address.SequenceEqual(primary_address))
                    {
                        amount += tx.amount + tx.fee;
                    }
                }
            }
            return amount;
        }

        public static void remove(string txid)
        {
            lock (pendingTransactions)
            {
                pendingTransactions.RemoveAll(x => ((Transaction)x[0]).id.SequenceEqual(txid));
            }
        }

        public static void increaseReceivedCount(string txid)
        {
            lock (pendingTransactions)
            {
                object[] pending = pendingTransactions.Find(x => ((Transaction)x[0]).id.SequenceEqual(txid));
                if (pending != null)
                {
                    pending[2] = (int)pending[2] + 1;
                }
            }
        }
    }
}
