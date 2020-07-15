using System.IO;

namespace IXICore
{
    class StreamTransaction
    {
        public byte[] messageID;
        public Transaction transaction;

        public StreamTransaction(byte[] message_id, Transaction tx)
        {
            messageID = message_id;
            transaction = tx;
        }

        public StreamTransaction(byte[] bytes)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    int msg_id_len = reader.ReadInt32();
                    messageID = reader.ReadBytes(msg_id_len);

                    int tx_len = reader.ReadInt32();
                    transaction = new Transaction(reader.ReadBytes(tx_len));
                }
            }
        }

        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(messageID.Length);
                    writer.Write(messageID);

                    byte[] tx_bytes = transaction.getBytes();
                    writer.Write(tx_bytes.Length);
                    writer.Write(tx_bytes);
                }
                return m.ToArray();
            }
        }

    }
}
