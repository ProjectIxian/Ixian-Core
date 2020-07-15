using System.IO;

namespace IXICore
{
    class StreamTransactionRequest
    {
        public byte[] messageID;
        public IxiNumber cost;

        public StreamTransactionRequest(byte[] message_id, IxiNumber cost)
        {
            messageID = message_id;
            this.cost = cost;
        }

        public StreamTransactionRequest(byte[] bytes)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    int msg_id_len = reader.ReadInt32();
                    messageID = reader.ReadBytes(msg_id_len);

                    cost = new IxiNumber(reader.ReadString());
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

                    writer.Write(cost.ToString());
                }
                return m.ToArray();
            }
        }

    }
}
