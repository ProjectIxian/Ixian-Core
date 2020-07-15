using System.IO;

namespace IXICore.SpixiBot
{
    public class BotChannel
    {
        public int index;
        public string channelName;

        public BotChannel(int id, string name)
        {
            index = id;
            channelName = name;
        }

        public BotChannel(byte[] contact_bytes)
        {
            using (MemoryStream m = new MemoryStream(contact_bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    index = reader.ReadInt32();
                    channelName = reader.ReadString();
                }
            }
        }

        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(index);
                    writer.Write(channelName);
                }
                return m.ToArray();
            }
        }
    }
}
