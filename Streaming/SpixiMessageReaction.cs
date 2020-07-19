using System.IO;

namespace IXICore
{
    public class SpixiMessageReaction
    {
        public byte[] msgId = null;
        public string reaction = null;

        public SpixiMessageReaction(byte[] msg_id, string reaction)
        {
            msgId = msg_id;
            this.reaction = reaction;
        }

        public SpixiMessageReaction(byte[] reaction_bytes)
        {
            using (MemoryStream m = new MemoryStream(reaction_bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    int msg_id_len = reader.ReadInt32();
                    msgId = reader.ReadBytes(msg_id_len);
                    reaction = reader.ReadString();
                }
            }
        }

        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(msgId.Length);
                    writer.Write(msgId);
                    writer.Write(reaction);
                }
                return m.ToArray();
            }
        }
    }
}
