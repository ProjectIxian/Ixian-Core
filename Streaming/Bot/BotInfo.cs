using IXICore;
using System.IO;

namespace IXICore.SpixiBot
{
    public class BotInfo
    {
        public short version;
        public string serverName;
        public IxiNumber cost;
        public long settingsGeneratedTime = 0;
        public bool admin;
        public int defaultGroup = 0;
        public int defaultChannel = 0;


        public BotInfo(short version, string server_name, IxiNumber cost, long settings_generated_time, bool admin, int default_group, int default_channel)
        {
            this.version = version;
            serverName = server_name;
            this.cost = cost;
            settingsGeneratedTime = settings_generated_time;
            this.admin = admin;
            defaultGroup = default_group;
            defaultChannel = default_channel;
        }

        public BotInfo(byte[] contact_bytes)
        {
            using (MemoryStream m = new MemoryStream(contact_bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    version = reader.ReadInt16();
                    serverName = reader.ReadString();
                    cost = new IxiNumber(reader.ReadString());
                    settingsGeneratedTime = reader.ReadInt64();
                    admin = reader.ReadBoolean();
                    defaultGroup = reader.ReadInt32();
                    defaultChannel = reader.ReadInt32();
                }
            }
        }

        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(version);
                    writer.Write(serverName);
                    writer.Write(cost.ToString());
                    writer.Write(settingsGeneratedTime);
                    writer.Write(admin);
                    writer.Write(defaultGroup);
                    writer.Write(defaultChannel);
                }
                return m.ToArray();
            }
        }
    }
}
