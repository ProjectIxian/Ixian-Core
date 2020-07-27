using IXICore;
using System.IO;

namespace IXICore.SpixiBot
{
    public class BotInfo
    {
        public short version;
        public string serverName;
        public string serverDescription;
        public IxiNumber cost;
        public long settingsGeneratedTime = 0;
        public bool admin;
        public int defaultGroup = 0;
        public int defaultChannel = 0;
        public bool sendNotification = false;


        public BotInfo(short version, string server_name, string server_description, IxiNumber cost, long settings_generated_time, bool admin, int default_group, int default_channel, bool send_notification)
        {
            this.version = version;
            serverName = server_name;
            serverDescription = server_description;
            this.cost = cost;
            settingsGeneratedTime = settings_generated_time;
            this.admin = admin;
            defaultGroup = default_group;
            defaultChannel = default_channel;
            sendNotification = send_notification;
        }

        public BotInfo(byte[] contact_bytes)
        {
            using (MemoryStream m = new MemoryStream(contact_bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    version = reader.ReadInt16();
                    serverName = reader.ReadString();
                    serverDescription = reader.ReadString();
                    cost = new IxiNumber(reader.ReadString());
                    settingsGeneratedTime = reader.ReadInt64();
                    admin = reader.ReadBoolean();
                    defaultGroup = reader.ReadInt32();
                    defaultChannel = reader.ReadInt32();
                    if(m.Position < m.Length)
                    {
                        sendNotification = reader.ReadBoolean();
                    }
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
                    writer.Write(serverDescription);
                    writer.Write(cost.ToString());
                    writer.Write(settingsGeneratedTime);
                    writer.Write(admin);
                    writer.Write(defaultGroup);
                    writer.Write(defaultChannel);
                    writer.Write(sendNotification);
                }
                return m.ToArray();
            }
        }
    }
}
