using System;
using System.IO;
using System.Text;

namespace IXICore.SpixiBot
{
    public class BotContact
    {
        private string nick = "";
        public byte[] nickData { get; private set; }
        public byte[] publicKey;
        private string role = "";
        public bool hasAvatar = false;
        public bool sendNotification = true;

        public BotContact(byte[] nick_data, byte[] public_key, int role_index, bool has_avatar, bool send_notification = true)
        {
            setNick(nick_data);
            publicKey = public_key;
            setRole(role_index);
            hasAvatar = has_avatar;
            sendNotification = send_notification;
        }

        public string getNick()
        {
            return nick;
        }

        public void setNick(string nick)
        {
            nickData = null;
            this.nick = nick;
        }

        public void setNick(byte[] nick_data)
        {
            nickData = nick_data;
            if(nickData != null)
            {
                nick = Encoding.UTF8.GetString(new SpixiMessage(new StreamMessage(nickData).data).data);
            }
        }

        public BotContact(byte[] contact_bytes, bool nick_as_string)
        {
            using (MemoryStream m = new MemoryStream(contact_bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    if(nick_as_string)
                    {
                        nick = reader.ReadString();
                    }else
                    {
                        int nd_length = reader.ReadInt32();
                        if (nd_length > 0)
                        {
                            setNick(reader.ReadBytes(nd_length));
                        }
                    }

                    int pk_length = reader.ReadInt32();
                    if (pk_length > 0)
                    {
                        publicKey = reader.ReadBytes(pk_length);
                    }

                    // TODO try/catch wrapper can be removed after upgrade
                    try
                    {
                        if (m.Position < m.Length)
                        {
                            role = reader.ReadString();
                            hasAvatar = reader.ReadBoolean();
                            sendNotification = reader.ReadBoolean();
                        }
                    }catch(Exception)
                    {

                    }
                }
            }
        }

        public byte[] getBytes(bool nick_as_string)
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    if(nick_as_string)
                    {
                        writer.Write(nick);
                    }else
                    {
                        if (nickData == null)
                        {
                            writer.Write((int)0);
                        }
                        else
                        {
                            writer.Write(nickData.Length);
                            writer.Write(nickData);
                        }
                    }

                    if (publicKey == null)
                    {
                        writer.Write((int)0);
                    }
                    else
                    {
                        writer.Write(publicKey.Length);
                        writer.Write(publicKey);
                    }

                    writer.Write(role);
                    writer.Write(hasAvatar);
                    writer.Write(sendNotification);
                }
                return m.ToArray();
            }
        }

        public bool hasRole(int index)
        {
            if(role.Contains(index + ";"))
            {
                return true;
            }
            return false;
        }

        public void setRole(int index)
        {
            if (index == 0)
            {
                role = "";
            }
            else
            {
                role = index + ";";
            }
        }

        public bool addRole(int index)
        {
            if (index == 0)
            {
                return false;
            }
            if (hasRole(index))
            {
                return false;
            }
            role += index + ";";
            return true;
        }

        public bool removeRole(int index)
        {
            if (index == 0)
            {
                return false;
            }
            if (!hasRole(index))
            {
                return false;
            }
            role.Replace(index + ";", "");
            return true;
        }

        public int getPrimaryRole()
        {
            if (role == "" || role == null)
            {
                return 0;
            }
            return Int32.Parse(role.Substring(0, role.IndexOf(';')));
        }
    }
}
