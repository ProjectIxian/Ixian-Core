using IXICore.Meta;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.IO;

namespace IXICore.SpixiBot
{
    public class BotUsers
    {
        public Dictionary<byte[], BotContact> contacts = new Dictionary<byte[], BotContact>(new ByteArrayComparer());

        string contactsPath = "contacts.ixi";
        string avatarPath = "Avatars";
        bool saveNickAsString = false;

        public BotUsers(string contacts_path, string avatar_path, bool save_nick_as_string)
        {
            saveNickAsString = save_nick_as_string;
            contactsPath = contacts_path;
            if (avatar_path != null)
            {
                if (!Directory.Exists(avatar_path))
                {
                    Directory.CreateDirectory(avatar_path);
                }
            }
            avatarPath = avatar_path;
        }

        public void writeContactsToFile()
        {
            lock (contacts)
            {
                FileStream fs;
                BinaryWriter writer;
                try
                {
                    // Prepare the file for writing
                    fs = new FileStream(contactsPath, FileMode.Create);
                    writer = new BinaryWriter(fs);
                }
                catch (Exception e)
                {
                    Logging.error("Cannot create {0} file: {1}", contactsPath, e.Message);
                    return;
                }

                try
                {
                    int version = 0;
                    writer.Write(version);

                    int num_contacts = contacts.Count;
                    writer.Write(num_contacts);

                    foreach (var contact in contacts)
                    {
                        byte[] contact_bytes = contact.Value.getBytes(saveNickAsString);
                        writer.Write(contact_bytes.Length);
                        writer.Write(contact_bytes);
                    }
                }
                catch (Exception e)
                {
                    Logging.error("Cannot write to {0} file: {1}", contactsPath, e.Message);
                }
                writer.Flush();
                writer.Close();
                writer.Dispose();

                fs.Close();
                fs.Dispose();
            }
        }

        public void loadContactsFromFile()
        {
            if (File.Exists(contactsPath) == false)
            {
                return;
            }

            lock (contacts)
            {
                BinaryReader reader;
                try
                {
                    reader = new BinaryReader(new FileStream(contactsPath, FileMode.Open));
                }
                catch (Exception e)
                {
                    Logging.error("Cannot open {0} file: {1}", contactsPath, e.Message);
                    return;
                }

                try
                {
                    int version = reader.ReadInt32();

                    int num_contacts = reader.ReadInt32();
                    for (int i = 0; i < num_contacts; i++)
                    {
                        int contact_len = reader.ReadInt32();
                        byte[] contact_bytes = reader.ReadBytes(contact_len);

                        BotContact bc = new BotContact(contact_bytes, saveNickAsString);
                        byte[] address = new Address(bc.publicKey).address;
                        contacts.AddOrReplace(address, bc);
                    }
                }
                catch (Exception e)
                {
                    Logging.error("Cannot read from {0} file: {1}", contactsPath, e.Message);
                    // TODO TODO notify the user or something like that
                }

                reader.Close();
            }
        }

        public bool hasUser(byte[] address)
        {
            lock (contacts)
            {
                if (contacts.ContainsKey(address))
                {
                    return true;
                }
            }
            return false;
        }

        public BotContact getUser(byte[] address)
        {
            lock(contacts)
            {
                if(contacts.ContainsKey(address))
                {
                    return contacts[address];
                }
            }
            return null;
        }

        public bool delUser(byte[] address)
        {
            lock (contacts)
            {
                if (!hasUser(address))
                {
                    return false;
                }
                contacts.Remove(address);
                writeContactsToFile();
            }
            return true;
        }

        public bool setPubKey(byte[] address, byte[] pub_key)
        {
            lock (contacts)
            {
                if (!hasUser(address))
                {
                    contacts.Add(address, new BotContact(null, pub_key, 0, false));
                    writeContactsToFile();
                }
            }
            return true;
        }

        public bool setAvatar(byte[] address, byte[] avatar_message)
        {
            if(avatarPath == null)
            {
                throw new Exception("Cannot set avatar, avatarPath is null.");
            }
            lock (contacts)
            {
                if (!hasUser(address))
                {
                    return false;
                }
                string path = Path.Combine(avatarPath, Base58Check.Base58CheckEncoding.EncodePlain(address) + ".raw");
                if (avatar_message != null)
                {
                    File.WriteAllBytes(path, avatar_message);
                    getUser(address).hasAvatar = true;
                }
                else if (File.Exists(path))
                {
                    File.Delete(path);
                    getUser(address).hasAvatar = false;
                }
                writeContactsToFile();
            }
            return true;
        }

        public bool setNick(byte[] address, byte[] nick)
        {
            lock (contacts)
            {
                if (!hasUser(address))
                {
                    return false;
                }
                contacts[address].setNick(nick);
                writeContactsToFile();
            }
            return true;
        }

        public bool setRole(byte[] address, int role)
        {
            lock (contacts)
            {
                if (!hasUser(address))
                {
                    return false;
                }
                contacts[address].setRole(role);
                writeContactsToFile();
            }
            return true;
        }

        public void setUser(BotContact user)
        {
            lock (contacts)
            {
                contacts.AddOrReplace(new Address(user.publicKey).address, user);
                writeContactsToFile();
            }
        }

        public string getAvatarPath(byte[] address)
        {
            if (avatarPath == null)
            {
                throw new Exception("Cannot get avatar path, avatarPath is null.");
            }

            if (!hasUser(address))
            {
                return null;
            }
            string path = Path.Combine(avatarPath, Base58Check.Base58CheckEncoding.EncodePlain(address) + ".raw");
            if (!File.Exists(path))
            {
                return null;
            }
            return path;
        }

        public int count()
        {
            lock (contacts)
            {
                return contacts.Count;
            }
        }
    }
}
