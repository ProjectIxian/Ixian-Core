using IXICore.Meta;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace IXICore.SpixiBot
{
    public class BotGroups
    {
        public Dictionary<string, BotGroup> groups = new Dictionary<string, BotGroup>();

        string groupsPath = "groups.ixi";

        public BotGroups(string groups_path)
        {
            groupsPath = groups_path;
        }

        public void writeGroupsToFile()
        {
            lock (groups)
            {
                BinaryWriter writer;
                try
                {
                    // Prepare the file for writing
                    writer = new BinaryWriter(new FileStream(groupsPath, FileMode.Create));
                }
                catch (Exception e)
                {
                    Logging.error("Cannot create {0} file: {1}", groupsPath, e.Message);
                    return;
                }

                try
                {
                    int version = 0;
                    writer.Write(version);

                    int num_groups = groups.Count;
                    writer.Write(num_groups);

                    foreach (var group in groups)
                    {
                        byte[] group_bytes = group.Value.getBytes();
                        writer.Write(group_bytes.Length);
                        writer.Write(group_bytes);
                    }
                }
                catch (Exception e)
                {
                    Logging.error("Cannot create {0} file: {1}", groupsPath, e.Message);
                }
                writer.Close();
            }
        }

        public void loadGroupsFromFile()
        {
            if (File.Exists(groupsPath) == false)
            {
                return;
            }

            lock (groups)
            {
                BinaryReader reader;
                try
                {
                    reader = new BinaryReader(new FileStream(groupsPath, FileMode.Open));
                }
                catch (Exception e)
                {
                    Logging.error("Cannot open {9} file: {1}", groupsPath, e.Message);
                    return;
                }

                try
                {
                    int version = reader.ReadInt32();

                    int num_groups = reader.ReadInt32();
                    for (int i = 0; i < num_groups; i++)
                    {
                        int group_len = reader.ReadInt32();
                        byte[] group_bytes = reader.ReadBytes(group_len);

                        BotGroup bc = new BotGroup(group_bytes);
                        groups.AddOrReplace(bc.groupName, bc);
                    }
                }
                catch (Exception e)
                {
                    Logging.error("Cannot read from {0} file: {1}", groupsPath, e.Message);
                    // TODO TODO notify the user or something like that
                }

                reader.Close();
            }
        }

        public bool hasGroup(string name)
        {
            lock (groups)
            {
                if (groups.ContainsKey(name))
                {
                    return true;
                }
            }
            return false;
        }

        public BotGroup getGroup(string name)
        {
            lock (groups)
            {
                if (groups.ContainsKey(name))
                {
                    return groups[name];
                }
            }
            return null;
        }

        public bool setGroup(string name, BotGroup group)
        {
            lock (groups)
            {
                if (group == null)
                {
                    if (groups.ContainsKey(name))
                    {
                        groups.Remove(name);
                    }
                }
                else
                {
                    groups.AddOrReplace(name, group);
                }
                writeGroupsToFile();
            }
            return true;
        }

        public int getNextIndex()
        {
            lock (groups)
            {
                if (groups.Count() > 0)
                {
                    return groups.Last().Value.index + 1;
                }
            }
            return 1;
        }

        public string groupIndexToName(int id)
        {
            if(id == 0)
            {
                return "";
            }
            lock (groups)
            {
                try
                {
                    var group = groups.First(x => x.Value.index == id);
                    return group.Key;
                }
                catch (Exception e)
                {
                    Logging.error("Error getting group with id {0}: {1}", id, e);
                }
                return null;
            }
        }
    }
}
