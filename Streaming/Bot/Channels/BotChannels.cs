using IXICore.Meta;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace IXICore.SpixiBot
{
    public class BotChannels
    {
        public Dictionary<string, BotChannel> channels = new Dictionary<string, BotChannel>();

        string channelsPath = "channels.ixi";

        public BotChannels(string channels_path)
        {
            channelsPath = channels_path;
        }

        public void writeChannelsToFile()
        {
            lock (channels)
            {
                BinaryWriter writer;
                try
                {
                    // Prepare the file for writing
                    writer = new BinaryWriter(new FileStream(channelsPath, FileMode.Create));
                }
                catch (Exception e)
                {
                    Logging.error("Cannot create {0} file: {1}", channelsPath, e.Message);
                    return;
                }

                try
                {
                    int version = 0;
                    writer.Write(version);

                    int num_channels = channels.Count;
                    writer.Write(num_channels);

                    foreach (var channel in channels)
                    {
                        byte[] channel_bytes = channel.Value.getBytes();
                        writer.Write(channel_bytes.Length);
                        writer.Write(channel_bytes);
                    }
                }
                catch (Exception e)
                {
                    Logging.error("Cannot write to {9} file: {1}", channelsPath, e.Message);
                }
                writer.Close();
            }
        }

        public void loadChannelsFromFile()
        {
            if (File.Exists(channelsPath) == false)
            {
                return;
            }

            lock (channels)
            {
                BinaryReader reader;
                try
                {
                    reader = new BinaryReader(new FileStream(channelsPath, FileMode.Open));
                }
                catch (Exception e)
                {
                    Logging.error("Cannot open {9} file: {1}", channelsPath, e.Message);
                    return;
                }

                try
                {
                    int version = reader.ReadInt32();

                    int num_channels = reader.ReadInt32();
                    for (int i = 0; i < num_channels; i++)
                    {
                        int channel_len = reader.ReadInt32();
                        byte[] channel_bytes = reader.ReadBytes(channel_len);

                        BotChannel bc = new BotChannel(channel_bytes);
                        channels.AddOrReplace(bc.channelName, bc);
                    }
                }
                catch (Exception e)
                {
                    Logging.error("Cannot read from {0} file: {1}", channelsPath, e.Message);
                    // TODO TODO notify the user or something like that
                }

                reader.Close();
            }
        }

        public bool hasChannel(string name)
        {
            lock (channels)
            {
                if (channels.ContainsKey(name))
                {
                    return true;
                }
            }
            return false;
        }

        public BotChannel getChannel(string name)
        {
            lock (channels)
            {
                if (channels.ContainsKey(name))
                {
                    return channels[name];
                }
            }
            return null;
        }

        public bool setChannel(string name, BotChannel channel)
        {
            lock (channels)
            {
                if (channel == null)
                {
                    if (channels.ContainsKey(name))
                    {
                        channels.Remove(name);
                    }
                }
                else
                {
                    channels.AddOrReplace(name, channel);
                }
                writeChannelsToFile();
            }
            return true;
        }

        public int getNextIndex()
        {
            lock (channels)
            {
                if (channels.Count() > 0)
                {
                    return channels.Last().Value.index + 1;
                }
            }
            return 1;
        }

        public string channelIndexToName(int id)
        {
            if (id == 0)
            {
                return "";
            }
            lock (channels)
            {
                try
                {
                    var channel = channels.First(x => x.Value.index == id);
                    return channel.Key;
                }catch(Exception e)
                {
                    Logging.error("Error getting channel with id {0}: {1}", id, e);
                }
                return null;
            }
        }

        public void clear()
        {
            lock (channels)
            {
                channels.Clear();
            }
        }
    }
}
