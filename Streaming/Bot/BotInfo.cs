﻿// Copyright (C) 2017-2020 Ixian OU
// This file is part of Ixian Core - www.github.com/ProjectIxian/Ixian-Core
//
// Ixian Core is free software: you can redistribute it and/or modify
// it under the terms of the MIT License as published
// by the Open Source Initiative.
//
// Ixian Core is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// MIT License for more details.

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
        public long userCount = 0;


        public BotInfo(short version, string server_name, string server_description, IxiNumber cost, long settings_generated_time, bool admin, int default_group, int default_channel, bool send_notification, long userCount)
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
            this.userCount = userCount;
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
                    if (m.Position < m.Length)
                    {
                        sendNotification = reader.ReadBoolean();
                    }
                    if (m.Position < m.Length)
                    {
                        userCount = reader.ReadInt64();
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
                    writer.Write(userCount);
                }
                return m.ToArray();
            }
        }
    }
}
