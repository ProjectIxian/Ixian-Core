// Copyright (C) 2017-2020 Ixian OU
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

using System.IO;

namespace IXICore.SpixiBot
{
    public class BotGroup
    {
        public int index;
        public string groupName;
        public IxiNumber messageCost = 0;
        public bool admin = false;

        public BotGroup(int id, string name, IxiNumber cost, bool admin)
        {
            index = id;
            groupName = name;
            messageCost = cost;
            this.admin = admin;
        }

        public BotGroup(byte[] contact_bytes)
        {
            using (MemoryStream m = new MemoryStream(contact_bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    index = reader.ReadInt32();
                    groupName = reader.ReadString();
                    messageCost = new IxiNumber(reader.ReadString());
                    admin = reader.ReadBoolean();
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
                    writer.Write(groupName);
                    writer.Write(messageCost.ToString());
                    writer.Write(admin);
                }
                return m.ToArray();
            }
        }
    }
}
