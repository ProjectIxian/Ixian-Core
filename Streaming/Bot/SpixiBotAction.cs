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

using IXICore.Meta;
using System;
using System.IO;

namespace IXICore.SpixiBot
{
    public enum SpixiBotActionCode
    {
        getInfo,
        info,
        getChannels,
        channel,
        getUsers,
        user,
        getGroups,
        group,
        getPayment,
        payment,
        kickUser,
        banUser,
        enableNotifications
    }

    class SpixiBotAction
    {
        public SpixiBotActionCode action;
        public byte[] data = null;

        public SpixiBotAction(SpixiBotActionCode action, byte[] data)
        {
            this.action = action;
            this.data = data;
        }

        public SpixiBotAction(byte[] bytes)
        {
            try
            {
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        int action = reader.ReadInt16();
                        this.action = (SpixiBotActionCode)action;

                        int data_length = reader.ReadInt32();
                        if (data_length > 0)
                            data = reader.ReadBytes(data_length);
                    }
                }
            }
            catch (Exception e)
            {
                Logging.error("Exception occured while trying to construct SpixiBotAction from bytes: " + e);
            }
        }

        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    // Write the type
                    writer.Write((short)action);

                    // Write the data
                    if (data != null)
                    {
                        writer.Write(data.Length);
                        writer.Write(data);
                    }
                    else
                    {
                        writer.Write(0);
                    }
                }
                return m.ToArray();
            }
        }

    }
}
