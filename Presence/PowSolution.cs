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
using IXICore.Utils;
using System;
using System.IO;

namespace IXICore
{
    public class PowSolution
    {
        public int version = 1;
        public byte[] blockHash;
        public byte[] solution;

        public PowSolution(byte[] bytes)
        {
            try
            {
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        version = (int)reader.ReadIxiVarInt();

                        int hashLen = (int)reader.ReadIxiVarUInt();
                        blockHash = reader.ReadBytes(hashLen);

                        int solutionLen = (int)reader.ReadIxiVarUInt();
                        solution = reader.ReadBytes(solutionLen);
                    }
                }
            }
            catch (Exception e)
            {
                Logging.warn("Cannot create PoW Solution from bytes: {0}", e.ToString());
                throw;
            }
        }

        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream(640))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.WriteIxiVarInt(version);

                    writer.WriteIxiVarInt(blockHash.Length);
                    writer.Write(blockHash);

                    writer.WriteIxiVarInt(solution.Length);
                    writer.Write(solution);

#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("PresenceList::keepAlive_v1: {0}", m.Length));
#endif
                }

                return m.ToArray();
            }
        }

        public bool verify()
        {

            return false;
        }
    }
}
