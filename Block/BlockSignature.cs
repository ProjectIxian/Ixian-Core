// Copyright (C) 2017-2021 Ixian OU
// This file is part of Ixian Core - www.github.com/ProjectIxian/Ixian-Core
//
// Ixian DLT is free software: you can redistribute it and/or modify
// it under the terms of the MIT License as published
// by the Open Source Initiative.
//
// Ixian DLT is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// MIT License for more details.

using IXICore.Meta;
using IXICore.Utils;
using System;
using System.IO;

namespace IXICore
{
    public class BlockSignature
    {
        public ulong blockNum;
        public byte[] blockHash;
        public byte[] signature;
        public byte[] signerAddress;
        public SignerPowSolution powSoluton;

        public BlockSignature()
        {

        }

        public BlockSignature(BlockSignature src)
        {
            blockNum = src.blockNum;

            blockHash = new byte[src.blockHash.Length];
            Array.Copy(src.blockHash, blockHash, blockHash.Length);

            signature = new byte[src.signature.Length];
            Array.Copy(src.signature, signature, signature.Length);

            signerAddress = new byte[src.signerAddress.Length];
            Array.Copy(src.signerAddress, signerAddress, signerAddress.Length);

            powSoluton = new SignerPowSolution(src.powSoluton);
        }

        public BlockSignature(byte[] bytes, bool bytesFromBroadcast)
        {
            try
            {
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        if(bytesFromBroadcast)
                        {
                            ulong blockNum = reader.ReadIxiVarUInt();

                            int blockHashLen = (int)reader.ReadIxiVarUInt();
                            blockHash = reader.ReadBytes(blockHashLen);
                        }

                        int signatureLen = (int)reader.ReadIxiVarUInt();
                        signature = reader.ReadBytes(signatureLen);

                        int signerAddressLen = (int)reader.ReadIxiVarUInt();
                        signerAddress = reader.ReadBytes(signerAddressLen);

                        if(m.Position < m.Length)
                        {
                            int powSolutonLen = (int)reader.ReadIxiVarUInt();
                            powSoluton = new SignerPowSolution(reader.ReadBytes(powSolutonLen));
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Logging.warn("Cannot create PoW Solution from bytes: {0}", e.ToString());
                throw;
            }
        }

        public byte[] getBytesForBlock()
        {
            using (MemoryStream m = new MemoryStream(1152))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.WriteIxiVarInt(signature.Length);
                    writer.Write(signature);

                    writer.WriteIxiVarInt(signerAddress.Length);
                    writer.Write(signerAddress);

                    if (powSoluton != null)
                    {
                        byte[] powSolutionBytes = powSoluton.getBytes(false);
                        writer.WriteIxiVarInt(powSolutionBytes.Length);
                        writer.Write(powSolutionBytes);
                    }
                    else
                    {
                        writer.WriteIxiVarInt(0);
                    }

#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("NetworkProtocol::broadcastNewBlockSignature: {0}", m.Length));
#endif
                }

                return m.ToArray();
            }
        }

        public byte[] getBytesForBroadcast()
        {
            using (MemoryStream m = new MemoryStream(1152))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.WriteIxiVarInt(blockNum);

                    writer.WriteIxiVarInt(blockHash.Length);
                    writer.Write(blockHash);

                    writer.WriteIxiVarInt(signature.Length);
                    writer.Write(signature);

                    writer.WriteIxiVarInt(signerAddress.Length);
                    writer.Write(signerAddress);

                    if(powSoluton != null)
                    {
                        byte[] powSolutionBytes = powSoluton.getBytes(false);
                        writer.WriteIxiVarInt(powSolutionBytes.Length);
                        writer.Write(powSolutionBytes);
                    }else
                    {
                        writer.WriteIxiVarInt(0);
                    }

#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("NetworkProtocol::broadcastNewBlockSignature: {0}", m.Length));
#endif
                }

                return m.ToArray();
            }
        }
    }
}
