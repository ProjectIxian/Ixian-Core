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
using System.Linq;

namespace IXICore
{
    // An object class that describes how to contact the specific node/client
    public class PresenceAddress
    {
        public int version = 1;
        public byte[] device; // Device id
        public string address; // IP and port
        public char type;   // M for MasterNode, R for RelayNode, D for Direct ip client, C for normal client
        public string nodeVersion; // Version
        public long lastSeenTime;
        public byte[] signature;

        public PresenceAddress(byte[] node_device, string node_address, char node_type, string node_version, long node_lastSeenTime, byte[] node_signature)
        {
            device = node_device;
            address = node_address;
            type = node_type;
            nodeVersion = node_version;
            lastSeenTime = node_lastSeenTime;
            signature = node_signature;
        }

        public PresenceAddress(byte[] bytes)
        {
            try
            {
                if (bytes.Length > 1024)
                {
                    throw new Exception("PresenceAddress size is bigger than 1kB.");
                }
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        if (bytes[0] == 1)
                        {
                            version = reader.ReadInt32();
                        }
                        else
                        {
                            version = (int)reader.ReadIxiVarInt();
                        }
                        if (version == 1)
                        {
                            // TODO remove this after upgrade
                            device = System.Guid.Parse(reader.ReadString()).ToByteArray();
                            address = reader.ReadString();
                            type = reader.ReadChar();
                            nodeVersion = reader.ReadString();
                            lastSeenTime = reader.ReadInt64();
                            int sigLen = reader.ReadInt32();
                            if (sigLen > 0)
                            {
                                signature = reader.ReadBytes(sigLen);
                            }
                        }
                        else
                        {
                            int device_len = (int)reader.ReadIxiVarUInt();
                            device = reader.ReadBytes(device_len);
                            address = reader.ReadString();
                            type = reader.ReadChar();
                            nodeVersion = reader.ReadString();
                            lastSeenTime = reader.ReadIxiVarInt();
                            int sigLen = (int)reader.ReadIxiVarUInt();
                            if (sigLen > 0)
                            {
                                signature = reader.ReadBytes(sigLen);
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Logging.error("Exception occurred while trying to construct PresenceAddress from bytes: " + e);
                throw;
            }
        }

        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream(640))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    if (version == 1)
                    {
                        // TODO remove this after upgrade
                        writer.Write(version);
                        writer.Write(new System.Guid(device).ToString());
                        writer.Write(address);
                        writer.Write(type);
                        writer.Write(nodeVersion);
                        writer.Write(lastSeenTime);
                        if (signature != null)
                        {
                            writer.Write(signature.Length);
                            writer.Write(signature);
                        }
                        else
                        {
                            writer.Write(0);
                        }
                    }
                    else
                    {
                        writer.WriteIxiVarInt(version);
                        writer.WriteIxiVarInt(device.Length);
                        writer.Write(device);

                        writer.Write(address);
                        writer.Write(type);
                        writer.Write(nodeVersion);
                        writer.WriteIxiVarInt(lastSeenTime);
                        if (signature != null)
                        {
                            writer.WriteIxiVarInt(signature.Length);
                            writer.Write(signature);
                        }
                        else
                        {
                            writer.Write(0);
                        }
                    }
#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("PresenceAddress::getBytes: {0}", m.Length));
#endif
                }
                return m.ToArray();
            }
        }

        public bool verifySignature(Address wallet, byte[] pub_key, SignerPowSolution powSolution)
        {
            if (signature != null)
            {
                using (MemoryStream m = new MemoryStream())
                {
                    byte[] data_to_verify = null;
                    using (BinaryWriter writer = new BinaryWriter(m))
                    {
                        if (version == 1)
                        {
                            // TODO remove this section after upgrade to Presence v2
                            writer.Write(version);
                            writer.Write(wallet.addressWithChecksum.Length);
                            writer.Write(wallet.addressWithChecksum);
                            writer.Write(new System.Guid(device).ToString());
                            writer.Write(lastSeenTime);
                            writer.Write(address);
                            writer.Write(type);

                            data_to_verify = m.ToArray();
                        }
                        else
                        {
                            writer.WriteIxiVarInt(version);
                            writer.WriteIxiVarInt(wallet.addressNoChecksum.Length);
                            writer.Write(wallet.addressNoChecksum);
                            writer.WriteIxiVarInt(device.Length);
                            writer.Write(device);
                            writer.WriteIxiVarInt(lastSeenTime);
                            writer.Write(address);
                            writer.Write(type);
                            if(powSolution != null)
                            {
                                byte[] powSolutionBytes = powSolution.getBytes();
                                writer.WriteIxiVarInt(powSolutionBytes.Length);
                                writer.Write(powSolutionBytes);
                            }
                            else
                            {
                                writer.WriteIxiVarInt(0);
                            }

                            byte[] tmpBytes = m.ToArray();
                            byte[] tmpBytesWithLock = new byte[ConsensusConfig.ixianChecksumLock.Length + tmpBytes.Length];
                            Array.Copy(ConsensusConfig.ixianChecksumLock, tmpBytesWithLock, ConsensusConfig.ixianChecksumLock.Length);
                            Array.Copy(tmpBytes, 0, tmpBytesWithLock, ConsensusConfig.ixianChecksumLock.Length, tmpBytes.Length);
                            data_to_verify = CryptoManager.lib.sha3_512sqTrunc(tmpBytesWithLock);
                        }
                    }

                    // Verify the signature
                    if (CryptoManager.lib.verifySignature(data_to_verify, pub_key, signature))
                    {
                        return true;
                    }
                }
            }


            return false;
        }

        public KeepAlive getKeepAlive(Address walletAddress, SignerPowSolution powSolution)
        {
            KeepAlive ka = new KeepAlive()
            {
                deviceId = device,
                hostName = address,
                nodeType = type,
                signature = signature,
                timestamp = lastSeenTime,
                version = version,
                walletAddress = walletAddress,
                powSolution = powSolution
            };

            return ka;
        }

        public override bool Equals(object obj)
        {
            var item = obj as PresenceAddress;

            if (item == null)
            {
                return false;
            }

            if (item.address.SequenceEqual(address) == false)
            {
                return false;
            }

            if (item.device.SequenceEqual(device) == false)
            {
                return false;
            }

            if (item.type != type)
            {
                return false;
            }

            if (item.nodeVersion.Equals(nodeVersion, StringComparison.Ordinal) == false)
            {
                return false;
            }

            return true;
        }

        public override int GetHashCode()
        {
            return device.GetHashCode() ^ address.GetHashCode();
        }
    }
}
