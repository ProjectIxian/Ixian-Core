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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace IXICore
{
    public static class BlockVer
    {
        public static int v0 = 0;
        public static int v1 = 1;
        public static int v2 = 2;
        public static int v3 = 3;
        public static int v4 = 4;
        public static int v5 = 5;
        public static int v6 = 6;
        public static int v7 = 7;
        public static int v8 = 8;
        public static int v9 = 9;
        public static int v10 = 10;
    }

    public class SuperBlockSegment
    {
        public ulong blockNum = 0;
        public byte[] blockChecksum = null;

        public SuperBlockSegment(ulong block_num, byte[] block_checksum)
        {
            blockNum = block_num;
            blockChecksum = block_checksum;
        }
    }
    
    /// <summary>
    ///  An Ixian DLT Block Header.
    ///  A block header contains the minimum required data needed for transaction inclusion verification.
    /// </summary>
    /// 
    public class BlockHeader
    {
        /// <summary>
        /// Block height (block number). This is a sequential index in the blockchain which uniquely identifies each block.
        /// </summary>
        public ulong blockNum { get; set; }
        /// <summary>
        /// The list of transactions which should act on the WalletState from the previous block to produce the WalletState for this block.
        /// </summary>
        public HashSet<byte[]> transactions = new HashSet<byte[]>(new ByteArrayComparer());
        /// <summary>
        /// Block version.
        /// </summary>
        /// <remarks>
        ///  New blocks should always be generated with the latest version - `maxVersion`, except during the transitional period while the network
        ///  is upgrading from one block version to the next. Older blocks, retrieved from files or the network may have an older version and this field identifies
        ///  which version the specific block has.
        ///  Some Block features are only enabled from specific versions forward.
        /// </remarks>
        public int version = 0;
        /// <summary>
        ///  Checksum of all the data in the block. This value serves as the basis for block signatures since no block contents may be changed without
        ///  affecting the block checksum.
        /// </summary>
        public byte[] blockChecksum = null;
        /// <summary>
        ///  Checksum of the previous block, so that accepting a new block indirectly confirms and validates all past blocks. This is the basic functionality of DLT.
        /// </summary>
        public byte[] lastBlockChecksum = null;
        /// <summary>
        ///  Checksum of the WalletState after the transactions in this block are applied to the WalletState from the previous block.
        /// </summary>
        /// <remarks>
        ///  This allows Ixian Master Nodes to operate on the WalletState and be certain that it matches all other Master nodes without exchanging all the wallet data.
        ///  WalletState is synchornized when the node first boots up, but is never transferred between nodes later, since it can be updated in a consistent manner
        ///  using the transactions and wallet state checksums in each block.
        /// </remarks>
        public byte[] walletStateChecksum = null;
        /// <summary>
        ///  Checksum of the final list of signatures for block `blockNum - 5`.
        /// </summary>
        /// <remarks>
        ///  In this way, the signers list is 'frozen' and may no longer be changed, preventing various possible tampering attacks. Since the payout of many of the Ixian DLT's
        ///  Master Node functions is tied to the accepted signature list, this field protects that list from malicious tinkering.
        ///  Changes are permitted for five blocks to allow slower nodes to process and apply their signatures.
        /// </remarks>
        public byte[] signatureFreezeChecksum = null;
        /// <summary>
        ///  Unix Epoch value of when the block was generated.
        /// </summary>
        public long timestamp = 0;
        /// <summary>
        ///  List of blocks and their checksums - used only in the superblock functionality.
        /// </summary>
        public Dictionary<ulong, SuperBlockSegment> superBlockSegments = new Dictionary<ulong, SuperBlockSegment>();
        /// <summary>
        ///  Checksum of the previous superblock - used only in superblock functionality.
        /// </summary>
        public byte[] lastSuperBlockChecksum = null;
        /// <summary>
        ///  Block height of the previous superblock - used only in superblock functionality.
        /// </summary>
        public ulong lastSuperBlockNum = 0;
        /// <summary>
        ///  Ixian Hybrid PoW difficulty value.
        /// </summary>
        /// <remarks>
        ///  Ixian Blockchain works on a consensus model and mining is not strictly required. An optional mining system is included to enable initial coin supply distribution.
        ///  The mining algorithm is Argon2id and the solutions are not included in blocks themselves. There is a special Transaction type which submits a solution to a block.
        ///  Miners are able to work on any block in the Redacted History window, with the target block specifying its difficulty to which the posted solution must conform.
        /// </remarks>
        public ulong difficulty = 0;
        /// <summary>
        ///  PIT Hash - transaction root hash, available from block v6
        /// </summary>
        public byte[] pitHash = null;
        /// <summary>
        ///  Address of the block proposer/first signer.
        /// </summary>
        public byte[] blockProposer = null;

        public BlockHeader()
        {
            version = BlockVer.v0;
            blockNum = 0;
            transactions = new HashSet<byte[]>(new ByteArrayComparer());
        }

        /// <summary>
        ///  Copies the given block's header
        /// </summary>
        /// <param name="block">Source block.</param>
        public BlockHeader(Block block)
        {
            version = block.version;
            blockNum = block.blockNum;

            lastSuperBlockNum = block.lastSuperBlockNum;

            foreach (var entry in block.superBlockSegments)
            {
                superBlockSegments.Add(entry.Key, new SuperBlockSegment(entry.Key, entry.Value.blockChecksum));
            }

            if (block.version < BlockVer.v6)
            {
                // Add transactions and signatures from the old block
                foreach (byte[] txid in block.transactions)
                {
                    transactions.Add(txid);
                }
            }else
            {
                pitHash = block.pitChecksum;
            }

            if (block.blockChecksum != null)
            {
                blockChecksum = new byte[block.blockChecksum.Length];
                Array.Copy(block.blockChecksum, blockChecksum, blockChecksum.Length);
            }

            if (block.lastBlockChecksum != null)
            {
                lastBlockChecksum = new byte[block.lastBlockChecksum.Length];
                Array.Copy(block.lastBlockChecksum, lastBlockChecksum, lastBlockChecksum.Length);
            }

            if (block.lastSuperBlockChecksum != null)
            {
                lastSuperBlockChecksum = new byte[block.lastSuperBlockChecksum.Length];
                Array.Copy(block.lastSuperBlockChecksum, lastSuperBlockChecksum, lastSuperBlockChecksum.Length);
            }

            if (block.walletStateChecksum != null)
            {
                walletStateChecksum = new byte[block.walletStateChecksum.Length];
                Array.Copy(block.walletStateChecksum, walletStateChecksum, walletStateChecksum.Length);
            }

            if (block.signatureFreezeChecksum != null)
            {
                signatureFreezeChecksum = new byte[block.signatureFreezeChecksum.Length];
                Array.Copy(block.signatureFreezeChecksum, signatureFreezeChecksum, signatureFreezeChecksum.Length);
            }

            difficulty = block.difficulty;

            timestamp = block.timestamp;

            if (block.blockProposer != null)
            {
                blockProposer = new byte[block.blockProposer.Length];
                Array.Copy(block.blockProposer, blockProposer, blockProposer.Length);
            }
        }

        /// <summary>
        ///  Reconstructs a BlockHeader from the bytestream. See also `getBytes`.
        /// </summary>
        /// <remarks>
        ///  Each block header has a `getBytes()` function which serializes the block header data into a byte buffer, suitable for sending over the network.
        ///  This constructor can re-create the block headerfrom the given bytestream.
        /// </remarks>
        /// <param name="bytes">Block header bytes, usually received from the network.</param>
        public BlockHeader(byte[] bytes)
        {
            try
            {
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        version = reader.ReadInt32();

                        blockNum = reader.ReadUInt64();

                        if (version <= Block.maxVersion)
                        {

                            if (version < BlockVer.v6)
                            {
                                // Get the transaction ids
                                int num_transactions = reader.ReadInt32();
                                for (int i = 0; i < num_transactions; i++)
                                {
                                    string txid = reader.ReadString();
                                    transactions.Add(Transaction.txIdLegacyToV8(txid));
                                }
                            }else
                            {
                                int pit_hash_len = reader.ReadInt32();
                                if (pit_hash_len > 0)
                                {
                                    pitHash = reader.ReadBytes(pit_hash_len);
                                }
                            }

                            int dataLen = reader.ReadInt32();
                            if (dataLen > 0)
                            {
                                blockChecksum = reader.ReadBytes(dataLen);
                            }

                            dataLen = reader.ReadInt32();
                            if (dataLen > 0)
                            {
                                lastBlockChecksum = reader.ReadBytes(dataLen);
                            }

                            dataLen = reader.ReadInt32();
                            if (dataLen > 0)
                            {
                                walletStateChecksum = reader.ReadBytes(dataLen);
                            }

                            dataLen = reader.ReadInt32();
                            if (dataLen > 0)
                            {
                                signatureFreezeChecksum = reader.ReadBytes(dataLen);
                            }

                            difficulty = reader.ReadUInt64();

                            if (version > BlockVer.v4)
                            {
                                lastSuperBlockNum = reader.ReadUInt64();

                                dataLen = reader.ReadInt32();
                                if (dataLen > 0)
                                {
                                    lastSuperBlockChecksum = reader.ReadBytes(dataLen);
                                }

                                int super_block_seg_count = reader.ReadInt32();
                                for (int i = 0; i < super_block_seg_count; i++)
                                {
                                    ulong seg_block_num = reader.ReadUInt64();
                                    int seg_bc_len = reader.ReadInt32();
                                    byte[] seg_bc = null;
                                    if (seg_bc_len > 0)
                                    {
                                        seg_bc = reader.ReadBytes(seg_bc_len);
                                    }
                                    superBlockSegments.Add(seg_block_num, new SuperBlockSegment(seg_block_num, seg_bc));
                                }
                            }

                            timestamp = reader.ReadInt64();

                            try
                            {
                                dataLen = (int)reader.ReadIxiVarUInt();
                                if (dataLen > 0)
                                {
                                    blockProposer = reader.ReadBytes(dataLen);
                                }
                            }
                            catch (Exception)
                            {

                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Logging.warn(string.Format("Cannot create block header from bytes: {0}", e.ToString()));
                throw;
            }
        }

        /// <summary>
        ///  Retrieves the block header in its serialized, 'byte stream' format. See also `BlockHeader(byte[] bytes)`.
        /// </summary>
        /// <remarks>
        ///  A block header can be serialized for network transmission using this function. All relevant fields will be encoded and a byte buffer will
        ///  be returned. The byte buffer contains a copy of the block header, so no thread synchronization is required.
        /// </remarks>
        /// <returns>Byte buffer with the serialized block header.</returns>
        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(version);

                    writer.Write(blockNum);

                    if (version < 6)
                    {
                        // Write the number of transactions
                        int num_transactions = transactions.Count;
                        writer.Write(num_transactions);

                        // Write each wallet
                        foreach (byte[] txid in transactions)
                        {
                            writer.Write(Transaction.txIdV8ToLegacy(txid));
                        }
                    }else
                    {
                        writer.Write(pitHash.Length);
                        writer.Write(pitHash);
                    }

                    writer.Write(blockChecksum.Length);
                    writer.Write(blockChecksum);

                    if (lastBlockChecksum != null)
                    {
                        writer.Write(lastBlockChecksum.Length);
                        writer.Write(lastBlockChecksum);
                    }
                    else
                    {
                        writer.Write((int)0);
                    }

                    if (walletStateChecksum != null)
                    {
                        writer.Write(walletStateChecksum.Length);
                        writer.Write(walletStateChecksum);
                    }
                    else
                    {
                        writer.Write((int)0);
                    }

                    if (signatureFreezeChecksum != null)
                    {
                        writer.Write(signatureFreezeChecksum.Length);
                        writer.Write(signatureFreezeChecksum);
                    }
                    else
                    {
                        writer.Write((int)0);
                    }

                    writer.Write(difficulty);

                    writer.Write(lastSuperBlockNum);

                    if (lastSuperBlockChecksum != null)
                    {
                        writer.Write(lastSuperBlockChecksum.Length);
                        writer.Write(lastSuperBlockChecksum);
                    }
                    else
                    {
                        writer.Write((int)0);
                    }

                    writer.Write(superBlockSegments.Count);
                    foreach (var entry in superBlockSegments)
                    {
                        writer.Write(entry.Key);
                        writer.Write(entry.Value.blockChecksum.Length);
                        writer.Write(entry.Value.blockChecksum);
                    }

                    writer.Write(timestamp);

                    if (blockProposer != null)
                    {
                        writer.WriteIxiVarInt(blockProposer.Length);
                        writer.Write(blockProposer);
                    }
                    else
                    {
                        writer.WriteIxiVarInt((int)0);
                    }
                }
                return m.ToArray();
            }
        }

        /// <summary>
        ///  Calculates the `blockChecksum` of the DLT Block header, using the relevant fields.
        /// </summary>
        /// <returns>Byte value of the checksum result.</returns>
        public byte[] calculateChecksum()
        {
            List<byte> merged_segments = new List<byte>();
            foreach (var entry in superBlockSegments.OrderBy(x => x.Key))
            {
                merged_segments.AddRange(BitConverter.GetBytes(entry.Key));
                merged_segments.AddRange(entry.Value.blockChecksum);
            }

            List<byte> rawData = new List<byte>();
            rawData.AddRange(ConsensusConfig.ixianChecksumLock);
            rawData.AddRange(BitConverter.GetBytes(version));
            rawData.AddRange(BitConverter.GetBytes(blockNum));
            if (version < BlockVer.v6)
            {
                StringBuilder merged_txids = new StringBuilder();
                foreach (byte[] txid in transactions)
                {
                    merged_txids.Append(Transaction.txIdV8ToLegacy(txid));
                }

                rawData.AddRange(Encoding.UTF8.GetBytes(merged_txids.ToString()));
            }
            else
            {
                // PIT is included in checksum since v6
                rawData.AddRange(pitHash);
            }

            if (lastBlockChecksum != null)
            {
                rawData.AddRange(lastBlockChecksum);
            }

            if (walletStateChecksum != null)
            {
                rawData.AddRange(walletStateChecksum);
            }

            if (signatureFreezeChecksum != null)
            {
                rawData.AddRange(signatureFreezeChecksum);
            }

            rawData.AddRange(BitConverter.GetBytes(difficulty));
            rawData.AddRange(merged_segments);

            if (lastSuperBlockChecksum != null)
            {
                rawData.AddRange(BitConverter.GetBytes(lastSuperBlockNum));
                rawData.AddRange(lastSuperBlockChecksum);
            }

            if (version >= BlockVer.v7)
            {
                rawData.AddRange(BitConverter.GetBytes(timestamp));
            }

            if(version >= BlockVer.v9)
            {
                rawData.AddRange(blockProposer);
            }

            if (version <= BlockVer.v2)
            {
                return Crypto.sha512quTrunc(rawData.ToArray());
            }
            else
            {
                return Crypto.sha512sqTrunc(rawData.ToArray());
            }
        }


        /// <summary>
        ///  Checks if the two blockheaders are exactly equal.
        /// </summary>
        /// <param name="bh">Other blockheader.</param>
        /// <returns>True if both objects represent the same Block Header.</returns>
        public bool Equals(BlockHeader bh)
        {
            byte[] a1 = getBytes();
            byte[] a2 = bh.getBytes();

            return a1.SequenceEqual(a2);
        }

    }
}
