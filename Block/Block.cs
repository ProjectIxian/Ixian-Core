using IXICore.Meta;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace IXICore
{
    /// <summary>
    ///  An Ixian DLT Block.
    ///  A block contains all the transactions which act on the WalletState and various checksums which validate the actions performed on the blockchain.
    ///  Blocks are the fundamental data structure of Distributed Ledger Technology (DLT) and form a chain of valid states from the so-called 'Genesis Block' to the present moment.
    ///  An Ixian Block must include checksums of the previous block, checksums of the internal data structures (WalletState) and a list of transactions which have updated the WalletState
    ///  from its previous value to its current value.
    ///  In addition, a block contains cryptographic signatures of Master nodes, which is the basis for the Ixian Consensus algorithm.
    /// </summary>
    public class Block
    {
        /// <summary>
        /// Latest possible version of the Block structure. New blocks should usually be created with the latest version.
        /// </summary>
        public static int maxVersion = BlockVer.v7;

        /// <summary>
        /// Block height (block number). This is a sequential index in the blockchain which uniquely identifies each block.
        /// </summary>
        public ulong blockNum { get; set; }

        /// <summary>
        /// The list of transactions which should act on the WalletState from the previous block to produce the WalletState for this block.
        /// </summary>
        public List<string> transactions = new List<string> { };

        /// <summary>
        /// The list of Master Node signatures which enable the Ixian Consensus algorithm.
        /// </summary>
        public List<byte[][]> signatures = new List<byte[][]> { };

        /// <summary>
        /// Prefix Inclusion Tree (PIT) checksum which enables the TIV protocol.
        /// </summary>
        public byte[] pitChecksum { get { return transactionPIT.calculateTreeHash(); } }

        private PrefixInclusionTree transactionPIT;

        /// <summary>
        /// The list of Frozen Master Node signatures which enable the Ixian Consensus algorithm.
        /// </summary>
        public List<byte[][]> frozenSignatures = null;

        private int signatureCount = 0; // used only when block is compacted

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
        ///  Ixian Hybrid PoW difficulty value.
        /// </summary>
        /// <remarks>
        ///  Ixian Blockchain works on a consensus model and mining is not strictly required. An optional mining system is included to enable initial coin supply distribution.
        ///  The mining algorithm is Argon2id and the solutions are not included in blocks themselves. There is a special Transaction type which submits a solution to a block.
        ///  Miners are able to work on any block in the Redacted History window, with the target block specifying its difficulty to which the posted solution must conform.
        /// </remarks>
        public ulong difficulty = 0;
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
        ///  Ixian Hybrid PoW solution, if it exists for this block.
        /// </summary>
        /// <remarks>
        ///  This field is not included in the block checksum, nor is it transmitted over the network. Master Nodes fill this information for themselves from the
        ///  special PoW-Solution transaction types in the TransactionPool.
        /// </remarks>
        public byte[] powField = null;


        /// <summary>
        ///  Indicator which shows if the block was processed through the Consensus algorithm, or read from cold storage.
        /// </summary>
        public bool fromLocalStorage = false;

        /// <summary>
        ///  Indicator to show if the block has already been compacted through the superblock functionality.
        /// </summary>
        public bool compacted = false;
        /// <summary>
        ///  Indicator to show if the block's signatures have been compacted through the superblock functionality.
        /// </summary>
        public bool compactedSigs = false;

        // Generate the genesis block
        static Block createGenesisBlock()
        {
            Block genesis = new Block();
 
            genesis.calculateChecksum();
            genesis.applySignature();

            return genesis;
        }


        public Block()
        {
            version = BlockVer.v0;
            blockNum = 0;
            transactions = new List<string>();
            initPITTree();
        }

        /// <summary>
        ///  Copies the given block rather than making a reference to it.
        /// </summary>
        /// <remarks>
        ///  This constructor is used in some places of the DLT software where copies of the block data are required and where such a copy
        ///  would improve performance by requiring less thread synchronziation.
        /// </remarks>
        /// <param name="block">Source block.</param>
        public Block(Block block)
        {
            version = block.version;
            blockNum = block.blockNum;
            initPITTree();

            lastSuperBlockNum = block.lastSuperBlockNum;

            foreach(var entry in block.superBlockSegments)
            {
                superBlockSegments.Add(entry.Key, new SuperBlockSegment(entry.Key, entry.Value.blockChecksum));
            }

            // Add transactions and signatures from the old block
            foreach (string txid in block.transactions)
            {
                transactions.Add(txid);
                transactionPIT.add(txid);
            }

            foreach (byte[][] signature in block.signatures)
            {
                byte[][] newSig = new byte[2][];
                if (signature[0] != null)
                {
                    newSig[0] = new byte[signature[0].Length];
                    Array.Copy(signature[0], newSig[0], newSig[0].Length);
                }
                newSig[1] = new byte[signature[1].Length];
                Array.Copy(signature[1], newSig[1], newSig[1].Length);
                signatures.Add(newSig);
            }

            if (block.frozenSignatures != null)
            {
                List<byte[][]> frozen_signatures = new List<byte[][]>();
                foreach (byte[][] signature in block.frozenSignatures)
                {
                    byte[][] newSig = new byte[2][];
                    if (signature[0] != null)
                    {
                        newSig[0] = new byte[signature[0].Length];
                        Array.Copy(signature[0], newSig[0], newSig[0].Length);
                    }
                    newSig[1] = new byte[signature[1].Length];
                    Array.Copy(signature[1], newSig[1], newSig[1].Length);
                    frozen_signatures.Add(newSig);
                }
                setFrozenSignatures(frozen_signatures);
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

            if (block.powField != null)
            {
                powField = new byte[block.powField.Length];
                Array.Copy(block.powField, powField, powField.Length);
            }

            timestamp = block.timestamp;
            difficulty = block.difficulty;

            fromLocalStorage = block.fromLocalStorage;

            compacted = block.compacted;
            compactedSigs = block.compactedSigs;
            signatureCount = block.signatureCount;
        }

        /// <summary>
        ///  Reconstructs a Block from the bytestream. See also `getBytes`.
        /// </summary>
        /// <remarks>
        ///  Each block has a `getBytes()` function which serializes the block data into a byte buffer, suitable for sending over the network.
        ///  This constructor can re-create the block from the given bytestream.
        /// </remarks>
        /// <param name="bytes">Block bytes, usually received from the network.</param>
        public Block(byte[] bytes)
        {
            initPITTree();
            try
            {
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        version = reader.ReadInt32();

                        blockNum = reader.ReadUInt64();

                        if (version < BlockVer.v6)
                        {
                            if (bytes.Length > 49152000)
                            {
                                throw new Exception("Block #" + blockNum + " size is bigger than 49MB.");
                            }
                        }else
                        {
                            if (bytes.Length > 10240000)
                            {
                                throw new Exception("Block #" + blockNum + " size is bigger than 19MB.");
                            }
                        }

                        if (version <= maxVersion)
                        {

                            // Get the transaction ids
                            int num_transactions = reader.ReadInt32();
                            for (int i = 0; i < num_transactions; i++)
                            {
                                string txid = reader.ReadString();
                                if (transactions.Contains(txid))
                                {
                                    // Block contains duplicate txid
                                    throw new Exception("Block #" + blockNum + " contains duplicate txid");
                                }
                                transactions.Add(txid);
                                transactionPIT.add(txid);
                            }

                            // Get the signatures
                            int num_signatures = reader.ReadInt32();

                            if (num_signatures > ConsensusConfig.maximumBlockSigners * 2)
                            {
                                throw new Exception("Block #" + blockNum + " has more than " + (ConsensusConfig.maximumBlockSigners * 2) + " signatures");
                            }


                            for (int i = 0; i < num_signatures; i++)
                            {
                                int sigLen = reader.ReadInt32();
                                byte[] sig = null;
                                if (sigLen > 0)
                                {
                                    sig = reader.ReadBytes(sigLen);
                                }

                                int sigAddresLen = reader.ReadInt32();
                                byte[] sigAddress = null;
                                if (sigAddresLen > 0)
                                {
                                    sigAddress = reader.ReadBytes(sigAddresLen);
                                }

                                if (!containsSignature(new Address(sigAddress)))
                                {
                                    byte[][] newSig = new byte[2][];
                                    newSig[0] = sig;
                                    newSig[1] = sigAddress;
                                    signatures.Add(newSig);
                                }
                            }

                            int dataLen = reader.ReadInt32();
                            if(dataLen > 0)
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
                            timestamp = reader.ReadInt64();

                            if(version > BlockVer.v4)
                            {
                                lastSuperBlockNum = reader.ReadUInt64();

                                dataLen = reader.ReadInt32();
                                if (dataLen > 0)
                                {
                                    lastSuperBlockChecksum = reader.ReadBytes(dataLen);
                                }

                                int super_block_seg_count = reader.ReadInt32();
                                for(int i = 0; i < super_block_seg_count; i++)
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
                        }
                    }
                }
            }
            catch(Exception e)
            {
                Logging.warn(string.Format("Cannot create block from bytes: {0}", e.ToString()));
                throw;
            }
        }

        private void initPITTree()
        {
            // Number of levels is intended for 2K transactions in block. Increase when num of transactions increases.
            transactionPIT = new PrefixInclusionTree(44, 3);
        }

        /// <summary>
        ///  Retrieves the block in its serialized, 'byte stream' format. See also `Block(byte[] bytes)`.
        /// </summary>
        /// <remarks>
        ///  A block can be serialized for network transmission using this function. All relevant fields will be encoded and a byte buffer will
        ///  be returned. The byte buffer contains a copy of the block, so no thread synchronization is required.
        /// </remarks>
        /// <param name="include_sb_segments">Includes superblock segments if true.</param>
        /// <param name="frozen_sigs_only">Returns only frozen signatures if true. If false it returns all signatures, if they are still available, otherwise falls back to frozen signatures.</param>
        /// <returns>Byte buffer with the serialized block.</returns>
        public byte[] getBytes(bool include_sb_segments = true, bool frozen_sigs_only = true)
        {
            if(compacted)
            {
                Logging.error("Trying to use getBytes() from a compacted Block {0}", blockNum);
                return null;
            }
            using (MemoryStream m = new MemoryStream(5120))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(version);

                    writer.Write(blockNum);

                    // Write the number of transactions
                    int num_transactions = transactions.Count;
                    writer.Write(num_transactions);

                    // Write each wallet
                    foreach (string txid in transactions)
                    {
                        writer.Write(txid);
                    }

                    lock (signatures)
                    {
                        List<byte[][]> tmp_signatures = signatures;
                        if(frozen_sigs_only && frozenSignatures != null)
                        {
                            tmp_signatures = frozenSignatures;
                        }

                        // Write the number of signatures
                        int num_signatures = tmp_signatures.Count;

                        if(num_signatures > ConsensusConfig.maximumBlockSigners * 2)
                        {
                            num_signatures = ConsensusConfig.maximumBlockSigners * 2;
                        }

                        writer.Write(num_signatures);

                        // Write each signature
                        for (int i = 0; i < num_signatures; i++)
                        {
                            byte[][] signature = tmp_signatures[i];

                            if (signature[0] != null)
                            {
                                writer.Write(signature[0].Length);
                                writer.Write(signature[0]);
                            }else
                            {
                                writer.Write((int)0);
                            }
                            writer.Write(signature[1].Length);
                            writer.Write(signature[1]);
                        }
                    }

                    writer.Write(blockChecksum.Length);
                    writer.Write(blockChecksum);

                    if (lastBlockChecksum != null)
                    {
                        writer.Write(lastBlockChecksum.Length);
                        writer.Write(lastBlockChecksum);
                    }else
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
                    writer.Write(timestamp);

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

                    if (include_sb_segments)
                    {
                        writer.Write(superBlockSegments.Count);
                        foreach (var entry in superBlockSegments)
                        {
                            writer.Write(entry.Key);
                            writer.Write(entry.Value.blockChecksum.Length);
                            writer.Write(entry.Value.blockChecksum);
                        }
                    }else
                    {
                        writer.Write((int)0);
                    }
#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("Block::getBytes: {0}", m.Length));
#endif
                }

                return m.ToArray();
            }
        }

        /// <summary>
        ///  Implementation of block equality.
        /// </summary>
        /// <remarks>
        ///  Due to how a distributed ledger works as a technology, the comparison must only examine certain checksums of both blocks
        ///  to verify whether they are equal or not.
        /// </remarks>
        /// <param name="b">Other block, sometimes called the RHS (Right-hand-side)</param>
        /// <returns>True if the blocks are equal.</returns>
        public bool Equals(Block b)
        {
            if (!b.blockChecksum.SequenceEqual(blockChecksum))
            {
                return false;
            }

            if (b.signatureFreezeChecksum != null && signatureFreezeChecksum != null)
            {
                if (!b.signatureFreezeChecksum.SequenceEqual(signatureFreezeChecksum))
                {
                    return false;
                }
            }else if(b.signatureFreezeChecksum != null || signatureFreezeChecksum != null)
            {
                return false;
            }

            if (!b.calculateSignatureChecksum().SequenceEqual(calculateSignatureChecksum()))
            {
                return false;
            }
            return true;
        }

        /// <summary>
        ///  Adds an Ixian `Transaction` to the block. The transaction must already be present in the TransactionPool.
        /// </summary>
        /// <remarks>
        ///  Note that the transaction is not executed against the `WalletState` when it's added to the block with this function.
        ///  It is the responsibiltiy of the Master Node implementation to ensure that all transactions, which are added to a specific block,
        ///  are also applied against the WalletState, so that the walletStateSchecksum represents the finishing state.
        /// </remarks>
        /// <param name="txid">ID of the transaction to add.</param>
        /// <returns>True, if the transaction was added successfully.</returns>
        public bool addTransaction(string txid)
        {
            if (compacted)
            {
                Logging.error("Trying to add transaction on a compacted block {0}", blockNum);
                return false;
            }
            // TODO: this assumes the transaction is properly validated as it's already in the Transaction Pool
            // Could add an additional layer of checks here, just as in the TransactionPool - to avoid tampering
            if (!transactions.Contains(txid))
            {
                transactions.Add(txid);
                transactionPIT.add(txid);
            }else
            {
                Logging.warn(String.Format("Tried to add a duplicate transaction {0} to block {1}.", txid, blockNum));
            }

            return true;
        }

        /// <summary>
        ///  Calculates the `blockChecksum` of the DLT Block, using the relevant fields.
        /// </summary>
        /// <returns>Byte value of the checksum result.</returns>
        public byte[] calculateChecksum()
        {
            if (compacted)
            {
                Logging.error("Trying to calculate checksum on a compacted block {0}", blockNum);
                return null;
            }

            return new BlockHeader(this).calculateChecksum();
        }

        /// <summary>
        ///  Calculates the checksum of all signatures on this block.
        /// </summary>
        /// <remarks>
        ///  This is used for the signature freeze functionality of the Ixian DLT. See remarks  on the `signatureFreezeChecksum` field for details.
        /// </remarks>
        /// <returns>Byte value of the signature checksum.</returns>
        public byte[] calculateSignatureChecksum()
        {
            if (compacted)
            {
                Logging.error("Trying to calculate signature checksum on a compacted block {0}", blockNum);
                return null;
            }

            // Sort the signature first
            List<byte[][]> sortedSigs = null;
            lock (signatures)
            {
                if(frozenSignatures != null)
                {
                    sortedSigs = new List<byte[][]>(frozenSignatures);
                }
                else
                {
                    sortedSigs = new List<byte[][]>(signatures);
                }
            }
            sortedSigs.Sort((x, y) => _ByteArrayComparer.Compare(x[1], y[1]));

            // Merge the sorted signatures
            List<byte> merged_sigs = new List<byte>();
            merged_sigs.AddRange(BitConverter.GetBytes(blockNum));
            foreach (byte[][] sig in sortedSigs)
            {
                if(version > BlockVer.v3)
                {
                    merged_sigs.AddRange(sig[1]);
                }
                else
                {
                    merged_sigs.AddRange(sig[0]);
                }
            }

            // Generate a checksum from the merged sorted signatures
            byte[] checksum = null;
            if (version <= BlockVer.v2)
            {
                checksum = Crypto.sha512quTrunc(merged_sigs.ToArray());
            }else
            {
                checksum = Crypto.sha512sqTrunc(merged_sigs.ToArray());
            }
            return checksum;
        }

        /// <summary>
        ///  Signs the Block with the running DLT Master Node's private key.
        /// </summary>
        /// <remarks>
        ///  Signing the block indicates that the node has executed all transactions, specified in this block and has confirmed that the resulting
        ///  state of all wallets (`WalletState`) matches the one in the `walletStateChecksum` field. The starting point for the transactions is
        ///  the Wallet State from the previous block.
        ///  The resulting signature may include either the node's public key, or its signing address, depending if the public key can be obtained through other means.
        ///  An example of this is when this node's public key is present in the Presence List.
        /// </remarks>
        /// <returns>Byte array with the node's signature and public key or address.</returns>
        public byte[][] applySignature()
        {
            if (compacted)
            {
                Logging.error("Trying to apply signature on a compacted block {0}", blockNum);
                return null;
            }

            // Note: we don't need any further validation, since this block has already passed through BlockProcessor.verifyBlock() at this point.
            byte[] myAddress = IxianHandler.getWalletStorage().getPrimaryAddress();
            if (containsSignature(new Address(myAddress, null, false)))
            {
                return null;
            }

            byte[] myPubKey = IxianHandler.getWalletStorage().getPrimaryPublicKey();

            // TODO: optimize this in case our signature is already in the block, without locking signatures for too long
            byte[] private_key = IxianHandler.getWalletStorage().getPrimaryPrivateKey();
            byte[] signature = CryptoManager.lib.getSignature(blockChecksum, private_key);

            Wallet w = IxianHandler.getWallet(myAddress);

            byte[][] newSig = new byte[2][];
            newSig[0] = signature;
            if (w.publicKey == null)
            {
                newSig[1] = myPubKey;
            }
            else
            {
                newSig[1] = myAddress;
            }

            lock (signatures)
            {
                signatures.Add(newSig);               
            }

            Logging.info(String.Format("Signed block #{0}.", blockNum));

            return newSig;
        }

        /// <summary>
        ///  Checks if the block's signatures field contains the signature of the specified node. Either the node's address or its public key is accepted.
        /// </summary>
        /// <param name="p_address">The signer's address.</param>
        /// <returns></returns>
        public bool containsSignature(Address p_address)
        {
            if (compacted)
            {
                Logging.error("Trying to check if compacted block {0} contains signature", blockNum);
                return false;
            }

            byte[] cmp_address = p_address.address;

            lock (signatures)
            {
                foreach (byte[][] sig in signatures)
                {
                    // Generate an address in case we got the pub key
                    Address s_address_or_pub_key = new Address(sig[1], null, false);
                    byte[] sig_address = s_address_or_pub_key.address;

                    if (cmp_address.SequenceEqual(sig_address))
                    {
                        return true;
                    }
                }
                return false;
            }
        }

        /// <summary>
        ///  Mergest the signatures of two blocks without duplicating.
        /// </summary>
        /// <remarks>
        ///  This is used when the Master Node has been working on one set of signatures but receives the same block with a different set of signatures and wishes
        ///  to merge the two lists together.
        ///  The function returns the list signatures which were in the `other` block, but not in this, while at the same time adding the new signatures to this block.
        /// </remarks>
        /// <param name="other">The other block (should be the same `blockNum`) whose signatures will be merged.</param>
        /// <returns>The list of 'new' signatures.</returns>
        public List<byte[][]> addSignaturesFrom(Block other)
        {
            if (compacted)
            {
                Logging.error("Trying to add signature from block on a compacted block {0}", blockNum);
                return null;
            }
            // Note: we don't need any further validation, since this block has already passed through BlockProcessor.verifyBlock() at this point.
            lock (signatures)
            {
                int count = 0;
                List<byte[][]> added_signatures = new List<byte[][]>();
                foreach (byte[][] sig in other.signatures)
                {
                    if (!containsSignature(new Address(sig[1])))
                    {
                        count++;
                        signatures.Add(sig);
                        added_signatures.Add(sig);
                    }
                }
                if (count > 0)
                {
                    //Logging.info(String.Format("Merged {0} new signatures from incoming block.", count));
                    return added_signatures;
                }
            }
            return null;
        }

        /// <summary>
        ///  Verifies if the given signature is valid for this block.
        /// </summary>
        /// <remarks>
        ///  Please note that this function only accepts a public key. If the signature is supplied with an address, the public key must somehow be obtained
        ///  prior to calling this function, either by taking it from the Presence List, or querying the network.
        /// </remarks>
        /// <param name="signature">Signature's byte value.</param>
        /// <param name="signer_pub_key">Public key of the signer.</param>
        /// <returns>True, if the signature validates this block.</returns>
        public bool verifySignature(byte[] signature, byte[] signer_pub_key)
        {
            return CryptoManager.lib.verifySignature(blockChecksum, signer_pub_key, signature);
        }

        /// <summary>
        ///  Adds the provided signature to the block's signature list.
        /// </summary>
        /// <param name="signature">Byte value of the signature.</param>
        /// <param name="address_or_pub_key">Address or public key of the signer.</param>
        /// <returns>True, if the signature was successfully added. False is returned if the signature was already present, or was not valid.</returns>
        public bool addSignature(byte[] signature, byte[] address_or_pub_key)
        {
            if(compacted)
            {
                Logging.error("Trying to add signature on a compacted block {0}", blockNum);
                return false;
            }
            lock (signatures)
            {
                if (!containsSignature(new Address(address_or_pub_key)))
                {
                    byte[] pub_key = getSignerPubKey(address_or_pub_key);
                    if (pub_key != null && verifySignature(signature, pub_key))
                    {
                        signatures.Add(new byte[2][] { signature, address_or_pub_key});
                        return true;
                    }
                }
            }
            return false;
        }

        /// <summary>
        ///  Attempts to retrieve the public key of the signer address.
        /// </summary>
        /// <remarks>
        ///  This function accepts either a wallet address or a public key. In the latter case, the public key is returned directly, but in the former case,
        ///  the public key is looked up from the wallet. This allows easy conversion from the signatures field for use in the verify function.
        /// </remarks>
        /// <param name="address_or_pub_key">Signer address or public key.</param>
        /// <returns>Public key, matching the given address, or null, if the public key is not known.</returns>
        public byte[] getSignerPubKey(byte[] address_or_pub_key)
        {
            if (compacted)
            {
                Logging.error("Trying to set signer pubkey on a compacted block {0}", blockNum);
                return null;
            }

            if (address_or_pub_key == null)
            {
                return null;
            }
            if (address_or_pub_key.Length > 128 && address_or_pub_key.Length < 2500)
            {
                return address_or_pub_key;
            }
            if (address_or_pub_key.Length >= 36 && address_or_pub_key.Length <= 128)
            {
                // Extract the public key from the walletstate
                Wallet signer_wallet = IxianHandler.getWallet(address_or_pub_key);
                if(signer_wallet.publicKey != null && signer_wallet.publicKey.Length < 50)
                {
                    Logging.error("Wallet {0} has an invalid value stored for public key ({1} bytes)!", Base58Check.Base58CheckEncoding.EncodePlain(address_or_pub_key), signer_wallet.publicKey == null ? 0 : signer_wallet.publicKey.Length);
                    return null;
                }
               return signer_wallet.publicKey;
            }
            return null;
        }

        /// <summary>
        ///  Verifies that all signatures on this block are valid.
        /// </summary>
        /// <remarks>
        ///  Checks if all the given signatures and signer addresses match and are valid. In the simpler form (`skip_sig_verification`), this function
        ///  only checks that public keys for all signatures exist and that all signers are known, without cryptographically verifying that each signature
        ///  matches the block.
        /// </remarks>
        /// <param name="skip_sig_verification">False for simpler, non-cryptographic verification.</param>
        /// <returns>True if all signatures are valid and (optionally) match the block's checksum.</returns>
        public bool verifySignatures(bool skip_sig_verification = false)
        {
            if (compacted)
            {
                Logging.error("Trying to verify signatures on a compacted block {0}", blockNum);
                return false;
            }

            lock (signatures)
            {
                if (signatures.Count == 0)
                {
                    return false;
                }
            }
            List<byte[]> sig_addresses = new List<byte[]>();
            List<byte[][]> safe_sigs = null;

            lock (signatures)
            {
                safe_sigs = new List<byte[][]>(signatures);
            }

            foreach (byte[][] sig in safe_sigs)
            {

                byte[] signature = sig[0];
                byte[] address = sig[1];

                byte[] signer_pub_key = getSignerPubKey(sig[1]);

                if (signer_pub_key == null)
                {
                    // invalid public key
                    lock (signatures)
                    {
                        signatures.Remove(sig);
                    }
                    continue;
                }

                if (sig_addresses.Find(x => x.SequenceEqual(signer_pub_key)) == null)
                {
                    sig_addresses.Add(signer_pub_key);
                }else
                {
                    lock (signatures)
                    {
                        signatures.Remove(sig);
                    }
                    continue;
                }

                if (skip_sig_verification == false && verifySignature(signature, signer_pub_key) == false)
                {
                    lock (signatures)
                    {
                        signatures.Remove(sig);
                    }
                    continue;
                }
            }

            lock(signatures)
            { 
                if(signatures.Count == 0)
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        ///  Checks the signatures on the block and returns true, if the block has already been signed by the given public key.
        /// </summary>
        /// <param name="public_key">The public key to check.</param>
        /// <returns>True, if the public key has already signed the block.</returns>
        public bool hasNodeSignature(byte[] public_key = null)
        {
            if (compacted)
            {
                Logging.error("Trying to execute hasNodeSignature on a compacted block {0}", blockNum);
                return false;
            }

            byte[] node_address = IxianHandler.getWalletStorage().getPrimaryAddress();
            if (public_key == null)
            {
                public_key = IxianHandler.getWalletStorage().getPrimaryPublicKey();
            }
            else
            {
                // Generate an address
                Address p_address = new Address(public_key, null, false);
                node_address = p_address.address;
            }

            lock (signatures)
            {
                foreach (byte[][] merged_signature in signatures)
                {
                    bool condition = false;

                    // Check if we have an address instead of a public key
                    if (merged_signature[1].Length < 70)
                    {
                        // Compare wallet address
                        condition = node_address.SequenceEqual(merged_signature[1]);
                    }
                    else
                    {
                        // Legacy, compare public key
                        condition = public_key.SequenceEqual(merged_signature[1]);
                    }

                    // Check if it matches
                    if (condition)
                    {
                        // Check if signature is actually valid
                        if (CryptoManager.lib.verifySignature(blockChecksum, public_key, merged_signature[0]))
                        {
                            return true;
                        }
                        else
                        {
                            // Somebody tampered this block. Show a warning and do not broadcast it further
                            // TODO: Possibly denounce the tampered block's origin node
                            Logging.warn(string.Format("Possible tampering on received block: {0}", blockNum));
                            return false;
                        }
                    }
                }
            }
            return false;
        }

        /// <summary>
        ///  Retrieves a list of Ixian Wallet addresses from the list of signatures on this block.
        /// </summary>
        /// <remarks>
        ///  Since signatures on the block may include either an address or a public key, this function performs the necessary lookups
        ///  to return only the Wallet addresses of all signers. If the parameter `convert_pubkeys` is specified false, then the public
        ///  key lookups aren't performed and only the addresses from the signature list are returned.
        /// </remarks>
        /// <param name="convert_pubkeys">True if public key signatures should be converted back to their respective Ixian Wallet addresses.</param>
        /// <returns>List of Ixian wallets which have signed this block.</returns>
        public List<byte[]> getSignaturesWalletAddresses(bool convert_pubkeys = true)
        {
            if (compacted)
            {
                Logging.error("Trying to get signer wallet addresses from a compacted block {0}", blockNum);
                return null;
            }

            List<byte[]> result = new List<byte[]>();

            lock (signatures)
            {
                List<byte[][]> tmp_sigs = null;
                if(frozenSignatures != null)
                {
                    tmp_sigs = frozenSignatures;
                }else
                {
                    tmp_sigs = signatures;
                }

                foreach (byte[][] merged_signature in tmp_sigs)
                {
                    byte[] signature = merged_signature[0];
                    byte[] keyOrAddress = merged_signature[1];
                    byte[] addressBytes = null;
                    byte[] pubKeyBytes = null;

                    // Check if we have an address instead of a public key
                    if (keyOrAddress.Length < 70)
                    {
                        addressBytes = keyOrAddress;
                        // Extract the public key from the walletstate
                        Wallet signerWallet = IxianHandler.getWallet(addressBytes);
                        if (signerWallet != null && signerWallet.publicKey != null)
                        {
                            pubKeyBytes = signerWallet.publicKey;
                        }else
                        {
                            // Failed to find signer publickey in walletstate
                            continue;
                        }
                    }else
                    {
                        pubKeyBytes = keyOrAddress;
                        if (convert_pubkeys)
                        {
                            Address address = new Address(pubKeyBytes, null, false);
                            addressBytes = address.address;
                        }else
                        {
                            addressBytes = pubKeyBytes;
                        }
                    }

                    // no need to verify if the sigs are ok, this has been pre-verified before the block was accepted

                    // Add the address to the list
                    result.Add(addressBytes);
                }
                result.Sort((x, y) => _ByteArrayComparer.Compare(x, y));
            }
            return result;
        }

        /// <summary>
        ///  Retrives the number of signatures on this block. This function might return a larger value, because it does not check for potential duplicates.
        /// </summary>
        /// <returns>Number of signatures.</returns>
        public int getSignatureCount()
        {
            if (compacted)
            {
                return signatureCount;
            }
            else
            {
                return signatures.Count;
            }
        }

        /// <summary>
        ///  Retrives the number of signatures on this block.
        /// </summary>
        /// <returns>Number of signatures.</returns>
        public int getFrozenSignatureCount()
        {
            if(frozenSignatures != null)
            {
                return frozenSignatures.Count;
            }else
            {
                return getSignatureCount();
            }
        }

        /// <summary>
        ///  Allocates and sets the `walletStateChecksum`.
        /// </summary>
        /// <param name="checksum">Checksum byte value.</param>
        public void setWalletStateChecksum(byte[] checksum)
        {
            walletStateChecksum = new byte[checksum.Length];
            Array.Copy(checksum, walletStateChecksum, walletStateChecksum.Length);
        }

        /// <summary>
        ///  ?
        /// </summary>
        /// <returns></returns>
        public bool pruneSignatures()
        {
            return false; // disabled for now

            if (version < BlockVer.v4)
            {
                return false;
            }

            if (compactedSigs)
            {
                return false;
            }

            compactedSigs = true;

            int compacted_cnt = 0;
            List<byte[][]> new_sigs = new List<byte[][]>();
            foreach(var entry in signatures)
            {
                if (entry[0] != null)
                {
                    compacted_cnt++;
                    entry[0] = null;
                }
                new_sigs.Add(entry);
            }

            if (compacted_cnt > 0)
            {
                signatures = new_sigs;
                return true;
            }

            return false;
        }

        /// <summary>
        ///  Removes the signatures as part of the compaction process (superblock functionality).
        /// </summary>
        /// <returns>True if compaction was performed, false if the block is already compacted.</returns>
        public bool compact()
        {
            if(compacted)
            {
                return false;
            }

            compacted = true;

            signatureCount = getFrozenSignatureCount();
            frozenSignatures = null;
            signatures = null;

            superBlockSegments = null;
            transactions = null;

            return true;

        }

        /// <summary>
        ///  Writes the block's details to the log for debugging purposes.
        /// </summary>
        public void logBlockDetails()
        {
            string last_block_chksum = "";
            if (lastBlockChecksum != null)
            {
               last_block_chksum = Crypto.hashToString(lastBlockChecksum);
            }
            if(last_block_chksum.Length == 0)
            {
                last_block_chksum = "G E N E S I S  B L O C K";
            }
            Logging.info(String.Format("\t\t|- Block Number:\t\t {0}", blockNum));
            Logging.info(String.Format("\t\t|- Block Version:\t\t {0}", version));
            Logging.info(String.Format("\t\t|- Signatures:\t\t\t {0}", signatures.Count));
            Logging.info(String.Format("\t\t|- Block Checksum:\t\t {0}", Crypto.hashToString(blockChecksum)));
            Logging.info(String.Format("\t\t|- Last Block Checksum: \t {0}", last_block_chksum));
            Logging.info(String.Format("\t\t|- WalletState Checksum:\t {0}", Crypto.hashToString(walletStateChecksum)));
            Logging.info(String.Format("\t\t|- Sig Freeze Checksum: \t {0}", Crypto.hashToString(signatureFreezeChecksum)));
            Logging.info(String.Format("\t\t|- Difficulty:\t\t\t {0}", difficulty));
            Logging.info(String.Format("\t\t|- Transaction Count:\t\t {0}", transactions.Count));
        }

        /// <summary>
        ///  Test if the block is the genesis block.
        /// </summary>
        public bool isGenesis { get { return this.blockNum == 0 && this.lastBlockChecksum == null; } }

        public void setFrozenSignatures(List<byte[][]> frozen_sigs)
        {
            if (compacted)
            {
                Logging.error("Trying to set frozen signatures on a compacted block {0}", blockNum);
                return;
            }

            lock (signatures)
            {
                frozenSignatures = frozen_sigs;
            }
        }

    }    
}