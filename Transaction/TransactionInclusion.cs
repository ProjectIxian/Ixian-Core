using IXICore.Meta;
using IXICore.Network;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace IXICore
{
    /// <summary>
    /// Caches information about received PIT data for each block we're interested in.
    /// Note: Because we may request a PIT for a subset of that block's transactions, we must also store
    /// all the transactions for which the PIT was requested.
    /// </summary>
    class PITCacheItem
    {
        public List<string> requestedForTXIDs;
        public long requestSent;
        public PrefixInclusionTree pit;
    }
    class TransactionInclusion
    {
        private Thread tiv_thread = null;
        private bool running = false;

        private readonly int candidateThreshold = 3;    // Minimum number of same exact block candidates

        Dictionary<string, Transaction> txQueue = new Dictionary<string, Transaction>(); // List of all transactions that should be verified
        SortedList<ulong, PITCacheItem> pitCache = new SortedList<ulong, PITCacheItem>();
        long pitRequestTimeout = 5; // timeout (seconds) before PIT for a specific block is re-requested
        long pitCachePruneInterval = 30; // interval how often pit cache is checked and uninteresting entries removed (to save memory)

        BlockHeader lastBlockHeader = null;

        long lastRequestedBlockTime = 0;
        long lastPITPruneTime = 0;

        public TransactionInclusion(BlockHeader last_block_header)
        {
            lastBlockHeader = last_block_header;
            running = true;
            // Start the thread
            tiv_thread = new Thread(onUpdate);
            tiv_thread.Name = "TIV_Update_Thread";
            tiv_thread.Start();
        }

        public void onUpdate()
        {
            while (running)
            {
                if(updateBlockHeaders())
                {
                    verifyUnprocessedTransactions();
                    long currentTime = Clock.getTimestamp();
                    if(currentTime - lastPITPruneTime > pitCachePruneInterval)
                    {
                        prunePITCache();
                    }
                    Thread.Sleep(ConsensusConfig.blockGenerationInterval);
                }else
                {
                    Thread.Sleep(10);
                }
            }
        }

        public void stop()
        {
            running = false;
        }

        private bool updateBlockHeaders()
        {
            long currentTime = Clock.getTimestamp();

            // Check if the request expired
            if (currentTime - lastRequestedBlockTime > ConsensusConfig.blockGenerationInterval)
            {
                ulong lastRequestedBlockHeight = 1;
                if (lastBlockHeader != null)
                {
                    lastRequestedBlockHeight = lastBlockHeader.blockNum + 1;
                }
                lastRequestedBlockTime = currentTime;

                // request next blocks
                requestBlockHeaders(lastRequestedBlockHeight, lastRequestedBlockHeight + 100);

                return true;
            }

            return false;
        }

        private ulong blockHeightFromTxid(string txid)
        {
            ulong txbnum = 0;
            // Extract the blocknum from the txid
            try
            {
                string[] split_str = txid.Split(new string[] { "-" }, StringSplitOptions.None);
                txbnum = Convert.ToUInt64(split_str[0]);
            }
            catch (Exception e)
            {
                Console.WriteLine("TIV exception: {0}", e.Message);
                return 0;
            }
            return txbnum;
        }

        /// <summary>
        ///  Posts a verify transaction inclusion request
        /// </summary>
        /// <param name="txid">transaction id string</param>
        public bool receivedNewTransaction(Transaction t)
        {
            // TODO verify transaction checksum/validity

            lock (txQueue)
            {
                if (txQueue.Count() > 0)
                {
                    if (txQueue.ContainsKey(t.id))
                    {
                        // Already in the requests queue
                        if (txQueue[t.id].applied == 0)
                        {
                            txQueue[t.id] = t;
                        }
                        return false;
                    }
                }

                txQueue.Add(t.id, t);
                return true;
            }
        }

        private void verifyUnprocessedTransactions()
        {
            lock (txQueue)
            {
                var tmp_txQueue = txQueue.Values.Where(x => x.applied != 0 && x.applied <= lastBlockHeader.blockNum).ToArray();
                foreach(var tx in tmp_txQueue)
                {
                    BlockHeader bh = BlockHeaderStorage.getBlockHeader(tx.applied);
                    if(bh is null)
                    {
                        // TODO: need to wait for the block to arrive, or re-request
                        // maybe something similar to PIT cache, or extend PIT cache to handle older blocks, too
                        continue;
                    }
                    if (bh.version < BlockVer.v6)
                    {
                        txQueue.Remove(tx.id);

                        if(bh.transactions.Contains(tx.id))
                        {
                            // valid
                            IxianHandler.receivedTransactionInclusionVerificationResponse(tx.id, true);
                        }else
                        {
                            // invalid
                            IxianHandler.receivedTransactionInclusionVerificationResponse(tx.id, false);
                        }

                    }
                    else
                    {
                        lock (pitCache)
                        {
                            // check if we already have the partial tree for this transaction
                            if (pitCache.ContainsKey(tx.applied) && pitCache[tx.applied].pit != null)
                            {
                                // Note: PIT has been verified against the block header when it was received, so additional verification is not needed here.
                                // Note: the PIT we have cached might have been requested for different txids (the current txid could have been added later)
                                // For that reason, the list of TXIDs we requested is stored together with the cached PIT
                                if (pitCache[tx.applied].requestedForTXIDs.Contains(tx.id))
                                {
                                    if (pitCache[tx.applied].pit.contains(tx.id))
                                    {
                                        // valid
                                        IxianHandler.receivedTransactionInclusionVerificationResponse(tx.id, true);
                                    }
                                    else
                                    {
                                        // invalid
                                        IxianHandler.receivedTransactionInclusionVerificationResponse(tx.id, false);
                                    }
                                }
                                else
                                {
                                    // PIT cache for the correct block exists, but it was originally requested for different txids
                                    // we have to re-request it for any remaining txids in the queue. (We do not need to request the already-verified ids)
                                    requestPITForBlock(tx.applied,
                                        txQueue.Values
                                            .Where(x => x.applied == tx.applied && x.applied <= lastBlockHeader.blockNum)
                                            .Select(x => x.id)
                                            .ToList());
                                    continue;
                                }
                            }
                            else
                            {
                                // PIT cache has not been received yet, or maybe it has never been requested for this block
                                requestPITForBlock(tx.applied,
                                    txQueue.Values
                                        .Where(x => x.applied == tx.applied && x.applied <= lastBlockHeader.blockNum)
                                        .Select(x => x.id)
                                        .ToList());
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Requests PIT for the specified block from a random connected neighbor node.
        /// Nominally, only the transactions included in `txids` need to be verifiable with the PIT, but
        /// due to how Cuckoo filtering works, some false positives will also be included. This helps with anonymization, if the false positive rate is high enough.
        /// </summary>
        /// <param name="block_num">Block number for which the PIT should be included.</param>
        /// <param name="txids">List of interesting transactions, which we wish to verify.</param>
        private void requestPITForBlock(ulong block_num, List<string> txids)
        {
            lock(pitCache)
            {
                long currentTime = Clock.getTimestamp();
                // Request might already have been sent. In that case, we re-send it we have been waiting for too long.
                if(!pitCache.ContainsKey(block_num) || currentTime - pitCache[block_num].requestSent > pitRequestTimeout)
                {
                    Cuckoo filter = new Cuckoo(txids.Count);
                    foreach (var tx in txids)
                    {
                        filter.Add(Encoding.UTF8.GetBytes(tx));
                    }
                    byte[] filter_bytes = filter.getFilterBytes();
                    MemoryStream m = new MemoryStream(filter_bytes.Length + 12);
                    using (BinaryWriter w = new BinaryWriter(m, Encoding.UTF8, true))
                    {
                        w.Write(block_num);
                        w.Write(filter_bytes.Length);
                        w.Write(filter_bytes);
                    }
                    CoreProtocolMessage.broadcastProtocolMessageToSingleRandomNode(new char[] { 'M' }, ProtocolMessageCode.getPIT, m.ToArray(), 0);
                    PITCacheItem ci = new PITCacheItem()
                    {
                        pit = null,
                        requestedForTXIDs = txids,
                        requestSent = Clock.getTimestamp()
                    };
                    pitCache.AddOrReplace(block_num, ci);
                }
            }
        }

        private bool processBlockHeader(BlockHeader header)
        {
            if (lastBlockHeader != null && !header.lastBlockChecksum.SequenceEqual(lastBlockHeader.blockChecksum))
            {
                Logging.warn("TIV: Invalid last block checksum");

                // discard the block

                // require previous block to get verifications from 3 nodes

                // if in verification mode, detect liar and flag him

                return false;
            }

            if (!header.calculateChecksum().SequenceEqual(header.blockChecksum))
            {
                Logging.warn("TIV: Invalid block checksum");
                return false;
            }

            lastBlockHeader = header;

            if (!BlockHeaderStorage.saveBlockHeader(lastBlockHeader))
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// When a response to a PIT request is received, this function validates and caches it so transactions may be verified in a separate thread.
        /// </summary>
        /// <param name="data">PIT response bytes.</param>
        /// <param name="endpoint">Neighbor, who sent this data.</param>
        public void receivedPIT(byte[] data, RemoteEndpoint endpoint)
        {
            MemoryStream m = new MemoryStream(data);
            using (BinaryReader r = new BinaryReader(m))
            {
                ulong block_num = r.ReadUInt64();
                int len = r.ReadInt32();
                if(len > 0)
                {
                    byte[] pit_data = r.ReadBytes(len);
                    PrefixInclusionTree pit = new PrefixInclusionTree();
                    try
                    {
                        pit.reconstructMinimumTree(pit_data);
                        BlockHeader h = BlockHeaderStorage.getBlockHeader(block_num);
                        if(h == null)
                        {
                            Logging.warn("TIV: Received PIT information for block {0}, but we do not have that block header in storage!", block_num);
                            return;
                        }
                        if(!h.pitHash.SequenceEqual(pit.calculateTreeHash()))
                        {
                            Logging.error("TIV: Received PIT information for block {0}, but the PIT checksum does not match the one in the block header!", block_num);
                            // TODO: more drastic action? Maybe blacklist or something.
                            return;
                        }
                        lock (pitCache) {
                            if (pitCache.ContainsKey(block_num))
                            {
                                Logging.info("TIV: Received valid PIT information for block {0}", block_num);
                                pitCache[block_num].pit = pit;
                            }
                         }
                    }
                    catch (Exception)
                    {
                        Logging.warn("TIV: Invalid or corrupt data received for block {0}.", block_num);
                    }
                }
            }
        }

        /// <summary>
        ///  Called when receiving multiple block headers at once from a remote endpoint
        /// </summary>
        /// <param name="data">byte array of received data</param>
        /// <param name="endpoint">corresponding remote endpoint</param>
        public void receivedBlockHeaders(byte[] data, RemoteEndpoint endpoint)
        {
            using (MemoryStream m = new MemoryStream(data))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    bool processed = false;

                    while(m.Position < m.Length)
                    {
                        int header_len = reader.ReadInt32();
                        byte[] header_bytes = reader.ReadBytes(header_len);

                        // Create the blockheader from the data and process it
                        BlockHeader header = new BlockHeader(header_bytes);
                        if(!processBlockHeader(header))
                        {
                            break;
                        }
                        processed = true;
                    }
                    if (processed)
                    {
                        lastRequestedBlockTime = 0;
                    }
                }
            }
        }
        
        private void requestBlockHeaders(ulong from, ulong to)
        {
            Console.WriteLine("Requesting block headers from {0} to {1}", from, to);
            using (MemoryStream mOut = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(mOut))
                {
                    writer.Write(from);
                    writer.Write(to);
                }

                // Request from all nodes
                //NetworkClientManager.broadcastData(new char[] { 'M', 'H' }, ProtocolMessageCode.getBlockHeaders, mOut.ToArray(), null);

                // Request from a single random node
                CoreProtocolMessage.broadcastProtocolMessageToSingleRandomNode(new char[] { 'M' }, ProtocolMessageCode.getBlockHeaders, mOut.ToArray(), 0);
            }
        }

        private void prunePITCache()
        {
            lock (txQueue)
            {

                lock (pitCache)
                {
                    List<ulong> to_remove = new List<ulong>();
                    foreach (var i in pitCache)
                    {
                        if (i.Value.requestedForTXIDs.Intersect(txQueue.Values.Select(tx => tx.id)).Any())
                        {
                            // PIT cache item is still needed
                        }
                        else
                        {
                            to_remove.Add(i.Key);
                        }
                    }
                    foreach(ulong b_num in to_remove)
                    {
                        pitCache.Remove(b_num);
                    }
                }
            }
        }
    }
}
