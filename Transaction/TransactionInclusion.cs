using IXICore.Meta;
using IXICore.Network;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace IXICore
{
    class TransactionInclusion
    {
        private Thread tiv_thread = null;
        private bool running = false;

        private readonly int candidateThreshold = 3;    // Minimum number of same exact block candidates

        Dictionary<string, Transaction> txQueue = new Dictionary<string, Transaction>(); // List of all transactions that should be verified

        BlockHeader lastBlockHeader = null;

        long lastRequestedBlockTime = 0;

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
            long currentTime = Core.getCurrentTimestamp();

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
                    if (bh.version < 6)
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
                        // TODO request PIT; also optimize for multiple tx requests in the same block
                    }
                }
            }
        }

            private bool processBlockHeader(BlockHeader header)
        {
            if(lastBlockHeader != null && !header.lastBlockChecksum.SequenceEqual(lastBlockHeader.blockChecksum))
            {
                Logging.warn("TIV: Invalid last block checksum");

                // discard the block

                // require previous block to get verifications from 3 nodes

                // if in verification mode, detect liar and flag him

                return false;
            }

            if(!header.calculateChecksum().SequenceEqual(header.blockChecksum))
            {
                Logging.warn("TIV: Invalid block checksum");
                return false;
            }

            lastBlockHeader = header;

            if(!BlockHeaderStorage.saveBlockHeader(lastBlockHeader))
            {
                return false;
            }

            return true;
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

    }
}
