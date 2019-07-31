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

        private ulong minimumCacheBlockHeight = 0;

        //List<BlockHeader> cachedHeaders = new List<BlockHeader>((int)ConsensusConfig.getRedactedWindowSize());
        Dictionary<ulong, BlockHeader> cachedHeaders = new Dictionary<ulong, BlockHeader>(); // Storage for quick lookups
        //Dictionary<ulong,BlockHeader> cachedHeadersCandidates = new Dictionary<ulong,BlockHeader>();

        ulong verifiedDownTo = UInt64.MaxValue;

        List<string> requestsQueue = new List<string>(); // List of all transactions that should be verified

        public TransactionInclusion()
        {
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
                int requestCount = 0;
                lock(requestsQueue)
                {
                    requestCount = requestsQueue.Count();
                }

                if(requestCount < 1)
                {
                    Thread.Sleep(2500);
                    continue;
                }


                lock (requestsQueue)
                {
                    for (int i = 0; i < requestCount; i++)
                    {
                        string txid = requestsQueue[i];
                        ulong bheight = blockHeightFromTxid(txid);
                        if(traverseCache(bheight, txid) == false)
                        {
                            Thread.Sleep(1000);
                            break;
                        }

                        // Remove from queue
                        requestsQueue.RemoveAt(i);
                        //verifiedDownTo = UInt64.MaxValue;
                        break;
                    }
                }

                Thread.Yield();
            }
        }

        public void stop()
        {
            running = false;
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

        public void verifyTransactionInclusion(Transaction tx)
        {
            verifyTransactionInclusion(tx.id, tx.blockHeight);
        }

        public void verifyTransactionInclusion(string txid)
        {
            verifyTransactionInclusion(txid, blockHeightFromTxid(txid));
        }

        /// <summary>
        ///  Posts a verify transaction inclusion request
        /// </summary>
        /// <param name="txid">transaction id string</param>
        /// <param name="blockheight">corresponding blockheight of transaction</param>
        public void verifyTransactionInclusion(string txid, ulong blockheight)
        {
            if (requestsQueue.Count() > 0)
            {
                if (requestsQueue.Contains(txid))
                {
                    // Already in the requests queue
                    return;
                }
            }

            lock (requestsQueue)
            {
                requestsQueue.Add(txid);
            }

            if (blockheight < minimumCacheBlockHeight)
                minimumCacheBlockHeight = blockheight;
        }

        public void processBlockHeader(BlockHeader header)
        {
            // Check if the candidate block is already cached
            if(cachedHeaders.ContainsKey(header.blockNum))
            {
                // TODO: verify the top-most block from 3 different sources and make sure the checksums match
         /*       cachedHeadersCandidates[header]++;

                // Check if candidate threshold is reached
                if(cachedHeadersCandidates[header] > candidateThreshold)
                {
                    // Add to cache
                    int index = 0;
                    cachedHeaders.Insert(index, header);
                }*/

                return;
            }

            // Check the newer block's previous block checksum
            Console.WriteLine("Adding {0} to cache", header.blockNum);
            // Add to candidates
            cachedHeaders.Add(header.blockNum, header);
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
                    ulong headers_num = reader.ReadUInt64();

                    for (ulong i = 0; i < headers_num; i++)
                    {
                        int header_len = reader.ReadInt32();
                        byte[] header_bytes = reader.ReadBytes(header_len);

                        // Create the blockheader from the data and process it
                        BlockHeader header = new BlockHeader(header_bytes);
                        processBlockHeader(header);
                    }
                }
            }
        }

        /// <summary>
        ///  Traverses the entire blockheaders cache and searches for block containing the txid
        /// </summary>
        /// <param name="targetheight">minimum block height the cache must have</param>
        /// <param name="txid">transaction id</param>
        private bool traverseCache(ulong targetheight, string txid)
        {
            ulong last_block = IxianHandler.getLastBlockHeight();
            if(last_block == 0)
            {
                return false;
            }

            if (cachedHeaders.ContainsKey(last_block-1) == false)
            {
                Console.WriteLine("Requesting latest blocks");
                requestBlockHeaders(last_block - 5, last_block);
                return false;
            }

            for(ulong i = last_block; i >= targetheight; i--)
            {
                if(cachedHeaders.ContainsKey(i-1) == false)
                {
                    // Request more block headers
                    requestBlockHeaders(i - 100, i);
                    return false;
                }

                if (i == last_block)
                    continue;

                // Verify block checksum
                BlockHeader bheader = cachedHeaders[i];

                if(i < last_block - 2 && verifiedDownTo > i)
                {
                    BlockHeader pheader = cachedHeaders[i - 1];
                    if(bheader.lastBlockChecksum.SequenceEqual(pheader.blockChecksum) == false)
                    {
                        // Request near blocks again
                        requestBlockHeaders(i - 4, i + 1);
                        return false;
                    }
                }

                if (i < verifiedDownTo)
                    verifiedDownTo = i;

                if (containsTransaction(bheader, txid))
                {
                    // TODO verification of this block's checksum could be done here for extra safety
                    IxianHandler.receivedTransactionInclusionVerificationResponse(txid, true);
                    return true;
                }
            }

            if(cachedHeaders.ContainsKey(targetheight) == false)
            {
                // Should never reach this point
                requestBlockHeaders(targetheight - 10, targetheight);
                return false;
            }


            IxianHandler.receivedTransactionInclusionVerificationResponse(txid, false);           
            return true;
        }

       
        private bool containsTransaction(BlockHeader header, string txid)
        {
            if (header.transactions.Contains(txid) == false)
            {
                return false;
            }
            return true;
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
                CoreProtocolMessage.broadcastProtocolMessageToSingleRandomNode(new char[] { 'M'}, ProtocolMessageCode.getBlockHeaders, mOut.ToArray(), IxianHandler.getLastBlockHeight());
            }
        }

    }
}
