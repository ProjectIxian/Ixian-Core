using System;
using System.Linq;
using System.IO;
using System.Collections.Generic;
using System.Text;
using IXICore.Utils;

namespace IXICore
{
    public class PrefixInclusionTree
    {
        class PITNode
        {
            public byte level;
            public SortedList<byte, PITNode> childNodes; // only on non-leaf nodes
            public byte[] hash; // only on non-leaf nodes
            public SortedSet<byte[]> data; // only on leaf nodes

            public PITNode(int l)
            {
                level = (byte)l;
            }
        }

        enum PIT_MinimumTreeType
        {
            SingleTX = 1,
            Anonymized = 2,
        }

        private byte levels;
        private int hashLength;
        private PITNode root = new PITNode(0);
        private readonly object threadLock = new object();

        /// <summary>
        /// Creates an empty Prefix-Inclusion-Tree with the specified hash length and number of levels.
        ///  PIT will always have the number of levels given here and the hashing result over same data 
        ///  will change if the number of levels is different.
        /// </summary>
        /// <param name="hash_length">Length of the hashes used inside the Prefix Inclusion Tree. Higher number 
        ///  makes it more secure, but increases the size of the Tree as well as the length of generated Minimal Tree bytestreams.</param>
        /// <param name="numLevels">Number of levels for the Prefix Inclusion Tree. Higher number reduces the overall number of 
        ///  transaction IDs in each leaf node, but increases the size of the tree as well as the length of the generated Minimal Tree byestreams.</param>
        public PrefixInclusionTree(int hash_length = 16, byte numLevels = 4)
        {
            hashLength = hash_length;
            levels = numLevels;
            root.childNodes = new SortedList<byte, PITNode>();
        }

        private bool addIntRec(byte[] binaryTxid, PITNode cn, byte level)
        {
            byte cb = binaryTxid[level];
            if (level >= (levels - 1))
            {
                // we've reached last (leaf) level
                if (cn.data == null)
                {
                    cn.data = new SortedSet<byte[]>(new ByteArrayComparer());
                }
                if (!cn.data.Contains(binaryTxid))
                {
                    cn.data.Add(binaryTxid);
                    cn.hash = null;
                    return true; // something has changed
                }
                return false; // nothing has changed
            }
            bool changed = false;
            if(!cn.childNodes.ContainsKey(cb))
            {
                PITNode n = new PITNode(level + 1);
                if (level + 1 < levels - 1)
                {
                    n.childNodes = new SortedList<byte, PITNode>();
                }
                cn.childNodes.Add(cb, n);
                changed = true;
            }
            changed |= addIntRec(binaryTxid, cn.childNodes[cb], (byte)(level + 1));
            if(changed)
            {
                cn.hash = null;
            }
            return changed;
        }

        private bool delIntRec(byte[] binaryTxid, PITNode cn)
        {
            if (cn.data != null)
            {
                // we've reached the last non-leaf level
                if(cn.data.RemoveWhere(x => x.SequenceEqual(binaryTxid)) > 0)
                {
                    cn.hash = null;
                    return true; // something has changed
                }
            }
            else if (cn.childNodes != null)
            {
                bool changed = false;
                byte cb = binaryTxid[cn.level];
                if (cn.childNodes.ContainsKey(cb))
                {
                    PITNode t_node = cn.childNodes[cb];
                    changed = delIntRec(binaryTxid, t_node);
                    if((t_node.childNodes == null || t_node.childNodes.Count == 0) && (t_node.data == null || t_node.data.Count == 0)) {
                        // the child node at `cb` has neither further children nor data, we can drop it
                        cn.childNodes.Remove(cb);
                        changed = true;
                    }
                    if (changed)
                    {
                        // child node has no leaves
                        cn.hash = null;
                    }
                }
                return changed;
            }
            return false;
        }

        private bool containsIntRec(byte[] binaryTxid, PITNode cn)
        {
            byte cb = binaryTxid[cn.level];
            if(cn.data != null)
            {
                if(cn.data.Any(x => x.SequenceEqual(binaryTxid)))
                {
                    return true;
                }
            }
            if(cn.childNodes != null && cn.childNodes.ContainsKey(cb))
            {
                return containsIntRec(binaryTxid, cn.childNodes[cb]);
            }
            return false;
        }

        private void calcHashInt(PITNode cn)
        {
            if (cn.hash != null)
            {
                // hash is already cached (or retrieved in the minimal tree)
                return;
            }
            if (cn.data != null)
            {
                // last non-leaf level
                int all_hashes_len = cn.data.Aggregate(0, (sum, x) => sum + x.Length);
                byte[] indata = new byte[all_hashes_len];
                int idx = 0;
                foreach (var d in cn.data)
                {
                    Array.Copy(d, 0, indata, idx, d.Length);
                    idx += d.Length;
                }
                cn.hash = Crypto.sha512sqTrunc(indata, 0, indata.Length, hashLength);
            } else if (cn.childNodes != null)
            {
                byte[] indata = new byte[cn.childNodes.Count * hashLength];
                int idx = 0;
                foreach (var n in cn.childNodes)
                {
                    if (n.Value.hash == null)
                    {
                        calcHashInt(n.Value);
                    }
                    Array.Copy(n.Value.hash, 0, indata, idx * hashLength, n.Value.hash.Length);
                    idx += 1;
                }
                cn.hash = Crypto.sha512sqTrunc(indata, 0, indata.Length, hashLength);
            }
        }

        private void writeMinTreeInt(byte[] binaryTxid, BinaryWriter wr, PITNode cn)
        {
            if(cn.data != null)
            {
                // final node - write all txids, because they are required to calculate node hash
                wr.Write((int)-1); // marker for the leaf node
                wr.Write(cn.data.Count);
                foreach(var txid in cn.data)
                {
                    wr.Write(txid.Length);
                    wr.Write(txid);
                }
            }
            if(cn.childNodes != null)
            {
                // intermediate node - write all prefixes and hashes, except for the downward tree, so the partial tree can be reconstructed
                wr.Write((int)-2); // marker for the non-leaf node
                wr.Write(cn.childNodes.Count - 1);
                byte cb = binaryTxid[cn.level];
                foreach (var n in cn.childNodes)
                {
                    if (n.Key == cb)
                    {
                        // skip our target branch - we will write that last
                        continue;
                    }
                    wr.Write(n.Key);
                    wr.Write(n.Value.hash);
                }
                // follow the downwards direction for the transaction we're adding
                wr.Write(cb);
                writeMinTreeInt(binaryTxid, wr, cn.childNodes[cb]);
            }
        }

        private void readMinTreeInt(BinaryReader br, PITNode cn)
        {
            int type = br.ReadInt32();
            if (type == -1)
            {
                // final non-leaf node, what follows are TXids
                int num_tx = br.ReadInt32();
                cn.data = new SortedSet<byte[]>(new ByteArrayComparer());
                for (int i = 0; i < num_tx; i++)
                {
                    int txid_len = br.ReadInt32();
                    byte[] txid = br.ReadBytes(txid_len);
                    cn.data.Add(txid);
                }
            }
            else if (type == -2)
            {
                // normal non-leaf node, following are hashes for child nodes and then the next node down
                int num_child = br.ReadInt32(); // children except for the downward
                cn.childNodes = new SortedList<byte, PITNode>(num_child + 1);
                for (int i = 0; i < num_child; i++)
                {
                    byte cb1 = br.ReadByte();
                    PITNode n = new PITNode(cn.level + 1);
                    n.hash = br.ReadBytes(hashLength);
                    cn.childNodes.Add(cb1, n);
                }
                // downwards direction:
                byte cb = br.ReadByte();
                PITNode n_down = new PITNode(cn.level + 1);
                readMinTreeInt(br, n_down);
                cn.childNodes.Add(cb, n_down);
            }
        }

        private void writeMinTreeAInt(BinaryWriter wr, PITNode cn)
        {
            if (cn.data != null)
            {
                // leaf node - write node's hash and transactions (only if more than one)
                wr.Write((int)-1); // marker for the leaf node
                if (cn.data.Count > 1)
                {
                    wr.Write(cn.data.Count);
                    foreach (var txid in cn.data)
                    {
                        wr.Write(txid.Length);
                        wr.Write(txid);
                    }
                }
                else
                {
                    wr.Write(0); // zero transactions needed
                }
                wr.Write(cn.hash);
            }
            if (cn.childNodes != null)
            {
                wr.Write((int)-2); // marker for non-leaf node
                wr.Write(cn.childNodes.Count);
                foreach (var n in cn.childNodes)
                {
                    wr.Write(n.Key);
                    writeMinTreeAInt(wr, n.Value);
                }
            }
        }

        private void readMinTreeAInt(BinaryReader br, PITNode cn)
        {
            int type = br.ReadInt32();
            if (type == -1)
            {
                // leaf node
                int count_txids = br.ReadInt32();
                if (count_txids > 0)
                {
                    cn.data = new SortedSet<byte[]>(new ByteArrayComparer());
                    for (int i = 0; i < count_txids; i++)
                    {
                        int txid_len = br.ReadInt32();
                        byte[] txid = br.ReadBytes(txid_len);
                        cn.data.Add(txid);
                    }
                }
                cn.hash = br.ReadBytes(hashLength);
            } else if (type == -2)
            {
                int num_child = br.ReadInt32();
                cn.childNodes = new SortedList<byte, PITNode>(num_child);
                for (int i = 0; i < num_child; i++)
                {
                    byte cb1 = br.ReadByte();
                    PITNode n = new PITNode(cn.level + 1);
                    readMinTreeAInt(br, n);
                    cn.childNodes.Add(cb1, n);
                }
            }
        }

        /// <summary>
        /// Adds the specified transaction ID (string) to the Prefix Inclusion Tree. The transaction
        ///  will always be placed in the same leaf node, depending on the tree's number of levels.
        /// </summary>
        /// <param name="txid">Transaction ID to add to the tree.</param>
        public void add(string txid)
        {
            lock(threadLock)
            {
                addIntRec(UTF8Encoding.UTF8.GetBytes(txid), root, 0);
            }
        }

        /// <summary>
        /// Removes the specified transaction from the Prefix Inclusion Tree.
        /// </summary>
        /// <remarks>
        /// If the transaction ID is not in the tree, no change is done.
        /// </remarks>
        /// <param name="txid">Transaction ID to remove from the tree.</param>
        public void remove(string txid)
        {
            lock(threadLock)
            {
                delIntRec(UTF8Encoding.UTF8.GetBytes(txid), root);
            }
        }

        /// <summary>
        /// Verifies that the given transaction ID is present in the Prefix Inclusion Tree.
        /// </summary>
        /// <param name="txid">Transaction ID to search for in the Tree.</param>
        /// <returns>True, if `txid` was found in the tree, false otherwise.</returns>
        public bool contains(string txid)
        {
            lock(threadLock)
            {
                return containsIntRec(UTF8Encoding.UTF8.GetBytes(txid), root);
            }
        }

        /// <summary>
        /// Calculates a summary hash of the Prefix Inclusion Tree. Given the summary hash
        ///  and the minimal tree representation, it is possible to verify with an extremely high degree of 
        ///  certainty that a specific transaction is included in the Tree.
        /// </summary>
        /// <remarks>
        /// False positives are proportional to the conflict possibility of the `SHA512SqTrunc` algorithm (see 
        ///  the IXICore.Crypto namespace for details). False positive chance is reduced depending on the hash_length
        ///  parameter with which the Tree was constructed.
        /// </remarks>
        /// <returns>A byte array containing the Tree hash (length depends on the `hash_length` parameter with which the Tree was constructed).</returns>
        public byte[] calculateTreeHash()
        {
            lock(threadLock)
            {
                calcHashInt(root);
                return root.hash;
            }
        }

        /// <summary>
        /// Retrieves the minimal amount of information required to reconstruct a Partial Inclusion Tree and verify that the given
        ///  transaction `txid` is present in the tree.
        /// </summary>
        /// <remarks>
        /// In order to verify transaction inclusion in a certain DLT block, a minimum tree can be requested from any node, after which
        ///  you must call the `reconstructMinimumTree()` function, followed by the `calculateTreehash()` function.
        ///  After that is calculated successfully, you must compare the tree's hash (obtained by calling the `calculateTreeHash()` function 
        ///  with the hash value in the DLT block.
        /// </remarks>
        /// <param name="txid">Transaction ID for which the minimal tree will be constructed/</param>
        /// <returns>Byte stream containig the minimal tree for the specified transaction.</returns>
        public byte[] getMinimumTree(string txid)
        {
            lock(threadLock)
            {
                if(root.hash == null)
                {
                    calculateTreeHash();
                }
                MemoryStream ms = new MemoryStream();
                using (BinaryWriter bw = new BinaryWriter(ms, Encoding.UTF8, true))
                {
                    bw.Write((int)(PIT_MinimumTreeType.SingleTX));
                    bw.Write(levels);
                    bw.Write(hashLength);
                    writeMinTreeInt(UTF8Encoding.UTF8.GetBytes(txid), bw, root);
                }
                return ms.ToArray();
            }
        }

        public byte[] getMinimumTreeAnonymized()
        {
            lock(threadLock)
            {
                if (root.hash == null)
                {
                    calculateTreeHash();
                }
                MemoryStream ms = new MemoryStream();
                using (BinaryWriter bw = new BinaryWriter(ms, Encoding.UTF8, true))
                {
                    bw.Write((int)(PIT_MinimumTreeType.Anonymized));
                    bw.Write(levels);
                    bw.Write(hashLength);
                    writeMinTreeAInt(bw, root);
                }
                return ms.ToArray();
            }
        }

        /// <summary>
        /// Reconstructs a minimal tree representation from the given bytestream.
        /// <remarks>
        /// In order to verify transaction inclusion in a certain DLT block, a minimum tree can be requested from any node, after which
        ///  you must call the `reconstructMinimumTree()` function, followed by the `calculateTreeHash()` function.
        /// The root hash will be calculated based on the provided data. You can then compare this value with the value in a block header.
        /// </remarks>
        /// </summary>
        /// <param name="data"></param>
        public void reconstructMinimumTree(byte[] data)
        {
            lock(threadLock)
            {
                root = new PITNode(0);
                root.childNodes = new SortedList<byte, PITNode>();
                using (BinaryReader br = new BinaryReader(new MemoryStream(data)))
                {
                    PIT_MinimumTreeType type = (PIT_MinimumTreeType)br.ReadInt32();
                    levels = br.ReadByte();
                    hashLength = br.ReadInt32();
                    if (type == PIT_MinimumTreeType.SingleTX)
                    {
                        readMinTreeInt(br, root);
                    } else if (type == PIT_MinimumTreeType.Anonymized)
                    {
                        readMinTreeAInt(br, root);
                    }
                }
            }
        }
    }
}
