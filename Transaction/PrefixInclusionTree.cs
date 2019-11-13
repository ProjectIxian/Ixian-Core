using System;
using System.Linq;
using System.IO;
using System.Collections.Generic;
using System.Text;

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

        private byte levels;
        private int hashLength;
        private PITNode root = new PITNode(0);
        private readonly object threadLock = new object();

        public PrefixInclusionTree(int hash_length = 16, byte numLevels = 4)
        {
            hashLength = hash_length;
            levels = numLevels;
            root.childNodes = new SortedList<byte, PITNode>();
        }

        private void addIntRec(byte[] binaryTxid, PITNode cn, byte level)
        {
            byte cb = binaryTxid[level];
            if (level >= (levels - 1))
            {
                // we've reached last non-leaf level
                if(cn.data == null)
                {
                    cn.data = new SortedSet<byte[]>();
                }
                cn.data.Add(binaryTxid);
                return;
            }

            if(!cn.childNodes.ContainsKey(cb))
            {
                PITNode n = new PITNode(level + 1);
                if (level + 1 < levels - 1)
                {
                    n.childNodes = new SortedList<byte, PITNode>();
                }
                cn.childNodes.Add(cb, n);
            }
            addIntRec(binaryTxid, cn.childNodes[cb], (byte)(level + 1));
        }

        private bool delIntRec(byte[] binaryTxid, PITNode cn)
        {
            byte cb = binaryTxid[cn.level];
            if (cn.data != null)
            {
                // we've reached the last non-leaf level
                cn.data.RemoveWhere(x => x.SequenceEqual(binaryTxid));
                return cn.data.Count == 0;
            }
            if (cn.childNodes != null && cn.childNodes.ContainsKey(cb))
            {
                bool r = delIntRec(binaryTxid, cn.childNodes[cb]);
                if(r)
                {
                    // child node has no leaves
                    cn.childNodes.Remove(cb);
                }
                return cn.childNodes.Count == 0;
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
            if(cn.data != null)
            {
                // last non-leaf level
                int all_hashes_len = cn.data.Aggregate(0, (sum, x) => sum + x.Length);
                byte[] indata = new byte[all_hashes_len];
                int idx = 0;
                foreach(var d in cn.data)
                {
                    Array.Copy(d, 0, indata, idx, d.Length);
                    idx += d.Length;
                }
                cn.hash = Crypto.sha512sqTrunc(indata, 0, indata.Length, hashLength);
            } else if(cn.childNodes != null)
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
                // intermediate node - write all prefixes and hashes, so the partial tree can be reconstructed
                wr.Write((int)-2); // marker for the non-leaf node
                wr.Write(cn.childNodes.Count);
                foreach(var n in cn.childNodes)
                {
                    wr.Write(n.Key);
                    wr.Write(n.Value.hash);
                }
                // only follow downwards direction for the transaction we're adding
                byte cb = binaryTxid[cn.level];
                wr.Write(cb);
                writeMinTreeInt(binaryTxid, wr, cn.childNodes[cb]);
            }
        }

        private void readMinTreeInt(BinaryReader br, PITNode cn)
        {
            int type = br.ReadInt32();
            if(type == -1)
            {
                // final non-leaf node, what follows are TXids
                int num_tx = br.ReadInt32();
                cn.data = new SortedSet<byte[]>();
                for(int i=0;i<num_tx;i++)
                {
                    int txid_len = br.ReadInt32();
                    byte[] txid = br.ReadBytes(txid_len);
                    cn.data.Add(txid);
                }
            } else if(type == -2)
            {
                // normal non-leaf node, following are hashes for child nodes and then the next node down
                int num_child = br.ReadInt32();
                cn.childNodes = new SortedList<byte, PITNode>(num_child);
                for(int i=0;i<num_child;i++)
                {
                    byte cb = br.ReadByte();
                    PITNode n = new PITNode(cn.level + 1);
                    n.hash = br.ReadBytes(hashLength);
                    // downwards direction:
                    cb = br.ReadByte();
                    readMinTreeInt(br, cn.childNodes[cb]);
                }
            }
        }

        public void add(string txid)
        {
            lock(threadLock)
            {
                addIntRec(UTF8Encoding.UTF8.GetBytes(txid), root, 0);
            }
        }

        public void remove(string txid)
        {
            lock(threadLock)
            {
                delIntRec(UTF8Encoding.UTF8.GetBytes(txid), root);
            }
        }

        public bool contains(string txid)
        {
            lock(threadLock)
            {
                return containsIntRec(UTF8Encoding.UTF8.GetBytes(txid), root);
            }
        }

        public byte[] calculateTreeHash()
        {
            lock(threadLock)
            {
                calcHashInt(root);
                return root.hash;
            }
        }

        public byte[] getMinimumTree(string txid)
        {
            lock(threadLock)
            {
                MemoryStream ms = new MemoryStream();
                using (BinaryWriter bw = new BinaryWriter(ms, Encoding.UTF8, true))
                {
                    bw.Write(levels);
                    bw.Write(hashLength);
                    writeMinTreeInt(UTF8Encoding.UTF8.GetBytes(txid), bw, root);
                }
                return ms.ToArray();
            }
        }

        public void reconstructMinimumTree(byte[] data)
        {
            lock(threadLock)
            {
                root = new PITNode(0);
                root.childNodes = new SortedList<byte, PITNode>();
                using (BinaryReader br = new BinaryReader(new MemoryStream(data)))
                {
                    levels = br.ReadByte();
                    hashLength = br.ReadInt32();
                    readMinTreeInt(br, root);
                }
            }
        }
    }
}
