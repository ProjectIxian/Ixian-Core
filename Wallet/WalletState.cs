using DLT.Meta;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DLT
{
    public class WsChunk
    {
        public ulong blockNum;
        public int chunkNum;
        public Wallet[] wallets;
    }

    class WalletState
    {
        private readonly object stateLock = new object();
        public int version = 0;
        private readonly Dictionary<byte[], Wallet> walletState = new Dictionary<byte[], Wallet>(new ByteArrayComparer()); // The entire wallet list
        private byte[] cachedChecksum = null;
        private Dictionary<byte[], Wallet> wsDelta = null;
        private byte[] cachedDeltaChecksum = null;
        private int cachedBlockVersion = 0;

        private IxiNumber cachedTotalSupply = new IxiNumber(0);

        /* Size:
         * 10_000 wallets: ~510 KB
         * 100_000 wallets: ~5 MB
         * 10_000_000 wallets: ~510 MB (312 MB)
         * 
         * Keys only:
         * 10_000_000 addresses: 350 MB (176 MB)
         * 
         */

        public int numWallets { get => walletState.Count; }
        public bool hasSnapshot { get => wsDelta != null; }

        public WalletState()
        {
        }

        public WalletState(IEnumerable<Wallet> genesisState)
        {
            Logging.info(String.Format("Generating genesis WalletState with {0} wallets.", genesisState.Count()));
            foreach(Wallet w in genesisState)
            {
                Logging.info(String.Format("-> Genesis wallet ( {0} ) : {1}.", Base58Check.Base58CheckEncoding.EncodePlain(w.id), w.balance));
                walletState.Add(w.id, w);
            }
        }

        // Construct the walletstate from and older one
        public WalletState(WalletState oldWS)
        {
            version = oldWS.version;
            walletState = new Dictionary<byte[], Wallet>(oldWS.walletState);
            cachedChecksum = oldWS.cachedChecksum;
            cachedTotalSupply = oldWS.cachedTotalSupply;
            wsDelta = new Dictionary<byte[], Wallet>(oldWS.wsDelta, new ByteArrayComparer());
            cachedDeltaChecksum = oldWS.cachedDeltaChecksum;
        }

        public void clear()
        {
            Logging.info("Clearing wallet state!!");
            lock(stateLock)
            {
                walletState.Clear();
                cachedChecksum = null;
                cachedTotalSupply = new IxiNumber(0);
                wsDelta = null;
                cachedDeltaChecksum = null;

            }
        }

        public bool snapshot()
        {
            lock (stateLock)
            {
                if (wsDelta != null)
                {
                    Logging.warn("Unable to create WalletState snapshot, because a snapshot already exists.");
                    return false;
                }
                Logging.info("Creating a WalletState snapshot.");
                wsDelta = new Dictionary<byte[], Wallet>(new ByteArrayComparer());
                return true;
            }
        }

        public void revert()
        {
            lock (stateLock)
            {
                if (wsDelta != null)
                {
                    Logging.info(String.Format("Reverting WalletState snapshot ({0} wallets).", wsDelta.Count));
                    wsDelta = null;
                    cachedDeltaChecksum = null;
                }
            }
        }

        public void commit()
        {
            lock (stateLock)
            {
                if (wsDelta != null)
                {
                    //Logging.info(String.Format("Committing WalletState snapshot. Wallets in snapshot: {0}.", wsDelta.Count));
                    foreach (var wallet in wsDelta)
                    {
                        if (cachedBlockVersion >= 5 && wallet.Value.balance.getAmount() == 0 && wallet.Value.type == WalletType.Normal)
                        {
                            walletState.Remove(wallet.Key);
                        }
                        else
                        {
                            walletState.AddOrReplace(wallet.Key, wallet.Value);
                        }
                    }
                    wsDelta = null;
                    cachedDeltaChecksum = null;
                    cachedChecksum = null;
                    cachedTotalSupply = new IxiNumber(0);
                }
            }
        }

        public IxiNumber getWalletBalance(byte[] id, bool snapshot = false)
        {
            return getWallet(id, snapshot).balance;
        }



        public Wallet getWallet(byte[] id, bool snapshot = false)
        {
            lock (stateLock)
            {
                Wallet candidateWallet = new Wallet(id, (ulong)0);
                if (walletState.ContainsKey(id))
                {
                    // copy
                    candidateWallet = new Wallet(walletState[id]);
                }
                if (snapshot)
                {
                    if (wsDelta != null && wsDelta.ContainsKey(id))
                    {
                        // copy
                        candidateWallet = new Wallet(wsDelta[id]);
                    }
                }
                return candidateWallet;
            }
        }

        public void setWallet(Wallet w, bool snapshot = false)
        {
            lock(stateLock)
            {
                if(snapshot)
                {
                    if(wsDelta != null)
                    {
                        wsDelta.AddOrReplace(w.id, w);
                        return;
                    } 
                }
                walletState.AddOrReplace(w.id, w);
            }
        }


        // Sets the wallet balance for a specified wallet
        public void setWalletBalance(byte[] id, IxiNumber balance, bool snapshot = false)
        {
            lock (stateLock)
            {
                // Check if wallet exists first
                Wallet wallet = getWallet(id, snapshot);

                if (wallet == null)
                {
                    // Create a new wallet if it doesn't exist
                    wallet = new Wallet(id, balance);
                }
                else
                {
                    // Set the balance
                    wallet.balance = balance;
                }

                if (snapshot == false)
                {
                    if (cachedBlockVersion >= 5 && balance.getAmount() == 0 && wallet.type == WalletType.Normal)
                    {
                        walletState.Remove(id);
                    }
                    else
                    {
                        walletState.AddOrReplace(id, wallet);
                    }
                    cachedChecksum = null;
                    cachedTotalSupply = new IxiNumber(0);
                    cachedDeltaChecksum = null;
                }
                else
                {
                    if (wsDelta == null)
                    {
                        Logging.warn(String.Format("Attempted to apply wallet state to the snapshot, but it does not exist."));
                        return;
                    }
                    wsDelta.AddOrReplace(id, wallet);
                    cachedDeltaChecksum = null;
                }
            }
        }

        // Sets the wallet public key for a specified wallet
        public void setWalletPublicKey(byte[] id, byte[] public_key, bool snapshot = false)
        {
            lock(stateLock)
            {
                Wallet wallet = getWallet(id, snapshot);

                if (wallet == null)
                {
                    Logging.warn(String.Format("Attempted to set public key for wallet {0} that does not exist.", Base58Check.Base58CheckEncoding.EncodePlain(id)));
                    return;
                }

                // TODO: perhaps check if the public key is already set
                wallet.publicKey = public_key;

                if (snapshot == false)
                {
                    walletState.AddOrReplace(id, wallet);
                    cachedChecksum = null;
                    cachedTotalSupply = new IxiNumber(0);
                    cachedDeltaChecksum = null;
                }
                else
                {
                    if (wsDelta == null)
                    {
                        Logging.warn(String.Format("Attempted to apply wallet state to the snapshot, but it does not exist."));
                        return;
                    }
                    wsDelta.AddOrReplace(id, wallet);
                    cachedDeltaChecksum = null;
                }
            }
        }

        public void setCachedBlockVersion(int block_version)
        {
            // edge case for first block of block_version 3
            if (block_version == 3 && Node.getLastBlockVersion() == 2)
            {
                block_version = 2;
            }

            if (cachedBlockVersion != block_version)
            {
                cachedChecksum = null;
                cachedDeltaChecksum = null;
                cachedBlockVersion = block_version;
            }
        }

        public byte[] calculateWalletStateChecksum(bool snapshot = false)
        {
            lock (stateLock)
            {
                if (snapshot == false && cachedChecksum != null)
                {
                    return cachedChecksum;
                }
                else if (snapshot == true && cachedDeltaChecksum != null)
                {
                    return cachedDeltaChecksum;
                }

                // TODO: This could get unwieldy above ~100M wallet addresses. We have to implement sharding by then.
                SortedSet<byte[]> eligible_addresses = null;
                eligible_addresses = new SortedSet<byte[]>(walletState.Keys, new ByteArrayComparer());

                if (snapshot == true)
                {
                    if (wsDelta != null)
                    {
                        foreach (var entry in wsDelta)
                        {
                            eligible_addresses.Add(entry.Key);
                        }
                    }
                }

                byte[] checksum = null;
                if (cachedBlockVersion <= 2)
                {
                    checksum = Crypto.sha512quTrunc(Encoding.UTF8.GetBytes("IXIAN-DLT" + version));
                }else
                {
                    checksum = Crypto.sha512sqTrunc(Encoding.UTF8.GetBytes("IXIAN-DLT" + version), 0, 0, 64);
                }

                // TODO: This is probably not the optimal way to do this. Maybe we could do it by blocks to reduce calls to sha256
                // Note: addresses are not fixed size
                foreach (byte[] addr in eligible_addresses)
                {
                    byte[] wallet_checksum = getWallet(addr, snapshot).calculateChecksum(cachedBlockVersion);
                    if (cachedBlockVersion <= 2)
                    {
                        checksum = Crypto.sha512quTrunc(Encoding.UTF8.GetBytes(Crypto.hashToString(checksum) + Crypto.hashToString(wallet_checksum)));
                    }else
                    {
                        List<byte> tmp_hash = checksum.ToList();
                        tmp_hash.AddRange(wallet_checksum);
                        checksum = Crypto.sha512sqTrunc(tmp_hash.ToArray(), 0, 0, 64);
                    }
                }

                if (snapshot == false)
                {
                    cachedChecksum = checksum;
                }
                else
                {
                    cachedDeltaChecksum = checksum;
                }
                return checksum;
            }
        }

        // calculates the checksum of changed balances (applicable only for snapshot use)
        public byte[] calculateWalletStateDeltaChecksum()
        {
            List<byte> ws_data = new List<byte>();

            lock (stateLock)
            {
                if (wsDelta == null)
                {
                    Logging.error("Tried to calculate WalletStateDeltaChecksum but wsDelta is null");
                    return null;
                }

                ws_data.AddRange(Encoding.UTF8.GetBytes("IXIAN-DLT" + version));

                var ordered_delta = wsDelta.OrderBy(x => x.Key, new ByteArrayComparer());

                foreach (var entry in ordered_delta)
                {
                    ws_data.AddRange(entry.Value.getBytes());
                }

            }

            return Crypto.sha512sqTrunc(ws_data.ToArray(), 0, 0, 64);
        }

        public WsChunk[] getWalletStateChunks(int chunk_size, ulong block_num)
        {
            lock(stateLock)
            {
                if(chunk_size == 0)
                {
                    chunk_size = walletState.Count;
                }
                int num_chunks = walletState.Count / chunk_size + 1;
                Logging.info(String.Format("Preparing {0} chunks of walletState. Total wallets: {1}", num_chunks, walletState.Count));
                WsChunk[] chunks = new WsChunk[num_chunks];
                for(int i=0;i<num_chunks;i++)
                {
                    chunks[i] = new WsChunk
                    {
                        blockNum = block_num,
                        chunkNum = i,
                        wallets = walletState.Skip(i * chunk_size).Take(chunk_size).Select(x => x.Value).ToArray()
                    };
                }
                Logging.info(String.Format("Prepared {0} WalletState chunks with {1} total wallets.",
                    num_chunks,
                    chunks.Sum(x => x.wallets.Count())));
                return chunks;
            }
        }

        public void setWalletChunk(Wallet[] wallets)
        {
            lock (stateLock)
            {
                if (wsDelta != null)
                {
                    // TODO: need to return an error to the caller, otherwise sync process might simply hang
                    Logging.error("Attempted to apply a WalletState chunk, but snapshots exist!");
                    return;
                }
                foreach (Wallet w in wallets)
                {
                    if (w != null)
                    {
                        walletState.AddOrReplace(w.id, w);
                    }
                }
                cachedChecksum = null;
                cachedDeltaChecksum = null;
                cachedTotalSupply = new IxiNumber(0);
            }
        }

        // Calculates the entire IXI supply based on the latest wallet state
        public IxiNumber calculateTotalSupply()
        {
            IxiNumber total = new IxiNumber();
            lock (stateLock)
            {
                if (cachedTotalSupply != (long)0)
                {
                    return cachedTotalSupply;
                }
                try
                {
                    foreach (var item in walletState)
                    {
                        Wallet wal = (Wallet)item.Value;
                        total = total + wal.balance;
                    }
                    cachedTotalSupply = total;
                }
                catch (Exception e)
                {
                    Logging.error(string.Format("Exception calculating total supply: {0}", e.Message));
                }
            }
            return total;
        }

        // only returns 50 wallets from base state (no snapshotting)
        public Wallet[] debugGetWallets()
        {
            lock (stateLock)
            {
                return walletState.Take(50).Select(x => x.Value).ToArray();
            }
        }

    }
}
