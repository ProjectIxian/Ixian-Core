using DLT.Meta;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Linq;
using IXICore.Utils;
using IXICore;

namespace DLT
{
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

    public class Block
    {
        public static int maxVersion = 4;

        // TODO: Refactor all of these as readonly get-params
        public ulong blockNum { get; set; }

        public List<string> transactions = new List<string> { };
        public List<byte[][]> signatures = new List<byte[][]> { };

        private int signatureCount = 0; // used only when block is compacted

        public int version = 0;
        public byte[] blockChecksum = null;
        public byte[] lastBlockChecksum = null;
        public byte[] walletStateChecksum = null;
        public byte[] signatureFreezeChecksum = null;
        public long timestamp = 0;
        public ulong difficulty = 0;

        public Dictionary<ulong, SuperBlockSegment> superBlockSegments = new Dictionary<ulong, SuperBlockSegment>();
        public byte[] lastSuperBlockChecksum = null;
        public ulong lastSuperBlockNum = 0;

        // Locally calculated
        public byte[] powField = null;


        // if block was read from local storage
        public bool fromLocalStorage = false;

        public bool compacted = false;
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
            version = 0;
            blockNum = 0;
            transactions = new List<string>();
        }

        public Block(Block block)
        {
            version = block.version;
            blockNum = block.blockNum;

            lastSuperBlockNum = block.lastSuperBlockNum;

            foreach(var entry in block.superBlockSegments)
            {
                superBlockSegments.Add(entry.Key, new SuperBlockSegment(entry.Key, entry.Value.blockChecksum));
            }

            // Add transactions and signatures from the old block
            foreach (string txid in block.transactions)
            {
                transactions.Add(txid);
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

        public Block(byte[] bytes)
        {
            try
            {
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        version = reader.ReadInt32();


                        if (version > 5 && bytes.Length > 10240000)
                        {
                            throw new Exception("Block size is bigger than 10MB.");
                        }else if(version < 6 && bytes.Length > 32768000)
                        {
                            throw new Exception("Block size is bigger than 32MB.");
                        }

                        blockNum = reader.ReadUInt64();

                        if (version <= maxVersion)
                        {

                            // Get the transaction ids
                            int num_transactions = reader.ReadInt32();
                            for (int i = 0; i < num_transactions; i++)
                            {
                                string txid = reader.ReadString();
                                transactions.Add(txid);
                            }

                            // Get the signatures
                            int num_signatures = reader.ReadInt32();
                            for (int i = 0; i < num_signatures; i++)
                            {
                                int sigLen = reader.ReadInt32();
                                byte[] sig = reader.ReadBytes(sigLen);
                                int sigAddresLen = reader.ReadInt32();
                                byte[] sigAddress = reader.ReadBytes(sigAddresLen);
                                if (!containsSignature(sigAddress))
                                {
                                    byte[][] newSig = new byte[2][];
                                    newSig[0] = sig;
                                    newSig[1] = sigAddress;
                                    signatures.Add(newSig);
                                }
                            }
                            int dataLen = reader.ReadInt32();
                            blockChecksum = reader.ReadBytes(dataLen);

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

                            if(version > 4)
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
                                    byte[] seg_bc = reader.ReadBytes(seg_bc_len);
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
        
        public byte[] getBytes()
        {
            if(compacted)
            {
                Logging.error("Trying to use getBytes() from a compacted Block {0}", blockNum);
                return null;
            }
            using (MemoryStream m = new MemoryStream())
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
                        // Write the number of signatures
                        int num_signatures = signatures.Count;
                        writer.Write(num_signatures);

                        // Write each signature
                        foreach (byte[][] signature in signatures)
                        {
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

                    writer.Write(superBlockSegments.Count);
                    foreach(var entry in superBlockSegments)
                    {
                        writer.Write(entry.Key);
                        writer.Write(entry.Value.blockChecksum.Length);
                        writer.Write(entry.Value.blockChecksum);
                    }
                }
                return m.ToArray();
            }
        }

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
            }else
            {
                Logging.warn(String.Format("Tried to add a duplicate transaction {0} to block {1}.", txid, blockNum));
            }

            return true;
        }

        // Returns the checksum of this block, without considering signatures
        public byte[] calculateChecksum()
        {
            if (compacted)
            {
                Logging.error("Trying to calculate checksum on a compacted block {0}", blockNum);
                return null;
            }

            List<byte> merged_segments = new List<byte>();
            foreach (var entry in superBlockSegments.OrderBy(x => x.Key))
            {
                merged_segments.AddRange(BitConverter.GetBytes(entry.Key));
                merged_segments.AddRange(entry.Value.blockChecksum);
            }

            StringBuilder merged_txids = new StringBuilder();
            foreach (string txid in transactions)
            {
                merged_txids.Append(txid);
            }


            List<byte> rawData = new List<byte>();
            rawData.AddRange(CoreConfig.ixianChecksumLock);
            rawData.AddRange(BitConverter.GetBytes(version));
            rawData.AddRange(BitConverter.GetBytes(blockNum));
            rawData.AddRange(Encoding.UTF8.GetBytes(merged_txids.ToString()));

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

            if (version <= 2)
            {
                return Crypto.sha512quTrunc(rawData.ToArray());
            }else
            {
                return Crypto.sha512sqTrunc(rawData.ToArray());
            }
        }

        // Returns the checksum of all signatures of this block
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
               sortedSigs = new List<byte[][]>(signatures);
            }
            sortedSigs.Sort((x, y) => _ByteArrayComparer.Compare(x[1], y[1]));

            // Merge the sorted signatures
            List<byte> merged_sigs = new List<byte>();
            merged_sigs.AddRange(BitConverter.GetBytes(blockNum));
            foreach (byte[][] sig in sortedSigs)
            {
                if(version > 3)
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
            if (version <= 2)
            {
                checksum = Crypto.sha512quTrunc(merged_sigs.ToArray());
            }else
            {
                checksum = Crypto.sha512sqTrunc(merged_sigs.ToArray());
            }
            return checksum;
        }

        // Applies this node's signature to this block
        public byte[][] applySignature()
        {
            // Note: we don't need any further validation, since this block has already passed through BlockProcessor.verifyBlock() at this point.
            byte[] myAddress = Node.walletStorage.getPrimaryAddress();
            if (containsSignature(myAddress))
            {
                return null;
            }

            byte[] myPubKey = Node.walletStorage.getPrimaryPublicKey();

            // TODO: optimize this in case our signature is already in the block, without locking signatures for too long
            byte[] private_key = Node.walletStorage.getPrimaryPrivateKey();
            byte[] signature = CryptoManager.lib.getSignature(blockChecksum, private_key);

            Wallet w = Node.walletState.getWallet(myAddress);

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

        public bool containsSignature(byte[] address_or_pub_key)
        {
            if (compacted)
            {
                Logging.error("Trying to check if compacted block {0} contains signature", blockNum);
                return false;
            }

            // Generate an address in case we got the pub key
            Address p_address = new Address(address_or_pub_key);
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
                    if (!containsSignature(sig[1]))
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

        public bool verifySignature(byte[] signature, byte[] signer_pub_key)
        {
            return CryptoManager.lib.verifySignature(blockChecksum, signer_pub_key, signature);
        }

        public bool addSignature(byte[] signature, byte[] address_or_pub_key)
        {
            if(compacted)
            {
                Logging.error("Trying to add signature on a compacted block {0}", blockNum);
                return false;
            }
            lock (signatures)
            {
                if (!containsSignature(address_or_pub_key))
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

        public byte[] getSignerPubKey(byte[] address_or_pub_key)
        {
            if(address_or_pub_key == null)
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
                Wallet signer_wallet = Node.walletState.getWallet(address_or_pub_key);
               return signer_wallet.publicKey;
            }
            return null;
        }

        public bool verifySignatures(bool skip_sig_verification = false)
        {
            if (compacted)
            {
                Logging.error("Trying to verify signatures on a compacted block {0}", blockNum);
                return false;
            }

            lock (signatures)
            {
                List<byte[]> sigAddresses = new List<byte[]>();

                List<byte[][]> safeSigs = new List<byte[][]>(signatures);

                foreach (byte[][] sig in safeSigs)
                {
                    byte[] signature = sig[0];
                    byte[] address = sig[1];

                    byte[] signer_pub_key = getSignerPubKey(sig[1]);

                    if (signer_pub_key == null)
                    {
                        // invalid public key
                        signatures.Remove(sig);
                        continue;
                    }

                    if (sigAddresses.Find(x => x.SequenceEqual(signer_pub_key)) == null)
                    {
                        sigAddresses.Add(signer_pub_key);
                    }else
                    {
                        signatures.Remove(sig);
                        continue;
                    }

                    if (skip_sig_verification == false && verifySignature(signature, signer_pub_key) == false)
                    {
                        signatures.Remove(sig);
                        continue;
                    }


                }

                if(signatures.Count == 0)
                {
                    return false;
                }

                return true;
            }
        }

        // Goes through all signatures and verifies if the block is already signed with this node's pubkey
        public bool hasNodeSignature(byte[] public_key = null)
        {
            if (compacted)
            {
                Logging.error("Trying to execute hasNodeSignature on a compacted block {0}", blockNum);
                return false;
            }

            byte[] node_address = Node.walletStorage.getPrimaryAddress();
            if (public_key == null)
            {
                public_key = Node.walletStorage.getPrimaryPublicKey();
            }
            else
            {
                // Generate an address
                Address p_address = new Address(public_key);
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

        // Goes through all signatures and generates the corresponding Ixian wallet addresses
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

                foreach (byte[][] merged_signature in signatures)
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
                        Wallet signerWallet = Node.walletState.getWallet(addressBytes);
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
                            Address address = new Address(pubKeyBytes);
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

        // Returns the number of unique signatures
        public int getUniqueSignatureCount()
        {
            if (compacted)
            {
                return signatureCount;
            }

            int signature_count = 0;

            // TODO: optimize this section to handle a large amount of signatures efficiently
            int sindex1 = 0;

            lock (signatures)
            {

                foreach (byte[][] signature in signatures)
                {
                    bool duplicate = false;
                    int sindex2 = 0;
                    foreach (byte[][] signature_check in signatures)
                    {
                        if (sindex1 == sindex2)
                            continue;

                        if (signature[1].SequenceEqual(signature_check[1]))
                        {
                            duplicate = true;
                        }
                        sindex2++;
                    }

                    if (duplicate == false)
                    {
                        signature_count++;
                    }
                    sindex1++;
                }
            }
            return signature_count;
        }

        public void setWalletStateChecksum(byte[] checksum)
        {
            walletStateChecksum = new byte[checksum.Length];
            Array.Copy(checksum, walletStateChecksum, walletStateChecksum.Length);
        }

        public bool pruneSignatures()
        {
            if (version < 4)
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

        public bool compact()
        {
            if(compacted)
            {
                return false;
            }

            compacted = true;

            signatureCount = signatures.Count;
            signatures = null;

            superBlockSegments = null;
            transactions = null;

            return true;

        }

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

        public bool isGenesis { get { return this.blockNum == 0 && this.lastBlockChecksum == null; } }

    }    
}