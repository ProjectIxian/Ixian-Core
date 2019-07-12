using IXICore.Meta;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace IXICore
{
    /// <summary>
    ///  Represents a single transaction on the Ixian blockchain.
    /// </summary>
    /// <remarks>
    ///  A transaction is an atomic change which manipulates the Ixian `WalletState`. Each transaction processed by the DLT
    ///  must be validated in some way:
    ///  <list type="bullet">
    ///   <item> For regular transactions this means a valid cryptographic signature by the source wallet owner.</item>
    ///   <item> For 'Multi-Signature' transactions this may include multiple cryptographic signatures</item>
    ///   <item> For 'PoW solution' transactions, the proposed value must be valid for the block it solves</item>
    ///   <item> For a 'Staking Reward' transaction, the proposed changes must be inline with the frozen signatures and the transaction must be
    ///          accepted by the network majority. </item>
    ///  </list>
    /// </remarks>
    public class Transaction
    {
        /// <summary>
        ///  Type of the transaction.
        /// </summary>
        public enum Type:int
        {
            /// <summary>
            ///  Regular transaction which sends balance from a set of `Wallet`s to a set of `Wallet`s.
            /// </summary>
            Normal = 0,
            /// <summary>
            ///  Transaction sends a PoW (Proof of Work) solution for a specific block and awards the signer a certain amount of Ixi as a reward.
            /// </summary>
            PoWSolution = 1,
            /// <summary>
            ///  Transaction awards the Master Nodes which participate in the consensus algorithm a certain reward of Ixi.
            /// </summary>
            StakingReward = 2,
            /// <summary>
            ///  Genesis transaction which created initial Ixi currency from nothing and deposited it into the seed nodes' wallets.
            /// </summary>
            /// <remarks>
            ///  This type of transaction should never again appear after the first block.
            /// </remarks>
            Genesis = 3,
            /// <summary>
            ///  Similar to `Trasaction.Type.Normal`, but requires multiple signatures to spend funds from a 'Multi-Signature' wallet.
            /// </summary>
            MultisigTX = 4,
            /// <summary>
            ///  Special transaction which alows modifying the list of allowed signers on a 'Multi-Signature' wallet.
            /// </summary>
            ChangeMultisigWallet = 5,
            /// <summary>
            ///  When a transaction involving a 'Multi-Signature' is first posted, it only has one signature, so this stub transaction is used to
            ///  add signatures so that private key sharing is not required among signers.
            /// </summary>
            MultisigAddTxSignature = 6
        }

        /// <summary>
        ///  Type of change being performed on a 'Multi-Signature' wallet.
        /// </summary>
        public enum MultisigWalletChangeType:byte
        {
            /// <summary>
            ///  A signer is being added to the Allowed Signers list.
            /// </summary>
            AddSigner = 1,
            /// <summary>
            ///  A signer is being removed from the Alloewd Signers list.
            /// </summary>
            /// <remarks>
            ///  The signer, who is being removed, can still validate the transaction that removes their address from the list. The change
            //   takes effect after the transaction is accepted.
            ///  The number of signatures must be equal to or less than the number of distinct allowed signers. A `ChangeMultisigWallet` transaction which would
            ///  make it impossible to use the wallet is invalid, even if it has enough correct signatures.
            /// </remarks>
            DelSigner = 2, 
            /// <summary>
            ///  The number of required signatures for the 'Multi-Signature' wallet is being changed.
            /// </summary>
            /// <remarks>
            ///  The number of signatures must be equal to or less than the number of distinct allowed signers. A `ChangeMultisigWallet` transaction which would
            ///  make it impossible to use the wallet is invalid, even if it has enough correct signatures.
            /// </remarks>
            ChangeReqSigs = 3
        }

        /// <summary>
        ///  Another allowed signer is being added to a Wallet. If the target wallet is not yet a 'Multi-Signature' wallet, it will be 
        ///  converted into one and the number of required signatures will be set to 1.
        /// </summary>
        public struct MultisigAddrAdd
        {
            /// <summary>
            ///  Wallet address of the new signer that is being added.
            /// </summary>
            public byte[] addrToAdd;
            /// <summary>
            ///  Public key of the new signer that is being validating this transaction, if neccessary.
            /// </summary>
            public byte[] signerPubKey;
            /// <summary>
            ///  Nonce value of the new signer that is validating this change.
            /// </summary>
            public byte[] signerNonce;
        }

        /// <summary>
        ///  An allowed signer is being removed from a Wallet. If the target wallet is not a 'Multi-Signature' wallet,
        ///  such a transaction is considered invalid. The original Wallet's owner cannot be removed.
        /// </summary>
        /// <remarks>
        ///  If the removal would cause the wallet to become unusable (Required Signatures greater than the number of possible signers),
        ///  this transaction is considered invalid.
        ///  If the removal leavs the wallet with a single remaining signer (the owner), the wallet is implicitly converted into a normal wallet.
        /// </remarks>
        public struct MultisigAddrDel
        {
            /// <summary>
            ///  Wallet address of the signer that is being removed.
            /// </summary>
            public byte[] addrToDel;
            /// <summary>
            ///  Public key of the signer that is validating this transaction, if neccessary.
            /// </summary>
            public byte[] signerPubKey;
            /// <summary>
            ///  Nonce value of the signer that is validating this change.
            /// </summary>
            public byte[] signerNonce;
        }

        /// <summary>
        ///  Change the number of required signatures for a 'Multi-Signature' wallet.
        /// </summary>
        /// <remarks>
        ///  The number of required signatures can be between 1 and the number of allowed signers for the wallet. If a transaction attempts to change
        ///  the required signatures number to larger than is possible (it would render the wallet unusable), such a change is considered invalid.
        ///  The `ChangeMultisigWallet` transaction which introduces the change is also subject to the *current* minimum signatures requirement.
        /// </remarks>
        public struct MultisigChSig
        {
            /// <summary>
            ///  New value for the minimum required signatures on the 'Multi-Signature' wallet.
            /// </summary>
            public byte reqSigs;
            /// <summary>
            ///  Public key of the signer that is validating this change, if neccessary.
            /// </summary>
            public byte[] signerPubKey;
            /// <summary>
            ///  Nonce value of the signer that is validating this change.
            /// </summary>
            public byte[] signerNonce;
        }

        /// <summary>
        ///  Additional signature for an existing `MultisigTX` transaction that is waiting in the pool.
        /// </summary>
        public struct MultisigTxData
        {
            /// <summary>
            ///  TXID of the original transaction which this transaction validates.
            /// </summary>
            public string origTXId;
            /// <summary>
            ///  Public key of the signer which can help authorize a Multisig transaction, if required (key is not yet present in the PresenceList).
            /// </summary>
            public byte[] signerPubKey;
            /// <summary>
            ///  Nonce value of the signer which can help authorize a Multisig transaction.
            /// </summary>
            public byte[] signerNonce;
        }

        /// <summary>
        ///  Transaction version.
        /// </summary>
        /// <remarks>
        ///  Later versions enable new features which were introduced later in development.
        /// </remarks>
        public int version;
        /// <summary>
        ///  Transaction ID.
        /// </summary>
        /// <remarks>
        ///  The transaction ID is not transferred over the network, because it can be recalculated from the transaction data.
        /// </remarks>
        public string id;
        /// <summary>
        ///  Transaction type. See also `Transaction.Type`.
        /// </summary>
        public int type;
        /// <summary>
        ///  Total amount of Ixi being transferred.
        /// </summary>
        public IxiNumber amount = new IxiNumber("0");
        /// <summary>
        ///  Transaction fee - based on the serialized size of the transaction.
        /// </summary>
        public IxiNumber fee = new IxiNumber("0");

        /// <summary>
        ///  Source wallets where the funds are withdrawn. Each address specifies the amount of Ixi being widthrawn from it.
        /// </summary>
        /// <remarks>
        ///  The sum of all amounts must be equal to `amount` + `fee`, otherwise the transaction is invalid. All source wallets
        ///  must belong to the same primary signing key.
        ///  The address can either be a wallet address or a nonce value which was used to generate the address. If the value
        ///  is a nonce value, then the public key, `pubKey`, for the transaction must be specified.
        /// </remarks>
        public SortedDictionary<byte[], IxiNumber> fromList = new SortedDictionary<byte[], IxiNumber>(new ByteArrayComparer());
        /// <summary>
        ///  Destination wallets where the funds will be deposited. Each address specifies the amount of Ixi being deposited to it.
        /// </summary>
        /// <remarks>
        ///  The sum of all amounts must be equal to `amount`, otherwise the transaction is invalid. Destination wallets can belong to
        ///  different signing keys.
        /// </remarks>
        public SortedDictionary<byte[], IxiNumber> toList = new SortedDictionary<byte[], IxiNumber>(new ByteArrayComparer());

        /// <summary>
        ///  Optional data included with the transaction. This can be any byte-field. The transaction fee will increase with the amount of data.
        /// </summary>
        public byte[] data;
        /// <summary>
        ///  Block number when the transaction was generated.
        /// </summary>
        public ulong blockHeight;
        /// <summary>
        ///  Unique 'nonce' value which prevents certain classes of transaction replay attacks.
        /// </summary>
        public int nonce;
        /// <summary>
        ///  Timestam of when the transaction was created as a unix epoch (seconds since 1970-01-01).
        /// </summary>
        public long timeStamp;
        /// <summary>
        ///  Checksum of all transaction data to ensure it hasn't been tampered with or corrupted during transmission.
        /// </summary>
        public byte[] checksum;
        /// <summary>
        ///  Signature by the originating wallets' primary key. See `fromList`.
        /// </summary>
        public byte[] signature;
        /// <summary>
        ///  Publick key which performed the signature and owns the source wallets in `fromList`.
        /// </summary>
        public byte[] pubKey;
        /// <summary>
        ///  Block height at which the transaction was applied.
        /// </summary>
        public ulong applied;
        /// <summary>
        ///  Indicator if the transaction was loaded from cold storage.
        /// </summary>
        /// <remarks>
        ///  If false, the transaction was generated by the current executable or received through the network.
        /// </remarks>
        public bool fromLocalStorage = false;

        /// <summary>
        ///  Unique value to identify serialized MultiSig data in the transaction `data` field.
        /// </summary>
        private readonly static byte[] multisigStartMarker = { 0x4d, 0x73 };

        /// <summary>
        ///  Helper flag that determines whether PoW solution was already verified (used locally)
        /// </summary>
        public bool powVerified = false;

        /// <summary>
        ///  Currently latest transaction version.
        /// </summary>
        public static int maxVersion = 3;

        /// <summary>
        ///  Sets the transaction's version appropriately, based on the current block version.
        /// </summary>
        private void setVersion()
        {
            int lastBlockVersion = IxianHandler.getLastBlockVersion();
            if (lastBlockVersion == 0)
            {
                version = 0;
            }else if (lastBlockVersion == 1)
            {
                version = 1;
            }else if(lastBlockVersion == 2)
            {
                version = 2;
            }else if(lastBlockVersion == 3)
            {
                version = 3;
            }else
            {
                version = maxVersion;
            }
        }

        /// <summary>
        /// Creates an empty transaction of the specified type.
        /// </summary>
        /// <param name="tx_type">Transaction type. See `Transaction.Type`.</param>
        public Transaction(int tx_type)
        {
            setVersion();

            type = tx_type;

            timeStamp = Core.getCurrentTimestamp();
            amount = new IxiNumber("0");
            fee = new IxiNumber("0");
            blockHeight = 0;

            Random r = new Random();
            nonce = (int)((DateTimeOffset.Now.ToUnixTimeMilliseconds() - (DateTimeOffset.Now.ToUnixTimeSeconds() * 1000)) * 100) + r.Next(100);

            applied = 0;
        }

        /// <summary>
        ///  Generates a new transaction from the provided data. This variant widthdraws from and deposits to a single address.
        /// </summary>
        /// <remarks>
        ///  The Fee can be higher than the minimum network fee, which will cause the transaction to be included faster in the event
        ///  of congestion.
        /// </remarks>
        /// <param name="tx_type">Type of the transaction. See `Transaction.Type`.</param>
        /// <param name="tx_amount">Total Ixi amount being transferred.</param>
        /// <param name="tx_feePerKb">Transaction fee per kilobyte of data.</param>
        /// <param name="tx_to">Destination address or nonce.</param>
        /// <param name="tx_from">Source address or nonce.</param>
        /// <param name="tx_data">Optional extra data.</param>
        /// <param name="tx_pubKey">Public key used to sign the transaction, if neccessary.</param>
        /// <param name="tx_blockHeight">Block height when the transaction was generated.</param>
        /// <param name="tx_nonce">Unique transaction nonce value.</param>
        /// <param name="tx_timestamp">Timestamp (unix epoch) when the transaction was generated.</param>
        public Transaction(int tx_type, IxiNumber tx_amount, IxiNumber tx_feePerKb, byte[] tx_to, byte[] tx_from, byte[] tx_data, byte[] tx_pubKey, ulong tx_blockHeight, int tx_nonce = -1, long tx_timestamp = 0)
        {
            setVersion();

            type = tx_type;

            amount = tx_amount;
            toList.Add(tx_to, amount);
            fromList.Add(new byte[1] { 0 }, amount);

            data = tx_data;

            blockHeight = tx_blockHeight;

            if (tx_nonce == -1)
            {
                Random r = new Random();
                nonce = (int)((DateTimeOffset.Now.ToUnixTimeMilliseconds() - (DateTimeOffset.Now.ToUnixTimeSeconds() * 1000)) * 100) + r.Next(100);
            }else
            {
                nonce = tx_nonce;
            }

            if (tx_timestamp > 0)
            {
                timeStamp = tx_timestamp;
            }else
            {
                timeStamp = Core.getCurrentTimestamp();
            }

            pubKey = tx_pubKey;
            if(pubKey == null)
            {
                pubKey = tx_from;
            }

            fee = calculateMinimumFee(tx_feePerKb);
            fromList[fromList.First().Key] = amount + fee;

            generateChecksums();

            if(type == (int)Transaction.Type.StakingReward)
            {
                signature = Encoding.UTF8.GetBytes("Stake");
            }
            else
            {
                signature = getSignature(checksum);
            }
        }

        /// <summary>
        ///  Generates a new transaction from the provided data. This variant can deposit to a multiple addresses.
        /// </summary>
        /// <remarks>
        ///  The Fee can be higher than the minimum network fee, which will cause the transaction to be included faster in the event
        ///  of congestion.
        ///  The sum if all amounts in the `tx_toList` is equal to `amount`.
        /// </remarks>
        /// <param name="tx_type">Type of the transaction. See `Transaction.Type`.</param>
        /// <param name="tx_feePerKb">Transaction fee per kilobyte of data.</param>
        /// <param name="tx_toList">List of deposit addresses and their amounts.</param>
        /// <param name="tx_from">Withdrawal address.</param>
        /// <param name="tx_data">Optional extra data.</param>
        /// <param name="tx_pubKey">Signer public key, if neccessary.</param>
        /// <param name="tx_blockHeight">Block number when the transaction was generated.</param>
        /// <param name="tx_nonce">Unique nonce value for the transaction.</param>
        /// <param name="tx_timestamp">Timestamp (unich epoch) when the transaction was generated.</param>
        public Transaction(int tx_type, IxiNumber tx_feePerKb, SortedDictionary<byte[], IxiNumber> tx_toList, byte[] tx_from, byte[] tx_data, byte[] tx_pubKey, ulong tx_blockHeight, int tx_nonce = -1, long tx_timestamp = 0)
        {
            setVersion();

            type = tx_type;


            toList = tx_toList;

            amount = calculateTotalAmount();

            fromList.Add(new byte[1] { 0 }, amount);

            data = tx_data;

            blockHeight = tx_blockHeight;

            if (tx_nonce == -1)
            {
                Random r = new Random();
                nonce = (int)((DateTimeOffset.Now.ToUnixTimeMilliseconds() - (DateTimeOffset.Now.ToUnixTimeSeconds() * 1000)) * 100) + r.Next(100);
            }
            else
            {
                nonce = tx_nonce;
            }

            if (tx_timestamp > 0)
            {
                timeStamp = tx_timestamp;
            }
            else
            {
                timeStamp = Core.getCurrentTimestamp();
            }

            pubKey = tx_pubKey;
            if (pubKey == null)
            {
                pubKey = tx_from;
            }

            fee = calculateMinimumFee(tx_feePerKb);
            fromList[fromList.First().Key] = amount + fee;

            generateChecksums();

            if (type == (int)Transaction.Type.StakingReward)
            {
                signature = Encoding.UTF8.GetBytes("Stake");
            }
            else
            {
                signature = getSignature(checksum);
            }
        }

        /// <summary>
        ///  Generates a new transaction from the provided data. This variant can withdraw from and deposit to a multiple addresses.
        /// </summary>
        /// <remarks>
        ///  The Fee can be higher than the minimum network fee, which will cause the transaction to be included faster in the event
        ///  of congestion.
        ///  All addresses in the `tx_fromList` must belong to the same signing keypair.
        ///  The sum if all amounts in the `tx_toList` is equal to `amount`.
        ///  The sum of all amounts in the `tx_fromList` must be equal to `amount` + `fee`.
        /// </remarks>
        /// <param name="tx_type">Type of the transaction. See `Transaction.Type`.</param>
        /// <param name="tx_feePerKb">Transaction fee per kilobyte of data.</param>
        /// <param name="tx_toList">List of deposit addresses and their amounts.</param>
        /// <param name="tx_fromList">List of withdrawal addresses and their amounts.</param>
        /// <param name="tx_data">Optional extra data.</param>
        /// <param name="tx_pubKey">Pubkey which can sign all the addresses in `tx_fromList`, if not already known.</param>
        /// <param name="tx_blockHeight">Block number when the transaction was generated.</param>
        /// <param name="tx_nonce">Unique nonce value for the transaction.</param>
        /// <param name="sign_transaction">True if the signature should be calculated, false if the signature will be calculated later</param>
        public Transaction(int tx_type, IxiNumber tx_feePerKb, SortedDictionary<byte[], IxiNumber> tx_toList, SortedDictionary<byte[], IxiNumber> tx_fromList, byte[] tx_data, byte[] tx_pubKey, ulong tx_blockHeight, int tx_nonce = -1, bool sign_transaction = true)
        {
            setVersion();

            type = tx_type;


            toList = tx_toList;

            amount = calculateTotalAmount();

            fromList = tx_fromList;

            data = tx_data;

            blockHeight = tx_blockHeight;

            if (tx_nonce == -1)
            {
                Random r = new Random();
                nonce = (int)((DateTimeOffset.Now.ToUnixTimeMilliseconds() - (DateTimeOffset.Now.ToUnixTimeSeconds() * 1000)) * 100) + r.Next(100);
            }
            else
            {
                nonce = tx_nonce;
            }

            timeStamp = Core.getCurrentTimestamp();

            pubKey = tx_pubKey;

            fee = calculateMinimumFee(tx_feePerKb);

            generateChecksums();

            if (type == (int)Transaction.Type.StakingReward)
            {
                signature = Encoding.UTF8.GetBytes("Stake");
            }
            else
            {
                if (sign_transaction)
                {
                    signature = getSignature(checksum);
                }
            }
        }

        /// <summary>
        ///  Copy constructor.
        /// </summary>
        /// <remarks>
        ///  In some places the Ixian software requires a full copy of the transaction and not a shared reference, so
        ///  this constructor is provided to achieve that.
        /// </remarks>
        /// <param name="tx_transaction">Source transaction to copy.</param>
        public Transaction(Transaction tx_transaction)
        {
            version = tx_transaction.version;
            id = tx_transaction.id;
            type = tx_transaction.type;
            amount = new IxiNumber(tx_transaction.amount.getAmount());
            fee = new IxiNumber(tx_transaction.fee.getAmount());

            toList = new SortedDictionary<byte[], IxiNumber>(new ByteArrayComparer());

            foreach (var entry in tx_transaction.toList)
            {
                byte[] address = new byte[entry.Key.Length];
                Array.Copy(entry.Key, address, address.Length);
                toList.Add(address, new IxiNumber(entry.Value.getAmount()));
            }

            fromList = new SortedDictionary<byte[], IxiNumber>(new ByteArrayComparer());

            foreach (var entry in tx_transaction.fromList)
            {
                byte[] address = new byte[entry.Key.Length];
                Array.Copy(entry.Key, address, address.Length);
                fromList.Add(address, new IxiNumber(entry.Value.getAmount()));
            }


            if (tx_transaction.data != null)
            {
                data = new byte[tx_transaction.data.Length];
                Array.Copy(tx_transaction.data, data, data.Length);
            }

            blockHeight = tx_transaction.blockHeight;
            nonce = tx_transaction.nonce;
            timeStamp = tx_transaction.timeStamp;

            if (tx_transaction.checksum != null)
            {
                checksum = new byte[tx_transaction.checksum.Length];
                Array.Copy(tx_transaction.checksum, checksum, checksum.Length);
            }

            if (tx_transaction.signature != null)
            {
                signature = new byte[tx_transaction.signature.Length];
                Array.Copy(tx_transaction.signature, signature, signature.Length);
            }

            if (tx_transaction.pubKey != null)
            {
                pubKey = new byte[tx_transaction.pubKey.Length];
                Array.Copy(tx_transaction.pubKey, pubKey, pubKey.Length);
            }

            applied = tx_transaction.applied;

            fromLocalStorage = tx_transaction.fromLocalStorage;

            powVerified = tx_transaction.powVerified;
        }

        /// <summary>
        ///  Constructs a transaction object from the serialized transaction data. See also `getBytes()`.
        /// </summary>
        /// <param name="bytes">Byte-field with the serialized transaction</param>
        public Transaction(byte[] bytes)
        {
            try
            {
                if (bytes.Length > 512000)
                {
                    throw new Exception("Transaction size is bigger than 500kB.");
                }
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        version = reader.ReadInt32();

                        if (version <= maxVersion)
                        {

                            type = reader.ReadInt32();
                            amount = new IxiNumber(reader.ReadString());
                            fee = new IxiNumber(reader.ReadString());

                            int toListLen = reader.ReadInt32();
                            for (int i = 0; i < toListLen; i++)
                            {
                                int addrLen = reader.ReadInt32();
                                byte[] address = reader.ReadBytes(addrLen);
                                IxiNumber amount = new IxiNumber(reader.ReadString());
                                toList.Add(address, amount);
                            }

                            if (version <= 1)
                            {
                                int fromLen = reader.ReadInt32();
                                pubKey = reader.ReadBytes(fromLen);
                                fromList.Add(new byte[1] { 0 }, amount + fee);
                            }
                            else
                            {
                                int fromListLen = reader.ReadInt32();
                                for (int i = 0; i < fromListLen; i++)
                                {
                                    int addrLen = reader.ReadInt32();
                                    byte[] address = reader.ReadBytes(addrLen);
                                    IxiNumber amount = new IxiNumber(reader.ReadString());
                                    fromList.Add(address, amount);
                                }
                            }

                            int dataLen = reader.ReadInt32();
                            if (dataLen > 0)
                            {
                                data = reader.ReadBytes(dataLen);
                            }

                            blockHeight = reader.ReadUInt64();

                            nonce = reader.ReadInt32();

                            timeStamp = reader.ReadInt64();

                            int crcLen = reader.ReadInt32();
                            if (crcLen > 0)
                            {
                                checksum = reader.ReadBytes(crcLen);
                            }

                            int sigLen = reader.ReadInt32();
                            if (sigLen > 0)
                            {
                                signature = reader.ReadBytes(sigLen);
                            }

                            int pkLen = reader.ReadInt32();
                            if (pkLen > 0)
                            {
                                pubKey = reader.ReadBytes(pkLen);
                            }

                            id = generateID();
                        }else
                        {
                            throw new Exception("Unknown transaction version " + version);
                        }
                    }
                }
            }
            catch(Exception e)
            {              
                Logging.error("Exception occured while trying to construct Transaction from bytes: " + e);
                throw;
            }
        }

        /// <summary>
        ///  Serializes the transaction object for transmission and returns a byte-field. See also the constructor `Transaction(byte[])`.
        /// </summary>
        /// <returns>Byte-field with the serialized transaction, suiteable for network transmission.</returns>
        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream(832))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(version);

                    writer.Write(type);

                    writer.Write(amount.ToString());

                    writer.Write(fee.ToString());

                    writer.Write(toList.Count);
                    foreach (var entry in toList)
                    {
                        writer.Write(entry.Key.Length);
                        writer.Write(entry.Key);
                        writer.Write(entry.Value.ToString());
                    }

                    if (version <= 1)
                    {
                        byte[] tmp_address = (new Address(pubKey)).address;
                        writer.Write(tmp_address.Length);
                        writer.Write(tmp_address);
                    }else
                    {
                        writer.Write(fromList.Count);
                        foreach (var entry in fromList)
                        {
                            writer.Write(entry.Key.Length);
                            writer.Write(entry.Key);
                            writer.Write(entry.Value.ToString());
                        }
                    }

                    if (data != null)
                    {
                        writer.Write(data.Length);
                        writer.Write(data);
                    }else
                    {
                        writer.Write((int)0);
                    }
                    writer.Write(blockHeight);
                    writer.Write(nonce);

                    writer.Write(timeStamp);

                    if (checksum != null)
                    {
                        writer.Write(checksum.Length);
                        writer.Write(checksum);
                    }
                    else
                    {
                        writer.Write((int)0);
                    }

                    if (signature != null)
                    {
                        writer.Write(signature.Length);
                        writer.Write(signature);
                    }else
                    {
                        writer.Write((int)0);
                    }

                    if ((version <= 1 && pubKey != null && pubKey.Length > 36)
                        || version >= 2)
                    {
                        writer.Write(pubKey.Length);
                        writer.Write(pubKey);
                    }else
                    {
                        writer.Write((int)0);
                    }
#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("Transaction::getBytes: {0}", m.Length));
#endif
                }
                return m.ToArray();
            }
        }

        /// <summary>
        ///  Checks if the two transactions are exactly equal.
        /// </summary>
        /// <param name="tx">Other transaction.</param>
        /// <returns>True if both objects represent the same Ixian transaction.</returns>
        public bool equals(Transaction tx)
        {
            byte[] a1 = getBytes();
            byte[] a2 = tx.getBytes();

            return a1.SequenceEqual(a2);
        }

        /// <summary>
        ///  Checks the transaction's signature against the given public key and address nonce.
        /// </summary>
        /// <param name="pubkey">Public key which signed the transaction</param>
        /// <param name="nonce">Nonce value of the originating wallet.</param>
        /// <returns>True if the signature is valid.</returns>
        public bool verifySignature(byte[] pubkey, byte[] nonce)
        {
            if(pubkey == null)
            {
                return false;
            }

            // Skip signature verification for staking rewards
            if (type == (int)Type.StakingReward || type == (int)Type.Genesis)
            {
                return true;
            }

            Address p_address = new Address(pubkey, nonce);
            bool allowed = false;
            Wallet from_wallet = IxianHandler.getWallet((new Address(this.pubKey)).address);
            if(from_wallet != null && from_wallet.id.SequenceEqual(p_address.address))
            {
                allowed = true;
            } else if (type == (int)Transaction.Type.MultisigTX || type == (int)Transaction.Type.ChangeMultisigWallet || type == (int)Transaction.Type.MultisigAddTxSignature)
            {
                // pubkey must be one of the allowed signers on wallet
                if(from_wallet.allowedSigners != null)
                {
                    foreach(var allowed_signer in from_wallet.allowedSigners)
                    {
                        if(allowed_signer.SequenceEqual(p_address.address))
                        {
                            allowed = true;
                        }
                    }
                }
            }

            if (!allowed) return false;

            if(signature == null || pubkey == null)
            {
                Logging.warn("Signature or pubkey for received txid {0} was null, verification failed.", id);
                return false;
            }

            // Verify the signature
            return CryptoManager.lib.verifySignature(checksum, pubkey, signature);
        }

        /// <summary>
        ///  Generates the Transaction ID from the transaction data.
        /// </summary>
        /// <returns>TXID</returns>
        public string generateID()
        {
            string txid = "";

            if(type == (int)Type.StakingReward)
            {

                if (data != null)
                {
                    ulong blockNum = BitConverter.ToUInt64(data, 0);
                    if (blockNum > 0)
                    {
                        txid = "stk-" + blockNum + "-";
                    }
                }
            }

            txid += blockHeight + "-";

            List<byte> rawData = new List<byte>();
            rawData.AddRange(BitConverter.GetBytes(type));
            rawData.AddRange(Encoding.UTF8.GetBytes(amount.ToString()));
            rawData.AddRange(Encoding.UTF8.GetBytes(fee.ToString()));

            if (toList.Count == 1)
            {
                rawData.AddRange(toList.ToArray()[0].Key);
            }
            else
            {
                foreach (var entry in toList)
                {
                    rawData.AddRange(entry.Key);
                    rawData.AddRange(entry.Value.getAmount().ToByteArray());
                }
            }

            if (fromList.Count == 1)
            {
                rawData.AddRange(new Address(pubKey).address);
            }
            else
            {
                foreach (var entry in fromList)
                {
                    rawData.AddRange(entry.Key);
                    rawData.AddRange(entry.Value.getAmount().ToByteArray());
                }
                rawData.AddRange(new Address(pubKey).address);
            }

            rawData.AddRange(BitConverter.GetBytes(blockHeight));
            rawData.AddRange(BitConverter.GetBytes(nonce));
            rawData.AddRange(BitConverter.GetBytes((int)0)); // version was replaced with this, as it's tx metadata and shouldn't be part of the ID
            string chk = null;
            if (version <= 2)
            {
                chk = Base58Check.Base58CheckEncoding.EncodePlain(Crypto.sha512quTrunc(rawData.ToArray()));
            }else
            {
                chk = Base58Check.Base58CheckEncoding.EncodePlain(Crypto.sha512sqTrunc(rawData.ToArray()));
            }

            txid += chk;

            return txid;
        }

        /// <summary>
        ///  Calculates the transaction's checksum.
        /// </summary>
        /// <param name="transaction">Transaction to calculate the checksum from.</param>
        /// <returns>Byte-field with the checksum value.</returns>
        public static byte[] calculateChecksum(Transaction transaction)
        {
            List<byte> rawData = new List<byte>();
            rawData.AddRange(ConsensusConfig.ixianChecksumLock);
            rawData.AddRange(Encoding.UTF8.GetBytes(transaction.id));
            rawData.AddRange(BitConverter.GetBytes(transaction.type));
            rawData.AddRange(Encoding.UTF8.GetBytes(transaction.amount.ToString()));
            rawData.AddRange(Encoding.UTF8.GetBytes(transaction.fee.ToString()));
            if (transaction.toList.Count == 1)
            {
                rawData.AddRange(transaction.toList.ToArray()[0].Key);
            }
            else
            {
                foreach (var entry in transaction.toList)
                {
                    rawData.AddRange(entry.Key);
                    rawData.AddRange(entry.Value.getAmount().ToByteArray());
                }
            }

            if (transaction.fromList.Count == 1)
            {
                rawData.AddRange(new Address(transaction.pubKey).address);
            }else
            {
                foreach (var entry in transaction.fromList)
                {
                    rawData.AddRange(entry.Key);
                    rawData.AddRange(entry.Value.getAmount().ToByteArray());
                }
            }

            if (transaction.data != null)
            {
                rawData.AddRange(transaction.data);
            }

            rawData.AddRange(BitConverter.GetBytes(transaction.blockHeight));
            rawData.AddRange(BitConverter.GetBytes(transaction.nonce));
            rawData.AddRange(BitConverter.GetBytes(transaction.timeStamp));
            rawData.AddRange(BitConverter.GetBytes(transaction.version));
            if((transaction.version <= 1 && transaction.pubKey != null && transaction.pubKey.Length > 36)
                || transaction.version >= 2)
            {
                rawData.AddRange(transaction.pubKey);
            }
            if (transaction.version <= 2)
            {
                return Crypto.sha512quTrunc(rawData.ToArray());
            }else
            {
                return Crypto.sha512sqTrunc(rawData.ToArray());
            }
        }

        /// <summary>
        ///  Calculates the signature for the transaction.
        /// </summary>
        /// <param name="checksum">Transaction checksum.</param>
        /// <param name="private_key">Private key with which to sign the transaction, or null if the primary key should be used.</param>
        /// <returns>Transaction signature in a byte-field.</returns>
        public byte[] getSignature(byte[] checksum, byte[] private_key = null)
        {
            if(private_key != null)
            {
                return CryptoManager.lib.getSignature(checksum, private_key);
            }

            byte[] address =  new Address(pubKey).address;

            IxianKeyPair kp = IxianHandler.getWalletStorage().getKeyPair(address);
            if (kp != null)
            {
                return CryptoManager.lib.getSignature(checksum, kp.privateKeyBytes);
            }
            return null;
        }

        /// <summary>
        ///  Calculates the total transaction amount, without fee.
        /// </summary>
        /// <returns>Sum of all deposits in the transaction's `toList`.</returns>
        public IxiNumber calculateTotalAmount()
        {
            IxiNumber total = new IxiNumber(0);
            foreach(var entry in toList)
            {
                total += entry.Value;
            }
            return total;
        }

        /// <summary>
        ///  Calculates the transaction checksum and stores it in the transaction.
        /// </summary>
        public void generateChecksums()
        {
            id = generateID();
            checksum = calculateChecksum(this);
        }

        /// <summary>
        ///  Calculates the lowest possible transaction fee based on the size of the transaction.
        /// </summary>
        /// <param name="pricePerKb">Price per kilobyte of data.</param>
        /// <returns>Minimum fee given the specified price per kilobyte.</returns>
        public IxiNumber calculateMinimumFee(IxiNumber pricePerKb)
        {
            int bytesLen = getBytes().Length;
            if (checksum == null)
            {
                bytesLen += 32;
            }
            if (signature == null)
            {
                bytesLen += 512;
            }
            IxiNumber expectedFee = pricePerKb * (ulong)Math.Ceiling((double)bytesLen / 1000);
            return expectedFee;
        }

        /// <summary>
        ///  Appends a signature for the given multisig transaction.
        /// </summary>
        /// <param name="orig_txid">Original multisig transaction's ID.</param>
        /// <param name="signer_pub_key">Public key of the additional signer.</param>
        /// <param name="signer_nonce">Nonce value of the wallet which is allowed to sign `orig_txid` and can be signed with the `signer_pub_key`.</param>
        private void AddMultisigOrig(string orig_txid, byte[] signer_pub_key, byte[] signer_nonce)
        {
            byte[] orig_txid_bytes = null;
            if (orig_txid != null && orig_txid != "")
            {
                orig_txid_bytes = Encoding.UTF8.GetBytes(orig_txid);
            }
            using (MemoryStream ms = new MemoryStream())
            {
                using (BinaryWriter bw = new BinaryWriter(ms))
                {
                    bw.Write(multisigStartMarker[0]);
                    bw.Write(multisigStartMarker[1]);
                    if (orig_txid_bytes == null)
                    {
                        bw.Write((int)0);
                    }
                    else
                    {
                        bw.Write(orig_txid_bytes.Length);
                        bw.Write(orig_txid_bytes);
                    }

                    bw.Write(signer_pub_key.Length);
                    bw.Write(signer_pub_key);

                    bw.Write(signer_nonce.Length);
                    bw.Write(signer_nonce);
#if TRACE_MEMSTREAM_SIZES
                        Logging.info(String.Format("Transaction::AddMultisigOrig: {0}", ms.Length));
#endif

                    data = ms.ToArray();
                }
            }
        }

        /// <summary>
        ///  Encodes information to add or delete an allowed signer from a multisig wallet.
        /// </summary>
        /// <param name="addr">Address to add or remove.</param>
        /// <param name="change_type">Operation - add or remove.</param>
        /// <param name="signer_pub_key">Signer, who is already on the multisig wallet's allowed list.</param>
        /// <param name="signer_nonce">Nonce value of the wallet which is allowed to make changes to the multisig wallet and can be signed with the `signer_pub_key`.</param>
        private void AddMultisigChWallet(byte[] addr, MultisigWalletChangeType change_type, byte[] signer_pub_key, byte[] signer_nonce)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                using (BinaryWriter bw = new BinaryWriter(ms))
                {
                    bw.Write(multisigStartMarker[0]);
                    bw.Write(multisigStartMarker[1]);
                    bw.Write((byte)change_type);

                    bw.Write(addr.Length);
                    bw.Write(addr);

                    bw.Write(signer_pub_key.Length);
                    bw.Write(signer_pub_key);

                    bw.Write(signer_nonce.Length);
                    bw.Write(signer_nonce);
#if TRACE_MEMSTREAM_SIZES
                        Logging.info(String.Format("Transaction::AddMultisigChWallet: {0}", ms.Length));
#endif

                    data = ms.ToArray();
                }
            }
        }

        /// <summary>
        ///  Encodes information to change the number of required signatures on a multisig wallet.
        /// </summary>
        /// <param name="addr">New number of signatures.</param>
        /// <param name="signer_pub_key">Signer, who is on the multisig wallet's allowed list.</param>
        /// <param name="signer_nonce">Nonce value of the wallet which is allowed to make changes to the multisig wallet and can be signed with the `signer_pub_key`.</param>
        private void AddMultisigChReqSigs(byte num_sigs, byte[] signer_pub_key, byte[] signer_nonce)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                using (BinaryWriter bw = new BinaryWriter(ms))
                {
                    bw.Write(multisigStartMarker[0]);
                    bw.Write(multisigStartMarker[1]);
                    bw.Write((byte)MultisigWalletChangeType.ChangeReqSigs);

                    bw.Write(num_sigs);

                    bw.Write(signer_pub_key.Length);
                    bw.Write(signer_pub_key);

                    bw.Write(signer_nonce.Length);
                    bw.Write(signer_nonce);
#if TRACE_MEMSTREAM_SIZES
                        Logging.info(String.Format("Transaction::AddMultisigChReqSigs: {0}", ms.Length));
#endif

                    data = ms.ToArray();
                }
            }
        }

        /// <summary>
        ///  Reads the transaction's optional data and attempts to parse it as a multisig transaction data.
        /// </summary>
        /// <returns>Multisig transaction data, or null if no valid object was found.</returns>
        private object getMultisigTxData()
        {
            if (data == null || data.Length < 6)
            {
                return null;
            }
            using (MemoryStream ms = new MemoryStream(data))
            {
                using (BinaryReader rd = new BinaryReader(ms))
                {
                    try
                    {
                        byte start_marker_1 = rd.ReadByte();
                        byte start_marker_2 = rd.ReadByte();
                        if (start_marker_1 != multisigStartMarker[0] || start_marker_2 != multisigStartMarker[1])
                        {
                            Logging.warn(String.Format("Multisig transaction: Invalid multisig transaction: Data start marker does not match! ({0}, {1})", start_marker_1, start_marker_2));
                            return null;
                        }

                        int orig_tx_len = rd.ReadInt32();
                        if (orig_tx_len < 0 || orig_tx_len > 100)
                        {
                            Logging.warn(String.Format("Multisig transaction: Invalid origin TXID length stored in data: {0}", orig_tx_len));
                            return null;
                        }
                        byte[] orig_txid = null;
                        if (orig_tx_len > 0)
                        {
                            orig_txid = rd.ReadBytes(orig_tx_len);
                            if (orig_txid == null || orig_txid.Length < orig_tx_len)
                            {
                                Logging.warn(String.Format("Multisig transaction: Invalid or missing origin txid!"));
                                return null;
                            }
                        }
                        else
                        {
                            orig_txid = Encoding.UTF8.GetBytes("");
                        }

                        int signer_pub_key_len = rd.ReadInt32();
                        if (signer_pub_key_len < 36 || signer_pub_key_len > 2500)
                        {
                            Logging.warn(String.Format("Multisig transaction: Invalid signer pub key length stored in data: {0}", signer_pub_key_len));
                            return null;
                        }
                        if (signer_pub_key_len == 0)
                        {
                            return null;
                        }
                        byte[] signer_pub_key = rd.ReadBytes(signer_pub_key_len);
                        if (signer_pub_key == null || signer_pub_key.Length < signer_pub_key_len)
                        {
                            Logging.warn(String.Format("Multisig transaction: Invalid or missing signer pub key!"));
                            return null;
                        }

                        int signer_nonce_len = rd.ReadInt32();
                        if (signer_nonce_len > 16)
                        {
                            Logging.warn(String.Format("Multisig transaction: Invalid signer nonce length stored in data: {0}", signer_nonce_len));
                            return null;
                        }
                        byte[] signer_nonce = rd.ReadBytes(signer_nonce_len);

                        return new MultisigTxData
                        {
                            origTXId = Encoding.UTF8.GetString(orig_txid),
                            signerPubKey = signer_pub_key,
                            signerNonce = signer_nonce
                        };
                    }
                    catch (Exception)
                    {
                        // early EOF or some strange data error
                        return null;
                    }
                }
            }
        }

        /// <summary>
        ///  Reads the transaction's optional data and attempts to parse it as a multisig change data.
        /// </summary>
        /// <returns>One of the multisig change data objects, or null if no valid object was found.</returns>
        private object getChangeMultisigWalletData()
        {
            if (data == null || data.Length < 6)
            {
                return null;
            }
            using (MemoryStream ms = new MemoryStream(data))
            {
                using (BinaryReader rd = new BinaryReader(ms))
                {
                    try
                    {
                        byte start_marker_1 = rd.ReadByte();
                        byte start_marker_2 = rd.ReadByte();
                        if (start_marker_1 != multisigStartMarker[0] || start_marker_2 != multisigStartMarker[1])
                        {
                            Logging.warn(String.Format("Multisig change transaction: Invalid multisig transaction: Data start marker does not match! ({0}, {1})", start_marker_1, start_marker_2));
                            return null;
                        }
                        // multisig change type
                        MultisigWalletChangeType change_type = (MultisigWalletChangeType)rd.ReadByte();
                        switch (change_type)
                        {
                            case MultisigWalletChangeType.AddSigner:
                                int ch_addr_len = rd.ReadInt32();
                                if (ch_addr_len < 36 || ch_addr_len > 128)
                                {
                                    Logging.warn("Multisig change transaction: Adding signer, but the data does not contain a valid address!");
                                    return null;
                                }
                                byte[] ch_addr = rd.ReadBytes(ch_addr_len);
                                if (ch_addr == null || ch_addr.Length < ch_addr_len)
                                {
                                    Logging.warn("Multisig change transaction: Adding signer, but the address data was corrupted.");
                                    return null;
                                }

                                int signer_pub_key_len = rd.ReadInt32();
                                if (signer_pub_key_len < 36 || signer_pub_key_len > 2500)
                                {
                                    Logging.warn(String.Format("Multisig transaction: Invalid signer pub key length stored in data: {0}", signer_pub_key_len));
                                    return null;
                                }
                                if (signer_pub_key_len == 0)
                                {
                                    return null;
                                }
                                byte[] signer_pub_key = rd.ReadBytes(signer_pub_key_len);

                                int signer_nonce_len = rd.ReadInt32();
                                if (signer_nonce_len > 16)
                                {
                                    Logging.warn(String.Format("Multisig transaction: Invalid signer nonce length stored in data: {0}", signer_nonce_len));
                                    return null;
                                }
                                byte[] signer_nonce = rd.ReadBytes(signer_nonce_len);

                                return new MultisigAddrAdd
                                {
                                    addrToAdd = ch_addr,
                                    signerPubKey = signer_pub_key,
                                    signerNonce = signer_nonce
                                };
                            case MultisigWalletChangeType.DelSigner:
                                ch_addr_len = rd.ReadInt32();
                                if (ch_addr_len < 36 || ch_addr_len > 128)
                                {
                                    Logging.warn("Multisig change transaction: Deleting signer, but the data does not contain a valid address!");
                                    return null;
                                }
                                ch_addr = rd.ReadBytes(ch_addr_len);
                                if (ch_addr == null || ch_addr.Length < ch_addr_len)
                                {
                                    Logging.warn("Multisig change transaction: Deleting signer, but the address data was corrupted.");
                                    return null;
                                }

                                signer_pub_key_len = rd.ReadInt32();
                                if (signer_pub_key_len < 36 || signer_pub_key_len > 2500)
                                {
                                    Logging.warn(String.Format("Multisig transaction: Invalid signer pub key length stored in data: {0}", signer_pub_key_len));
                                    return null;
                                }
                                if (signer_pub_key_len == 0)
                                {
                                    return null;
                                }
                                signer_pub_key = rd.ReadBytes(signer_pub_key_len);

                                signer_nonce_len = rd.ReadInt32();
                                if (signer_nonce_len > 16)
                                {
                                    Logging.warn(String.Format("Multisig transaction: Invalid signer nonce length stored in data: {0}", signer_nonce_len));
                                    return null;
                                }
                                signer_nonce = rd.ReadBytes(signer_nonce_len);

                                return new MultisigAddrDel
                                {
                                    addrToDel = ch_addr,
                                    signerPubKey = signer_pub_key,
                                    signerNonce = signer_nonce
                                };
                            case MultisigWalletChangeType.ChangeReqSigs:
                                byte new_req_sigs = rd.ReadByte();

                                signer_pub_key_len = rd.ReadInt32();
                                if (signer_pub_key_len < 36 || signer_pub_key_len > 2500)
                                {
                                    Logging.warn(String.Format("Multisig transaction: Invalid signer pub key length stored in data: {0}", signer_pub_key_len));
                                    return null;
                                }
                                if (signer_pub_key_len == 0)
                                {
                                    return null;
                                }
                                signer_pub_key = rd.ReadBytes(signer_pub_key_len);

                                signer_nonce_len = rd.ReadInt32();
                                if (signer_nonce_len > 16)
                                {
                                    Logging.warn(String.Format("Multisig transaction: Invalid signer nonce length stored in data: {0}", signer_nonce_len));
                                    return null;
                                }
                                signer_nonce = rd.ReadBytes(signer_nonce_len);

                                return new MultisigChSig
                                {
                                    reqSigs = new_req_sigs,
                                    signerPubKey = signer_pub_key,
                                    signerNonce = signer_nonce
                                };
                            default:
                                Logging.warn(String.Format("Invalid MultisigWalletChangeType for a multisig change transaction {{ {0} }}.", id));
                                return null;
                        }
                    }
                    catch (Exception)
                    {
                        // early EOL or strange data error
                        return null;
                    }
                }
            }
        }

        /// <summary>
        ///  Wrapper function to attempt and parse the transaction's optional data field as some kind of Multisig object.
        /// </summary>
        /// <returns>A multisig data object, if found, or null.</returns>
        public object GetMultisigData()
        {
            if (type == (int)Transaction.Type.MultisigTX || type == (int)Transaction.Type.MultisigAddTxSignature)
            {
                return getMultisigTxData();
            }
            else if (type == (int)Transaction.Type.ChangeMultisigWallet)
            {
                return getChangeMultisigWalletData();
            }
            else
            {
                Logging.info(String.Format("Transaction {{ {0} }} is not a multisig transaction, so MultisigData cannot be retrieved.", id));
                return null;
            }
        }

        /// <summary>
        ///  Checks owned addresses and returns the first one which is allowed to sign transactions for `multisig_address`.
        /// </summary>
        /// <param name="multisig_address">Multisig address to check.</param>
        /// <returns>Own address which is allowed to sign transactions for `multisig_address`, or null, if no such local address.</returns>
        public static AddressData findMyMultisigAddressData(byte[] multisig_address)
        {
            AddressData ad = IxianHandler.getWalletStorage().getAddress(multisig_address);
            if (ad != null)
            {
                return ad;
            }

            Wallet w = IxianHandler.getWallet(multisig_address);
            if (w == null)
            {
                return null;
            }

            if (w.allowedSigners != null)
            {
                foreach(var entry in w.allowedSigners)
                {
                    AddressData tmp_ad = IxianHandler.getWalletStorage().getAddress(entry);
                    if(tmp_ad != null)
                    {
                        return tmp_ad;
                    }
                }
            }

            if (CoreConfig.isTestNet)
            {
                // exploit test
                return IxianHandler.getWalletStorage().getAddress(IxianHandler.getWalletStorage().getPrimaryAddress());
            }

            return null;
        }

        /// <summary>
        ///  Generates a multisig transaction.
        /// </summary>
        /// <param name="tx_amount">Amount of Ixi to widthraw and deposit.</param>
        /// <param name="tx_fee">Transaction fee</param>
        /// <param name="tx_to">Destination address where the funds should be deposited.</param>
        /// <param name="tx_from">Multisig wallet where the funds should be withdrawn.</param>
        /// <param name="tx_blockHeight">Blockheight at which the transaction is generated.</param>
        /// <returns>Generated transaction object.</returns>
        public static Transaction multisigTransaction(IxiNumber tx_amount, IxiNumber tx_fee, byte[] tx_to, byte[] tx_from, ulong tx_blockHeight)
        {
            Transaction t = new Transaction((int)Transaction.Type.MultisigTX, tx_amount, tx_fee, tx_to, tx_from, null, tx_from, tx_blockHeight);

            // TODO TODO TODO TODO TODO TODO make this compatible with wallet v3

            AddressData ad = findMyMultisigAddressData(tx_from);
            if(ad == null)
            {
                return null;
            }

            t.AddMultisigOrig(null, ad.keyPair.publicKeyBytes, ad.nonce);

            t.fee = t.calculateMinimumFee(tx_fee);
            t.fromList[t.fromList.First().Key] = tx_amount + t.fee;

            t.generateChecksums();

            t.signature = t.getSignature(t.checksum);

            return t;
        }

        /// <summary>
        ///  Generates a multisig transaction with multiple destination addresses.
        /// </summary>
        /// <param name="tx_fee">Transaction fee</param>
        /// <param name="tx_to_list">Destination addresses where the funds should be deposited.</param>
        /// <param name="tx_from">Multisig wallet where the funds should be withdrawn.</param>
        /// <param name="tx_blockHeight">Blockheight at which the transaction is generated.</param>
        /// <returns>Generated transaction object.</returns>
        public static Transaction multisigTransaction(IxiNumber tx_fee, SortedDictionary<byte[], IxiNumber> tx_to_list, byte[] tx_from, ulong tx_blockHeight)
        {
            Transaction t = new Transaction((int)Transaction.Type.MultisigTX, tx_fee, tx_to_list, tx_from, null, tx_from, tx_blockHeight);

            // TODO TODO TODO TODO TODO TODO make this compatible with wallet v3

            AddressData ad = findMyMultisigAddressData(tx_from);
            if (ad == null)
            {
                return null;
            }

            t.AddMultisigOrig(null, ad.keyPair.publicKeyBytes, ad.nonce);

            t.fee = t.calculateMinimumFee(tx_fee);
            t.fromList[t.fromList.First().Key] = t.amount + t.fee;

            t.generateChecksums();

            t.signature = t.getSignature(t.checksum, ad.keyPair.privateKeyBytes);

            return t;
        }

        /// <summary>
        ///  Adds a signature to the specified multisig transaction, if possible.
        ///  This function generates a transaction which adds the signature for `orig_txid`.
        /// </summary>
        /// <param name="orig_txid">Multisig transaction which is waiting to accumulate signatures.</param>
        /// <param name="tx_fee">Fee per kilobyte of data.</param>
        /// <param name="tx_from">Own address which may be allowed to sign `orig_txid`.</param>
        /// <param name="tx_blockHeight">Block height at which to generate the new transaction/</param>
        /// <returns>Signing transaction.</returns>
        public static Transaction multisigAddTxSignature(string orig_txid, IxiNumber tx_fee, byte[] tx_from, ulong tx_blockHeight)
        {
            Transaction t = new Transaction((int)Transaction.Type.MultisigAddTxSignature, new IxiNumber(0), tx_fee, tx_from, tx_from, null, tx_from, tx_blockHeight);

            // TODO TODO TODO TODO TODO TODO make this compatible with wallet v3

            AddressData ad = findMyMultisigAddressData(tx_from);
            if (ad == null)
            {
                return null;
            }

            t.AddMultisigOrig(orig_txid, ad.keyPair.publicKeyBytes, ad.nonce);

            t.fee = t.calculateMinimumFee(tx_fee);
            t.fromList[t.fromList.First().Key] = t.fee;

            t.generateChecksums();

            t.signature = t.getSignature(t.checksum, ad.keyPair.privateKeyBytes);

            return t;
        }

        /// <summary>
        ///  Adds a signature to the specified multisig wallet.
        ///  This function generates a transaction which adds the specified `allowed_address` to the multisig wallet `tx_from`.
        /// </summary>
        ///  The transaction fee is paid by `tx_from` - the multisig wallet.
        /// </remarks>
        /// <param name="allowed_address">Address which will be added to `tx_from`.</param>
        /// <param name="tx_fee">Fee per kilobyte of data.</param>
        /// <param name="tx_from">Multisig address where the `allowed_address` will be added.</param>
        /// <param name="tx_blockHeight">Block height at which to generate the new transaction/</param>
        /// <returns>Multisig change transaction.</returns>
        public static Transaction multisigAddKeyTransaction(byte[] allowed_address,  IxiNumber tx_fee, byte[] tx_from, ulong tx_blockHeight)
        {
            Transaction t = new Transaction((int)Transaction.Type.ChangeMultisigWallet, new IxiNumber(0), tx_fee, tx_from, tx_from, null, tx_from, tx_blockHeight);

            // TODO TODO TODO TODO TODO TODO make this compatible with wallet v3

            AddressData ad = findMyMultisigAddressData(tx_from);
            if (ad == null)
            {
                return null;
            }

            t.AddMultisigChWallet(allowed_address, MultisigWalletChangeType.AddSigner, ad.keyPair.publicKeyBytes, ad.nonce);

            t.fee = t.calculateMinimumFee(tx_fee);
            t.fromList[t.fromList.First().Key] = t.fee;

            t.generateChecksums();

            t.signature = t.getSignature(t.checksum, ad.keyPair.privateKeyBytes);

            return t;
        }

        /// <summary>
        ///  Deletes a signature from the specified multisig wallet.
        ///  This function generates a transaction which deletes the specified `disallowed_address` from the multisig wallet `tx_from`.
        /// </summary>
        ///  The transaction fee is paid by `tx_from` - the multisig wallet.
        /// </remarks>
        /// <param name="disallowed_address">Address which will be removed from `tx_from`.</param>
        /// <param name="tx_fee">Fee per kilobyte of data.</param>
        /// <param name="tx_from">Multisig address where the `allowed_address` will be added.</param>
        /// <param name="tx_blockHeight">Block height at which to generate the new transaction/</param>
        /// <returns>Multisig change transaction.</returns>
        public static Transaction multisigDelKeyTransaction(byte[] disallowed_address, IxiNumber tx_fee, byte[] tx_from, ulong tx_blockHeight)
        {
            Transaction t = new Transaction((int)Transaction.Type.ChangeMultisigWallet, new IxiNumber(0), tx_fee, tx_from, tx_from, null, tx_from, tx_blockHeight);

            // TODO TODO TODO TODO TODO TODO make this compatible with wallet v3

            AddressData ad = findMyMultisigAddressData(tx_from);
            if (ad == null)
            {
                return null;
            }

            t.AddMultisigChWallet(disallowed_address, MultisigWalletChangeType.DelSigner, ad.keyPair.publicKeyBytes, ad.nonce);

            t.fee = t.calculateMinimumFee(tx_fee);
            t.fromList[t.fromList.First().Key] = t.fee;

            t.generateChecksums();

            t.signature = t.getSignature(t.checksum, ad.keyPair.privateKeyBytes);

            return t;
        }

        /// <summary>
        ///  Changes the multisig wallet minimum required signatures value.
        ///  This function generates a transaction which changes the specified multisig wallet `tx_from` with a new minimum
        ///  required signatures value..
        /// </summary>
        ///  The transaction fee is paid by `tx_from` - the multisig wallet.
        /// </remarks>
        /// <param name="sigs">New minimum required signatures value for `tx_from`.</param>
        /// <param name="tx_fee">Fee per kilobyte of data.</param>
        /// <param name="tx_from">Multisig address where the `allowed_address` will be added.</param>
        /// <param name="tx_blockHeight">Block height at which to generate the new transaction/</param>
        /// <returns>Multisig change transaction.</returns>
        public static Transaction multisigChangeReqSigs(byte sigs, IxiNumber tx_fee, byte[] tx_from, ulong tx_blockHeight)
        {
            Transaction t = new Transaction((int)Transaction.Type.ChangeMultisigWallet, new IxiNumber(0), tx_fee, tx_from, tx_from, null, tx_from, tx_blockHeight);

            // TODO TODO TODO TODO TODO TODO make this compatible with wallet v3

            AddressData ad = findMyMultisigAddressData(tx_from);
            if (ad == null)
            {
                return null;
            }

            t.AddMultisigChReqSigs(sigs, ad.keyPair.publicKeyBytes, ad.nonce);

            t.fee = t.calculateMinimumFee(tx_fee);
            t.fromList[t.fromList.First().Key] = t.fee;

            t.generateChecksums();

            t.signature = t.getSignature(t.checksum, ad.keyPair.privateKeyBytes);

            return t;
        }

        /// <summary>
        ///  Encodes all transaction data fields into a Dictionary for easier conversion to JSON via the REST API server.
        /// </summary>
        /// <returns>Dictionary with all transaction fields.</returns>
        public Dictionary<string, object> toDictionary()
        {
            Dictionary<string, object> tDic = new Dictionary<string, object>();
            tDic.Add("id", id);
            tDic.Add("version", version);
            tDic.Add("blockHeight", blockHeight.ToString());
            tDic.Add("nonce", nonce.ToString());

            if (signature != null)
            {
                tDic.Add("signature", Crypto.hashToString(signature));
            }

            if (pubKey != null)
            {
                tDic.Add("pubKey", Base58Check.Base58CheckEncoding.EncodePlain(pubKey));
            }

            if (data != null)
            {
                tDic.Add("data", Crypto.hashToString(data));
            }

            tDic.Add("timestamp", timeStamp.ToString());
            tDic.Add("type", type.ToString());
            tDic.Add("amount", amount.ToString());
            tDic.Add("applied", applied.ToString());
            tDic.Add("checksum", Crypto.hashToString(checksum));

            Dictionary<string, string> fromListDic = new Dictionary<string, string>();
            foreach (var entry in fromList)
            {
                fromListDic.Add(Base58Check.Base58CheckEncoding.EncodePlain(entry.Key), entry.Value.ToString());
            }
            tDic.Add("from", fromListDic);

            Dictionary<string, string> toListDic = new Dictionary<string, string>();
            foreach (var entry in toList)
            {
                toListDic.Add(Base58Check.Base58CheckEncoding.EncodePlain(entry.Key), entry.Value.ToString());
            }
            tDic.Add("to", toListDic);

            tDic.Add("fee", fee.ToString());
            tDic.Add("totalAmount", (amount + fee).ToString());

            return tDic;
        }
    }
}