// Copyright (C) 2017-2024 Ixian OU
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
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace IXICore.Journal
{
    public abstract class JournalEntry
    {
        public byte[] targetWallet { get; protected set; }

        public virtual byte[] checksum()
        {
            return Crypto.sha512sqTrunc(getBytes());
        }

        public virtual byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream(64))
            {
                using (BinaryWriter w = new BinaryWriter(m))
                {
                    writeBytes(w);
                    return m.ToArray();
                }
            }
        }
        public abstract void writeBytes(BinaryWriter w);
        public abstract bool apply();
        public abstract bool revert();
        public virtual string toString()
        {
            return targetWallet.ToString() + ": " + this.GetType().Name;
        }
    }

    public class JournalTransaction
    {
        protected readonly List<JournalEntry> entries = new List<JournalEntry>();

        public ulong journalTxNumber { get; protected set; }

        public JournalTransaction(ulong number)
        {
            journalTxNumber = number;
        }

        protected JournalTransaction()
        {

        }

        public bool apply()
        {
            lock (entries)
            {
                foreach (var e in entries)
                {
                    if (e.apply() == false)
                    {
                        Logging.error("Error while applying Journal transaction.");
                        return false;
                    }
                }
            }
            return true;
        }

        public bool revert()
        {
            lock (entries)
            {
                foreach (var e in entries.AsEnumerable().Reverse())
                {
                    if (e.revert() == false)
                    {
                        Logging.error("Error while reverting Journal transaction.");
                    }
                }
            }
            return true;
        }

        public void addChange(JournalEntry entry)
        {
            lock (entries)
            {
                entries.Add(entry);
            }
        }

        public byte[] getBytes()
        {
            lock (entries)
            {
                // 144 = guid + before checksum + after checksum
                // entries are 64 bytes on average
                using (MemoryStream m = new MemoryStream(144 + 80 * entries.Count))
                {
                    using (BinaryWriter w = new BinaryWriter(m))
                    {
                        w.Write(journalTxNumber);

                        w.Write(entries.Count);
                        foreach (var e in entries)
                        {
                            e.writeBytes(w);
                        }

                        return m.ToArray();
                    }
                }
            }
        }
    }

    public class GenericJournal
    {
        protected readonly object stateLock = new object();

        protected JournalTransaction currentTransaction = null;
        protected List<JournalTransaction> processedJournalTransactions = new List<JournalTransaction>(); // keep last Journal states for block reorg purposes
        public bool inTransaction { get; protected set; } = false;

        protected bool beginTransaction(ulong blockNum, bool inTransaction = true)
        {
            lock (stateLock)
            {
                if (currentTransaction != null)
                {
                    // Transaction is already open
                    return false;
                }
                var tx = new JournalTransaction(blockNum);
                currentTransaction = tx;
                this.inTransaction = inTransaction;
                return true;
            }
        }

        public bool commitTransaction(ulong transactionId)
        {
            if (transactionId == 0)
            {
                return false;
            }
            // data has already been changed in the WalletState directly
            lock (stateLock)
            {
                processedJournalTransactions.Add(currentTransaction);
                if (processedJournalTransactions.Count > 10)
                {
                    processedJournalTransactions.RemoveAt(0);
                }
                currentTransaction = null;
                inTransaction = false;
                return true;
            }
        }

        public bool canRevertTransaction(ulong transactionId)
        {
            if (transactionId == 0)
            {
                return false;
            }
            lock (stateLock)
            {
                if (currentTransaction != null && currentTransaction.journalTxNumber == transactionId)
                {
                    return true;
                }
                else
                {
                    JournalTransaction jtx = processedJournalTransactions.Find(x => x.journalTxNumber == transactionId);
                    if (jtx == null)
                    {
                        return false;
                    }
                    return true;
                }
            }
        }

        public virtual bool revertTransaction(ulong transactionId)
        {
            if (transactionId == 0)
            {
                return false;
            }
            lock (stateLock)
            {
                bool result = false;
                if (currentTransaction != null && currentTransaction.journalTxNumber == transactionId)
                {
                    JournalTransaction jtx = currentTransaction;
                    result = jtx.revert();
                    currentTransaction = null;
                    inTransaction = false;
                }
                else
                {
                    JournalTransaction jtx = processedJournalTransactions.Find(x => x.journalTxNumber == transactionId);
                    if (jtx == null)
                    {
                        return false;
                    }
                    result = jtx.revert();
                    processedJournalTransactions.Remove(jtx);
                }
                return result;
            }
        }
    }
}
