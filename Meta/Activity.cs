﻿// Copyright (C) 2017-2020 Ixian OU
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

#if !__MOBILE__

using IXICore.Utils;
using SQLite;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading;

namespace IXICore.Meta
{
    /// <summary>
    /// Type of the stored activity item.
    /// </summary>
    public enum ActivityType
    {
        /// <summary>
        /// Transaction was received.
        /// </summary>
        TransactionReceived = 100,
        /// <summary>
        /// Transaction was generated and sent.
        /// </summary>
        TransactionSent = 101,
        /// <summary>
        /// A mining reward transaction was generated and sent.
        /// </summary>
        MiningReward = 200,
        /// <summary>
        /// A staking reward transaction was received.
        /// </summary>
        StakingReward = 201,
        /// <summary>
        /// A transaction fee was awarded.
        /// </summary>
        TxFeeReward = 202,
        /// <summary>
        /// Contact request was received.
        /// </summary>
        ContactRequest = 300
    }

    /// <summary>
    /// State of the activity.
    /// </summary>
    public enum ActivityStatus
    {
        Pending = 1,
        Final = 2,
        Error = 3
    }

    /// <summary>
    /// An activity item which describes a potentially interesting event on the DLT or S2 network.
    /// </summary>
    public class Activity
    {
        private string _id = null;
        private Dictionary<Address, IxiNumber> _cachedToListArray = new Dictionary<Address, IxiNumber>(new AddressComparer());

        public byte[] seedHash { get; set; }
        public string wallet { get; set; }
        public string from { get; set; }
        public string toList { get; set; }
        public int type { get; set; }
        public byte[] data { get; set; }
        public string value { get; set; }
        public long timestamp { get; set; }
        public int status { get; set; }
        public long blockHeight { get; set; }
        public string txid { get; set; }

        public Activity()
        {

        }

        public Activity(byte[] seed_hash, string wallet, string from, string to_list, int type, byte[] data, string value, long timestamp, int status, ulong block_height, string txid)
        {
            this.seedHash = seed_hash;
            this.wallet = wallet;
            this.from = from;
            this.toList = to_list;
            this.type = type;
            this.data = data;
            this.value = value;
            this.timestamp = timestamp;
            this.status = status;
            this.blockHeight = (long)block_height;
            this.txid = txid;
        }

        public Activity(byte[] seed_hash, string wallet, string from, IDictionary<Address, Transaction.ToEntry> to_list, int type, byte[] data, string value, long timestamp, int status, ulong block_height, string txid)
        {
            this.seedHash = seed_hash;
            this.wallet = wallet;
            this.from = from;
            setToListArray(to_list);
            this.type = type;
            this.data = data;
            this.value = value;
            this.timestamp = timestamp;
            this.status = status;
            this.blockHeight = (long)block_height;
            this.txid = txid;
        }

        public string id
        {
            get
            {
                if (_id == null)
                {
                    List<byte> raw_data = new List<byte>();
                    if (seedHash != null)
                    {
                        raw_data.AddRange(seedHash);
                    }
                    raw_data.AddRange(Encoding.UTF8.GetBytes(wallet));
                    raw_data.AddRange(Encoding.UTF8.GetBytes(from));
                    Dictionary<Address, IxiNumber> tmp_to_list = getToListAsArray();
                    foreach (var entry in tmp_to_list)
                    {
                        raw_data.AddRange(entry.Key.addressWithChecksum);
                        raw_data.AddRange(entry.Value.getAmount().ToByteArray());
                    }
                    raw_data.AddRange(BitConverter.GetBytes(type));
                    raw_data.AddRange(data);
                    // value shouldn't be part of the id, as it can change
                    raw_data.AddRange(BitConverter.GetBytes(timestamp));
                    // status shouldn't be part of the id, as it can change
                    // blockHeight shouldn't be part of the id, as it can change

                    string chk = Base58Check.Base58CheckEncoding.EncodePlain(Crypto.sha512sqTrunc(raw_data.ToArray()));

                    _id = chk;
                }
                return _id;
            }
            set
            {
                _id = value;
            }
        }

        public Dictionary<Address, IxiNumber> getToListAsArray()
        {
            if(_cachedToListArray.Count > 0)
            {
                return _cachedToListArray;
            }

            _cachedToListArray.Clear();
            string[] split_str = toList.Split(new string[] { "||" }, StringSplitOptions.None);
            int to_counter = 0;
            foreach (string s1 in split_str)
            {
                to_counter++;
                if (to_counter == 1)
                    continue;

                string[] split_to = s1.Split(new string[] { ":" }, StringSplitOptions.None);
                if (split_to.Length < 2)
                {
                    continue;
                }
                byte[] address = Base58Check.Base58CheckEncoding.DecodePlain(split_to[0]);
                IxiNumber amount = new IxiNumber(new BigInteger(Convert.FromBase64String(split_to[1])));
                _cachedToListArray.AddOrReplace(new Address(address), amount);
            }

            return _cachedToListArray;
        }

        public bool setToListArray(IDictionary<Address, Transaction.ToEntry> to_list)
        {
            _cachedToListArray.Clear();

            toList = "";
            foreach (var to in to_list)
            {
                toList = string.Format("{0}||{1}:{2}", toList, to.Key.ToString(), Convert.ToBase64String(to.Value.amount.getAmount().ToByteArray()));
                _cachedToListArray.AddOrReplace(to.Key, to.Value.amount);
            }

            return true;
        }
    }

    public class ActivityStorage
    {
        private static string filename = "activity.dat";

        // Sql connections
        private static SQLiteConnection sqlConnection = null;
        private static readonly object storageLock = new object(); // This should always be placed when performing direct sql operations

        // Threading
        private static Thread thread = null;
        private static bool running = false;
        private static ThreadLiveCheck TLC;

        private enum QueueStorageCode
        {
            insertActivity,
            updateStatus,
            updateValue

        }
        private struct QueueStorageMessage
        {
            public QueueStorageCode code;
            public int retryCount;
            public object data;
        }

        private struct MessageDataStatus
        {
            public byte[] data;
            public ActivityStatus status;
            public ulong blockHeight;
            public long timestamp;
        }

        private struct MessageDataValue
        {
            public byte[] data;
            public IxiNumber value;
        }

        // Maintain a queue of sql statements
        private static readonly List<QueueStorageMessage> queueStatements = new List<QueueStorageMessage>();
        
        public static bool prepareStorage(string filename = "", bool pruneStorage = true)
        {
            running = true;
            if(filename == "")
            {
                filename = "activity.dat";
                if (IxianHandler.isTestNet)
                {
                    filename = "testnet-activity.dat";
                }
            }
            ActivityStorage.filename = filename;
            if (!prepareStorageInternal(pruneStorage))
            {
                running = false;
                return false;
            }
            // Start thread
            TLC = new ThreadLiveCheck();
            thread = new Thread(new ThreadStart(threadLoop));
            thread.Name = "Activity_Storage_Thread";
            thread.Start();

            return true;
        }


        // Creates the storage file if not found
        private static bool prepareStorageInternal(bool pruneStorage = true)
        {
            Logging.info("Preparing Activity storage, please wait...");

            // Bind the connection
            sqlConnection = new SQLiteConnection(filename);

            // The database needs to be prepared first
            var tableInfo = sqlConnection.GetTableInfo("activity");
            if (!tableInfo.Any())
            {
                // Create the activity table
                string sql = "CREATE TABLE `activity` (`id` TEXT, `seedHash` BLOB, `wallet` TEXT, `from` TEXT, `toList` TEXT, `type` INTEGER, `data` BLOB, `value` TEXT, `timestamp` INTEGER, `status` INTEGER, `blockHeight` INTEGER, `txid` TEXT, `insertedTimestamp` INTEGER, PRIMARY KEY(`id`));";
                executeSQL(sql);

                sql = "CREATE INDEX `seedHash` ON `activity` (`seedHash`);";
                executeSQL(sql);
                sql = "CREATE INDEX `wallet` ON `activity` (`wallet`);";
                executeSQL(sql);
                sql = "CREATE INDEX `from` ON `activity` (`from`);";
                executeSQL(sql);
                sql = "CREATE INDEX `toList` ON `activity` (`toList`);";
                executeSQL(sql);
                sql = "CREATE INDEX `type` ON `activity` (`type`);";
                executeSQL(sql);
                sql = "CREATE INDEX `timestamp` ON `activity` (`timestamp`);";
                executeSQL(sql);
                sql = "CREATE INDEX `status` ON `activity` (`status`);";
                executeSQL(sql);
                sql = "CREATE INDEX `blockHeight` ON `activity` (`blockHeight`);";
                executeSQL(sql);
                sql = "CREATE INDEX `txid` ON `activity` (`txid`);";
                executeSQL(sql);
                sql = "CREATE INDEX `insertedTimestamp` ON `activity` (`insertedTimestamp`);";
                executeSQL(sql);
            }
            else
            {
                // database exists, check if it needs upgrading
                if (!tableInfo.Exists(x => x.Name == "insertedTimestamp"))
                {
                    sqlConnection.Close();
                    File.Delete(filename);
                    return prepareStorageInternal();
                }
            }

            if(pruneStorage && CoreConfig.minActivityBlockHeight > 0)
            {
                clearStorage(CoreConfig.minActivityBlockHeight);
            }
            Logging.info("Prepared Activity storage");

            return true;
        }

        public static void stopStorage()
        {
            running = false;
        }

        // Clears the activity storage by keeping only activity of last n block heights as defined by lastBlocksToKeep.
        public static bool clearStorage(long lastBlocksToKeep = 0)
        {
            Logging.info("Clearing old Activity entries, please wait...");
            Logging.flush();

            lock (storageLock)
            {
                string sql = "select * from `activity` ORDER BY `blockHeight` DESC LIMIT 1;";
                try
                {
                    Activity activity = null;
                    List<Activity> tmpActivityList = sqlConnection.Query<Activity>(sql);
                    if (tmpActivityList != null && tmpActivityList.Count > 0)
                    {
                        activity = tmpActivityList[0];
                        if (activity.blockHeight > lastBlocksToKeep)
                        {
                            executeSQL("DELETE FROM `activity` WHERE `blockHeight` <= ?", activity.blockHeight - lastBlocksToKeep);
                            executeSQL("VACUUM;");
                        }
                    }
                }
                catch (Exception e)
                {
                    Logging.error("Exception has been thrown while executing SQL Query {0}. Exception message: {1}", sql, e.Message);
                    return false;
                }
            }

            return true;
        }

        public static List<Activity> getActivitiesByAddress(string address, int fromIndex, int count, bool descending)
        {
            if (address.Length < 1)
            {
                return null;
            }

            string orderBy = " ORDER BY `insertedTimestamp` ASC";
            if (descending)
            {
                orderBy = " ORDER BY `insertedTimestamp` DESC";
            }

            string sql = "select * from `activity` where `wallet` = ?" + orderBy + " LIMIT " + fromIndex + ", " + count;
            List<Activity> activity_list = null;

            lock (storageLock)
            {
                try
                {
                    activity_list = sqlConnection.Query<Activity>(sql, address);
                }
                catch (Exception e)
                {
                    Logging.error(String.Format("Exception has been thrown while executing SQL Query {0}. Exception message: {1}", sql, e.Message));
                    return null;
                }
            }

            return activity_list;
        }

        public static List<Activity> getActivitiesBySeedHash(byte[] seed_hash, int fromIndex, int count, bool descending, string orderByField = "insertedTimestamp")
        {
            string orderBy = " ORDER BY `" + orderByField + "` ASC";
            if (descending)
            {
                orderBy = " ORDER BY `" + orderByField + "` DESC";
            }

            if (seed_hash == null)
            {
                seed_hash = new byte[1] { 0 };
            }

            string sql = "select * from `activity` where `seedHash` = ?" + orderBy + " LIMIT " + fromIndex + ", " + count;
            List<Activity> activity_list = null;

            lock (storageLock)
            {
                try
                {
                    activity_list = sqlConnection.Query<Activity>(sql, seed_hash);
                }
                catch (Exception e)
                {
                    Logging.error(String.Format("Exception has been thrown while executing SQL Query {0}. Exception message: {1}", sql, e.Message));
                    return null;
                }
            }

            return activity_list;
        }

        public static List<Activity> getActivitiesBySeedHashAndType(byte[] seed_hash, ActivityType type, int fromIndex, int count, bool descending, string orderByField = "insertedTimestamp")
        {
            string orderBy = " ORDER BY `" + orderByField + "` ASC";
            if (descending)
            {
                orderBy = " ORDER BY `" + orderByField + "` DESC";
            }

            if (seed_hash == null)
            {
                seed_hash = new byte[1] { 0 };
            }

            string sql = "select * from `activity` where  `type` = ? aND `seedHash` = ?" + orderBy + " LIMIT " + fromIndex + ", " + count;
            List<Activity> activity_list = null;

            lock (storageLock)
            {
                try
                {
                    activity_list = sqlConnection.Query<Activity>(sql, type, seed_hash);
                }
                catch (Exception e)
                {
                    Logging.error(String.Format("Exception has been thrown while executing SQL Query {0}. Exception message: {1}", sql, e.Message));
                    return null;
                }
            }

            return activity_list;
        }

        public static List<Activity> getActivitiesByStatus(ActivityStatus status, int fromIndex, int count, bool descending)
        {
            string orderBy = " ORDER BY `insertedTimestamp` ASC";
            if (descending)
            {
                orderBy = " ORDER BY `insertedTimestamp` DESC";
            }

            string sql = "select * from `activity` where `status` = ?" + orderBy + " LIMIT " + fromIndex + ", " + count;
            List<Activity> activity_list = null;

            lock (storageLock)
            {
                try
                {
                    activity_list = sqlConnection.Query<Activity>(sql, (int)status);
                }
                catch (Exception e)
                {
                    Logging.error(String.Format("Exception has been thrown while executing SQL Query {0}. Exception message: {1}", sql, e.Message));
                    return null;
                }
            }

            return activity_list;
        }


        public static List<Activity> getActivitiesByType(ActivityType type, int fromIndex, int count, bool descending)
        {
            string orderBy = " ORDER BY `insertedTimestamp` ASC";
            if (descending)
            {
                orderBy = " ORDER BY `insertedTimestamp` DESC";
            }

            string sql = "select * from `activity` where `type` = ?" + orderBy + " LIMIT " + fromIndex + ", " + count;
            List<Activity> activity_list = null;

            lock (storageLock)
            {
                try
                {
                    activity_list = sqlConnection.Query<Activity>(sql, (int)type);
                }
                catch (Exception e)
                {
                    Logging.error(String.Format("Exception has been thrown while executing SQL Query {0}. Exception message: {1}", sql, e.Message));
                    return null;
                }
            }

            return activity_list;
        }

        public static Activity getActivityById(string id)
        {
            if (id.Length < 1)
            {
                return null;
            }

            string sql = "select * from `activity` where `id` = ? LIMIT 1";
            Activity activity = null;

            lock (storageLock)
            {
                try
                {
                    List<Activity> tmpActivityList = sqlConnection.Query<Activity>(sql, id);
                    if (tmpActivityList != null && tmpActivityList.Count > 0)
                    {
                        activity = tmpActivityList[0];
                    }
                }
                catch (Exception e)
                {
                    Logging.error(String.Format("Exception has been thrown while executing SQL Query {0}. Exception message: {1}", sql, e.Message));
                    return null;
                }
            }

            return activity;
        }

        public static void insertActivity(Activity activity)
        {
            // Make a copy of the block for the queue storage message processing
            QueueStorageMessage message = new QueueStorageMessage
            {
                code = QueueStorageCode.insertActivity,
                retryCount = 0,
                data = activity
            };

            lock (queueStatements)
            {
                queueStatements.Add(message);
            }
        }

        private static bool insertActivityInternal(Activity activity)
        {
            if(activity.id == null || activity.id.Length < 1)
            {
                return false;
            }

            byte[] seed_hash = activity.seedHash;
            if (seed_hash == null)
            {
                seed_hash = new byte[1] { 0 };
            }

            bool result = false;

            try
            {
                if (CoreConfig.walletNotifyCommand != "")
                {
                    IxiUtils.executeProcess(CoreConfig.walletNotifyCommand, Transaction.getTxIdString(activity.data), false);
                }
            }
            catch (Exception e)
            {
                Logging.error("Exception occurred in Activity:insertActivityInternal: " + e);
            }

            lock (storageLock)
            {
                string sql = "INSERT OR REPLACE INTO `activity` (`id`, `seedHash`, `wallet`, `from`, `toList`, `type`, `data`, `value`, `timestamp`, `status`, `blockHeight`, `txid`, `insertedTimestamp`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
                result = executeSQL(sql, activity.id, seed_hash, activity.wallet, activity.from, activity.toList, activity.type, activity.data, activity.value, activity.timestamp, activity.status, activity.blockHeight, activity.txid, Clock.getTimestampMillis());
            }

            return result;
        }

        public static void updateStatus(byte[] data, ActivityStatus status, ulong block_height, long timestamp = 0)
        {
            // Make a copy of the block for the queue storage message processing
            QueueStorageMessage message = new QueueStorageMessage
            {
                code = QueueStorageCode.updateStatus,
                retryCount = 0,
                data = new MessageDataStatus { data = data, status = status, blockHeight = block_height, timestamp = timestamp }
            };

            lock (queueStatements)
            {
                queueStatements.Add(message);
            }
        }


        private static bool updateStatusInternal(byte[] data, ActivityStatus status, ulong block_height, long timestamp)
        {
            bool result = false;

            try
            {
                if (CoreConfig.walletNotifyCommand != "")
                {
                    IxiUtils.executeProcess(CoreConfig.walletNotifyCommand, Transaction.getTxIdString(data), false);
                }
            }
            catch (Exception e)
            {
                Logging.error("Exception occurred in Activity:updateStatusInternal: " + e);
            }

            lock (storageLock)
            {
                List<object> sqlParams = new List<object>();
                string sql = "UPDATE `activity` SET `status` = ?";
                sqlParams.Add(status);

                if (block_height > 0)
                {
                    sql += ", `blockHeight` = ?";
                    sqlParams.Add((long)block_height);
                }

                if (timestamp > 0)
                {
                    sql += ", `timestamp` = ?";
                    sqlParams.Add(timestamp);
                }

                sql += " WHERE `data` = ?";
                sqlParams.Add(data);

                result = executeSQL(sql, sqlParams.ToArray());
            }

            return result;
        }

        public static void updateValue(byte[] data, IxiNumber value)
        {
            // Make a copy of the block for the queue storage message processing
            QueueStorageMessage message = new QueueStorageMessage
            {
                code = QueueStorageCode.updateValue,
                retryCount = 0,
                data = new MessageDataValue { data = data, value = value }
            };

            lock (queueStatements)
            {
                queueStatements.Add(message);
            }
        }

        private static bool updateValueInternal(byte[] data, IxiNumber value)
        {
            bool result = false;

            try
            {
                if (CoreConfig.walletNotifyCommand != "")
                {
                    IxiUtils.executeProcess(CoreConfig.walletNotifyCommand, Transaction.getTxIdString(data), false);
                }
            }
            catch (Exception e)
            {
                Logging.error("Exception occurred in Activity:updateValueInternal: " + e);
            }

            lock (storageLock)
            {
                string sql = "UPDATE `activity` SET `value` = ? WHERE `data` = ?";
                result = executeSQL(sql, value.ToString(), data);
            }

            return result;
        }

        // Escape and execute an sql command
        private static bool executeSQL(string sql, params object[] sqlParameters)
        {
            try
            {
                sqlConnection.Execute(sql, sqlParameters);
            }
            catch (Exception e)
            {
                Logging.error("Exception has been thrown while executing SQL Query {0}. Exception message: {1}", sql, e);
                return false;
            }
            return true;
        }

        public static void deleteCache()
        {
            if (File.Exists(filename))
            {
                File.Delete(filename);
            }
        }

        public static void threadLoop()
        {
            QueueStorageMessage active_message = new QueueStorageMessage();

            bool pending_statements = false;

            while (running || pending_statements == true)
            {
                bool message_found = false;
                pending_statements = false;
                TLC.Report();
                try
                {
                    lock (queueStatements)
                    {
                        int statements_count = queueStatements.Count();
                        if (statements_count > 0)
                        {
                            if (statements_count > 1)
                            {
                                pending_statements = true;
                            }
                            QueueStorageMessage candidate = queueStatements[0];
                            active_message = candidate;
                            message_found = true;
                        }
                    }

                    if (message_found)
                    {
                        if (active_message.code == QueueStorageCode.insertActivity)
                        {
                            insertActivityInternal((Activity)active_message.data);
                        }
                        else if (active_message.code == QueueStorageCode.updateStatus)
                        {
                            MessageDataStatus mds = (MessageDataStatus)active_message.data;
                            updateStatusInternal(mds.data, mds.status, mds.blockHeight, mds.timestamp);
                        }
                        else if (active_message.code == QueueStorageCode.updateValue)
                        {
                            MessageDataValue mdv = (MessageDataValue)active_message.data;
                            updateValueInternal(mdv.data, mdv.value);
                        }
                        lock (queueStatements)
                        {
                            queueStatements.RemoveAt(0);
                        }
                    }
                    else
                    {
                        // Sleep for 50ms to yield CPU schedule slot
                        Thread.Sleep(50);
                    }
                }
                catch (Exception e)
                {
                    Logging.error("Exception occurred in Activity storage thread loop: " + e);
                    if (message_found)
                    {
                        active_message.retryCount += 1;
                        if (active_message.retryCount > 10)
                        {
                            lock (queueStatements)
                            {
                                queueStatements.RemoveAt(0);
                            }
                            Logging.error("Too many retries, aborting...");
                            shutdown();
                            throw new Exception("Too many Activity storage retries. Aborting storage thread.");
                        }
                    }
                }
                Thread.Yield();
            }
            shutdown();
        }

        private static void shutdown()
        {
            running = false;
            if (sqlConnection != null)
            {
                sqlConnection.Close();
                sqlConnection = null;
            }
            thread = null;
            Logging.info("Activity Storage stopped.");
        }

        public static int getQueuedQueryCount()
        {
            lock (queueStatements)
            {
                return queueStatements.Count;
            }
        }
    }
}

#endif