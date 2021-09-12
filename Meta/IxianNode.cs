// Copyright (C) 2017-2020 Ixian OU
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

using IXICore.Network;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.Linq;

namespace IXICore.Meta
{
    public enum NetworkType
    {
        main = 0,
        test = 1
    }

    public enum NodeStatus
    {
        warmUp = 0, // when the node is warming up
        ready = 1, // when the node is ready to process all data
        stalled = 2, // when the node hasn't received any block updates from the network for over 30 minutes
        stopping = 3, // when the node is stopping
        stopped = 4
    }

    public abstract class IxianNode
    {
        // Required
        public abstract ulong getHighestKnownNetworkBlockHeight();
        public abstract Block getLastBlock();
        public abstract ulong getLastBlockHeight();
        public abstract int getLastBlockVersion();
        public abstract bool addTransaction(Transaction tx, bool force_broadcast);
        public abstract bool isAcceptingConnections();
        public abstract Wallet getWallet(byte[] id);
        public abstract IxiNumber getWalletBalance(byte[] id);
        public abstract void parseProtocolMessage(ProtocolMessageCode code, byte[] data, RemoteEndpoint endpoint);

        public abstract void shutdown();

        // Optional
        public virtual void receivedTransactionInclusionVerificationResponse(byte[] txid, bool verified) { }
        public virtual void receivedBlockHeader(BlockHeader block_header, bool verified) { }

        public abstract Block getBlock(ulong blockNum);
    }

    public static class IxianHandler
    {
        private static IxianNode handlerClass = null;

        private static string _publicIP = "";
        private static int _publicPort = 0;

        public static bool forceShutdown = false;

        /// <summary>
        /// Current node status.
        /// </summary>
        public static NodeStatus status = NodeStatus.warmUp;

        /// <summary>
        /// Network type designator.
        /// </summary>
        public static NetworkType networkType { get; private set; } = NetworkType.main;
       
        /// <summary>
        /// Testnet designator. If false the node can only connect to mainnet, if true it can only connect to testnet.
        /// </summary>
        public static bool isTestNet { get; private set; } = false;

        public static byte[] primaryWalletAddress = null;
        public static Dictionary<byte[], WalletStorage> wallets = new Dictionary<byte[], WalletStorage>(new ByteArrayComparer());

        public static void init(string product_version, IxianNode handler_class, NetworkType type, bool set_title = false,
            byte[] checksum_lock = null)
        {
            CoreConfig.productVersion = product_version;
            if(set_title)
            {
                Console.Title = product_version + " (" + CoreConfig.version + ")";
            }
            init(handler_class, type, checksum_lock);
        }

        public static void init(IxianNode handler_class, NetworkType type, byte[] checksum_lock = null)
        {
            handlerClass = handler_class;
            networkType = type;
            switch(type)
            {
                case NetworkType.main:
                    if(checksum_lock != null)
                    {
                        ConsensusConfig.ixianChecksumLock = checksum_lock;
                    }else
                    {
                        ConsensusConfig.ixianChecksumLock = ConsensusConfig.ixianChecksumLockMainNet;
                    }
                    isTestNet = false;
                    break;

                case NetworkType.test:
                    if (checksum_lock != null)
                    {
                        ConsensusConfig.ixianChecksumLock = checksum_lock;
                    }
                    else
                    {
                        ConsensusConfig.ixianChecksumLock = ConsensusConfig.ixianChecksumLockTestNet;
                    }
                    isTestNet = true;
                    break;
            }
        }

        private static void verifyHandler()
        {
            if (handlerClass == null)
            {
                throw new Exception("Handler Class must be specified in IxianHandler Class");
            }
        }

        public static ulong getHighestKnownNetworkBlockHeight()
        {
            verifyHandler();
            return handlerClass.getHighestKnownNetworkBlockHeight();
        }

        public static Block getLastBlock()
        {
            verifyHandler();
            return handlerClass.getLastBlock();
        }

        public static ulong getLastBlockHeight()
        {
            verifyHandler();
            return handlerClass.getLastBlockHeight();
        }

        public static int getLastBlockVersion()
        {
            verifyHandler();
            return handlerClass.getLastBlockVersion();
        }

        public static bool addTransaction(Transaction tx, bool force_broadcast)
        {
            verifyHandler();
            return handlerClass.addTransaction(tx, force_broadcast);
        }

        public static bool isAcceptingConnections()
        {
            verifyHandler();
            return handlerClass.isAcceptingConnections();
        }

        public static Wallet getWallet(byte[] id)
        {
            verifyHandler();
            return handlerClass.getWallet(id);
        }

        public static IxiNumber getWalletBalance(byte[] id)
        {
            verifyHandler();
            return handlerClass.getWalletBalance(id);
        }

        public static void receivedTransactionInclusionVerificationResponse(byte[] txid, bool verified)
        {
            verifyHandler();
            handlerClass.receivedTransactionInclusionVerificationResponse(txid, verified);
        }

        public static void receivedBlockHeader(BlockHeader block_header, bool verified)
        {
            verifyHandler();
            handlerClass.receivedBlockHeader(block_header, verified);
        }

        public static Block getBlock(ulong blockNum)
        {
            verifyHandler();
            return handlerClass.getBlock(blockNum);
        }

        public static void parseProtocolMessage(ProtocolMessageCode code, byte[] data, RemoteEndpoint endpoint)
        {
            verifyHandler();
            handlerClass.parseProtocolMessage(code, data, endpoint);
        }

        public static void shutdown()
        {
            forceShutdown = true;
            verifyHandler();
            handlerClass.shutdown();
        }

        public static WalletStorage getWalletStorage(byte[] walletAddress = null)
        {
            if (walletAddress == null)
            {
                return wallets[primaryWalletAddress];
            }
            return wallets[walletAddress];
        }

        public static WalletStorage getWalletStorageByFilename(string filename)
        {
            return wallets.First(x => x.Value.filename == filename).Value;
        }

        public static bool addWallet(WalletStorage ws)
        {
            lock (wallets)
            {
                if (wallets.Count == 0)
                {
                    primaryWalletAddress = ws.getPrimaryAddress();
                }
                if (wallets.ContainsKey(ws.getPrimaryAddress()))
                {
                    return false;
                }
                wallets.Add(ws.getPrimaryAddress(), ws);
            }
            return true;
        }

        public static bool removeWallet(byte[] walletAddress)
        {
            lock(wallets)
            {
                return wallets.Remove(walletAddress);
            }
        }

        public static bool isMyAddress(byte[] walletAddress)
        {
            lock(wallets)
            {
                foreach (var wallet in wallets)
                {
                    if(wallet.Value.isMyAddress(walletAddress))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        public static Dictionary<byte[], List<byte[]>> extractMyAddressesFromAddressList(SortedDictionary<byte[], IxiNumber> addressList, bool useSeedHashAsKey = true)
        {
            Dictionary<byte[], List<byte[]>> addresses = new Dictionary<byte[], List<byte[]>>();
            lock (wallets)
            {
                foreach (var wallet in wallets)
                {
                    var extractedAddresses = wallet.Value.extractMyAddressesFromAddressList(addressList);
                    if(extractedAddresses != null && extractedAddresses.Count > 0)
                    {
                        if(useSeedHashAsKey)
                        {
                            addresses.Add(wallet.Value.getSeedHash(), extractedAddresses);
                        }else
                        {
                            addresses.Add(wallet.Key, extractedAddresses);
                        }
                    }
                }
            }
            return addresses;
        }

        public static List<string> getWalletList()
        {
            List<string> walletList = new List<string>();

            lock (wallets)
            {
                foreach (var wallet in wallets)
                {
                    walletList.Add(Base58Check.Base58CheckEncoding.EncodePlain(wallet.Key));
                }
            }

            return walletList;
        }

        /// <summary>
        ///  IP Address on which the node is reachable.
        /// </summary>
        public static string publicIP
        {
            get { return _publicIP; }
            set
            {
                _publicIP = value;
                PresenceList.myPublicAddress = getFullPublicAddress();
            }
        }

        /// <summary>
        ///  Port on which the node is reachable.
        /// </summary>
        public static int publicPort
        {
            get { return _publicPort; }
            set
            {
                _publicPort = value;
                PresenceList.myPublicAddress = getFullPublicAddress();
            }
        }

        public static string getFullPublicAddress()
        {
            return publicIP + ":" + publicPort;
        }
    }
}
