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

using IXICore.Meta;
using System.Numerics;
using System.Text;

namespace IXICore
{
    /// <summary>
    /// Basic Ixian (compile-time) configuration values.
    /// </summary>
    public class ConsensusConfig
    {
        /// <summary>
        ///  Target Block generation interval, in seconds.
        ///  Default value for Ixian DLT is 30.
        /// </summary>
        /// <remarks>
        ///  The DLT will strive to generate new Blocks according to this value.
        /// </remarks>
        public static readonly int blockGenerationInterval = 30;

        /// <summary>
        ///  Minimum valid time difference between previous and newly generated block, in seconds.
        ///  Default value for Ixian DLT is 20.
        /// </summary>
        public static readonly int minBlockTimeDifference = 20;

        /// <summary>
        ///  Maximum valid time difference between newly generated block and network time, in seconds.
        ///  Default value for Ixian DLT is 60.
        /// </summary>
        /// <remarks>
        ///  If block's time is higher than the Clock.getNetworkTimestamp() + maxBlockNetworkTimeDifference, the block will be invalid.
        /// </remarks>
        public static readonly int maxBlockNetworkTimeDifference = 60;

        /// <summary>
        ///  Number of blocks this particular is required to keep before discarding older blocks. Blocks older than the redaction window can be discarded.
        /// </summary>
        /// <remarks>
        ///  The redacted window, together with the block generation inverval specify that blocks should be kept for approximately 15 days.
        /// </remarks>
        public static ulong redactedWindowSize = 43200;
        /// <summary>
        ///  Number of blocks all Master Nodes are required to keep before discarding older blocks. Blocks older than the redaction window can be discarded.
        /// </summary>
        /// <remarks>
        ///  The redacted window, together with the block generation inverval specify that blocks should be kept for approximately 15 days.
        /// </remarks>
        public static ulong minRedactedWindowSize = 43200;
        /// <summary>
        ///  [LEGACY] Number of v0 and v1 blocks all Master Nodes are required to keep before discarding older blocks. Blocks older than the redaction window can be discarded.
        /// </summary>
        private static readonly ulong minRedactedWindowSize_v0 = 43200;
        /// <summary>
        ///  Number of v2 blocks all Master Nodes are required to keep before discarding older blocks. Blocks older than the redaction window can be discarded.
        /// </summary>
        /// <remarks>
        ///  The redacted window, together with the block generation inverval specify that blocks should be kept for approximately 7 days.
        /// </remarks>
        private static readonly ulong minRedactedWindowSize_v2 = 20000;
        /// <remarks>
        ///  The redacted window, together with the block generation inverval specify that blocks should be kept for approximately 3-4 days.
        /// </remarks>
        private static readonly ulong minRedactedWindowSize_v10 = 10000;
        /// <summary>
        /// Nonexistant wallet address which is used in the 'from' fields for PoW and PoS transactions, where currency is generated "from nothing".
        /// </summary>
        public static readonly Address ixianInfiniMineAddress = new Address(Base58Check.Base58CheckEncoding.DecodePlain("1ixianinfinimine234234234234234234234234234242HP"));
        /// <summary>
        /// Default security (in bits) of the generated RSA wallet keys.
        /// </summary>
        public static readonly int defaultRsaKeySize = 4096;
        /// <summary>
        ///  How often a special kind of block, called a 'superblock' is generated on the Ixian blockchain.
        ///  Default value for Ixian DLT network is 1000.
        /// </summary>
        /// <remarks>
        ///  Superblocks condense the information of the previous blocks (from the previous superblock to the current one), so that much of the superfluous blockchain data
        ///  can be dropped and still allow clients to bootstrap safely from potentially untrusted Master Nodes.
        /// </remarks>
        public static readonly ulong superblockInterval = 1000;


        /// <summary>
        /// Amount of signatures (ratio) of consenting signatures vs. available Master Nodes before a block can be accepted.
        /// </summary>
        public static readonly double networkConsensusRatio = 0.75;
        public static readonly int networkConsensusRatioNew = 75;

        /// <summary>
        /// Maximum allowed signers on a single block.
        /// </summary>
        public static readonly int maximumBlockSigners = 1000; // TODO TODO Omega - discard sigs that have lower difficulty than the new sig, when it is received

        public static readonly IxiNumber minBlockSignerPowDifficulty = 10000000;

        /// <summary>
        /// Minimum funds a wallet must have before it is allowed to participate in the block consensus algorithm. (used in DLT Node executable).
        /// </summary>
        public static readonly IxiNumber minimumMasterNodeFunds = new IxiNumber("2000");
        /// <summary>
        /// Transaction fee per kilobyte. Total transaction size is used. (Used in DLT Node executable.) 
        /// </summary>
        private static IxiNumber _forceTransactionPrice = new IxiNumber("0.00500000");
        public static IxiNumber forceTransactionPrice
        {
            get
            {
                if(_forceTransactionPrice != 0)
                {
                    return _forceTransactionPrice;
                }
                return transactionPrice;
            }

            set
            {
                _forceTransactionPrice = value;
            }
        }

        public static IxiNumber transactionPrice
        {
            get
            {
                // TODO Omega this has to be configurable; needs modifications to the mempool
                int lastBlockVersion = IxianHandler.getLastBlockVersion();
                if (lastBlockVersion == -1 || lastBlockVersion >= BlockVer.v10)
                {
                    return new IxiNumber("0.00500000");
                }
                return new IxiNumber("0.00005000");
            }
        }

        /// <summary>
        /// Transaction Dust Limit. Recipient value cannot be lower than this number.
        /// </summary>
        /// TODO Omega this has to be configurable; needs modifications to the mempool
        public static readonly IxiNumber transactionDustLimit = new IxiNumber("0.01000000");
        /// <summary>
        /// Amount of transaction fees, in percent, that are deposited into the foundation wallet, which funds the development of Ixian technology. (Used in DLT Node executable.)
        /// </summary>
        public static readonly IxiNumber foundationFeePercent = 3;
        /// <summary>
        /// Address of the Ixian foundation wallet, which is used to fund development of the Ixian technology stack. (Used in DLT Node executable.)
        /// </summary>
        public static readonly Address foundationAddress = new Address(Base58Check.Base58CheckEncoding.DecodePlain("153xXfVi1sznPcRqJur8tutgrZecNVYGSzetp47bQvRfNuDix")); // Foundation wallet address
        /// <summary>
        /// Initial price for relaying a kilobyte of data through an S2 node. (Used in S2 Node executable.)
        /// </summary>
        public static readonly IxiNumber relayPriceInitial = new IxiNumber("0.0002");
        /// <summary>
        /// Maximum number of transactions in each block that the node will accept. (Used in DLT Node executable.)
        /// </summary>
        public static readonly ulong maximumTransactionsPerBlock = 70200;
        /// <summary>
        /// Maximum block size in bytes. (Used in DLT Node executable.)
        /// </summary>
        public static readonly long maximumBlockSize = 1024000 + (((long)maximumTransactionsPerBlock + 1) * 100); // TODO fine-tune this
        /// <summary>
        /// Initial value for seeding the Transaction SHA512 checksum generator.
        /// </summary>
        public static readonly byte[] ixianChecksumLockMainNet = Encoding.UTF8.GetBytes("Ixian");

        /// <summary>
        /// Initial value for seeding the Transaction SHA512 checksum generator for TestNet.
        /// </summary>
        public static readonly byte[] ixianChecksumLockTestNet = Encoding.UTF8.GetBytes("IxiTest");

        /// <summary>
        /// Initial value for seeding the Transaction SHA512 checksum generator.
        /// </summary>
        public static byte[] ixianChecksumLock = Encoding.UTF8.GetBytes("Ixian");

        /// <summary>
        /// Block height after which mining/PoW transactions are not accepted anymore.
        /// </summary>
        public static readonly ulong miningExpirationBlockHeight = 105120000;


        /// <summary>
        /// Number of blocks that the PL PoW is valid for.
        /// </summary>
        public static readonly ulong plPowBlocksValidity = 120; // 120 blocks = approx. 1 hour

        /// <summary>
        /// Min. number of seconds that the PL PoW will be calculated for.
        /// </summary>
        public static readonly ulong plPowMinCalculationBlockTime = 20; // 20 blocks = 10 mins
        public static readonly long plPowMinCalculationTime = (long)plPowMinCalculationBlockTime * blockGenerationInterval;

        /// <summary>
        /// Number of blocks after how many to re-calculate the PL PoW since last solution.
        /// </summary>
        public static readonly ulong plPowCalculationInterval = 40; // 40 blocks = approx. 20 mins

        /// <summary>
        /// Number of blocks after how many the signing and mining rewards become available for spending.
        /// </summary>
        public static readonly ulong rewardMaturity = 960;// plPowBlocksValidity * 8;

        /// <summary>
        ///  Retrieves the lenght of the redacted window based on the block version in use.
        /// </summary>
        /// <param name="block_version">Block version for which you'd like to calculate the redacted window.</param>
        /// <returns>Redacted window length.</returns>
        public static ulong getRedactedWindowSize(int block_version = -1)
        {
            if (block_version == -1)
            {
                return minRedactedWindowSize;
            }
            if (block_version < 2)
            {
                return minRedactedWindowSize_v0;
            }
            if (block_version < BlockVer.v10)
            {
                return minRedactedWindowSize_v2;
            }
            if (block_version >= BlockVer.v10)
            {
                return minRedactedWindowSize_v10;
            }
            return minRedactedWindowSize;
        }

        /// <summary>
        ///  Calculates the mining reward amount for a certain block
        /// </summary>
        /// <param name="blockNum">Block number for which you'd like to calculate the mining reward amount.</param>
        /// <returns>Mining reward amount for the specified block.</returns>
        public static IxiNumber calculateMiningRewardForBlock(ulong blockNum)
        {
            ulong pow_reward = 0;

            if (blockNum < 1051200) // first year
            {
                pow_reward = (blockNum * 9) + 9; // +0.009 IXI
                pow_reward = (pow_reward / 2 + 10000) * 100000; // Divide by 2 (assuming 50% block coverage) + add inital 10 IXI block reward + add the full amount of 0s to cover IxiNumber decimals
            }
            else if (blockNum < 1802000) // second year, until first adjustment
            {
                pow_reward = (1051200 * 9);
                pow_reward = (pow_reward / 2 + 10000) * 100000; // Divide by 2 (assuming 50% block coverage) + add inital 10 IXI block reward + add the full amount of 0s to cover IxiNumber decimals
            }
            else if (blockNum < 6307200) // up to first halving
            {
                pow_reward = 2304;
                pow_reward *= 100000000;
            }
            else if (blockNum < 9460800) // up to 2nd halving
            {
                pow_reward = 1152;
                pow_reward *= 100000000;
            }
            else if (blockNum < 12614400) // up to final reward
            {
                pow_reward = 576;
                pow_reward *= 100000000;
            }
            else if (blockNum < miningExpirationBlockHeight) // final reward
            {
                pow_reward = 18;
                pow_reward *= 100000000;
            }

            return new IxiNumber(new BigInteger(pow_reward)); // Generate the corresponding IxiNumber, including decimals
        }

        /// <summary>
        ///  Calculates the signing reward amount for a certain block
        /// </summary>
        /// <param name="target_block_num">Block number for which you'd like to calculate the mining signing amount.</param>
        /// <param name="current_supply">Current circulating supply of IXI.</param>
        /// <returns>Mining reward amount for the specified block.</returns>
        public static IxiNumber calculateSigningRewardForBlock(ulong target_block_num, IxiNumber current_supply)
        {
            IxiNumber reward = 0;
            if (target_block_num <= 86400)
            {
                reward = current_supply * new IxiNumber("0.1") / new IxiNumber("100000000"); // approximation of 2*60*24*365*100
            }
            else if (target_block_num < 1802000)
            {
                reward = current_supply * new IxiNumber("5") / new IxiNumber("100000000"); // approximation of 2*60*24*365*100
            }
            else if (target_block_num < 6307200)
            {
                reward = 576;
            }
            else if (target_block_num < 9460800)
            {
                reward = 288;
            }
            else if (target_block_num < 12614400)
            {
                reward = 144;
            }
            else if (target_block_num < 15768000)
            {
                reward = 72;
            }
            else
            {
                reward = 36; // 36 per block after block num > 15768000 (12 years)
            }

            return reward;
        }
    }
}
