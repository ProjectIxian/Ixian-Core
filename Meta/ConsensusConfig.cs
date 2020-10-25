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
        /// <summary>
        /// Nonexistant wallet address which is used in the 'from' fields for PoW and PoS transactions, where currency is generated "from nothing".
        /// </summary>
        public static readonly byte[] ixianInfiniMineAddress = Base58Check.Base58CheckEncoding.DecodePlain("1ixianinfinimine234234234234234234234234234242HP");
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

        /// <summary>
        /// Maximum allowed signers on a single block.
        /// </summary>
        public static readonly int maximumBlockSigners = 1000;

        /// <summary>
        /// Minimum funds a wallet must have before it is allowed to participate in the block consensus algorithm. (used in DLT Node executable).
        /// </summary>
        public static readonly IxiNumber minimumMasterNodeFunds = new IxiNumber("2000");
        /// <summary>
        /// Transaction fee per kilobyte. Total transaction size is used. (Used in DLT Node executable.)
        /// </summary>
        public static readonly IxiNumber transactionPrice = new IxiNumber("0.00005000");
        /// <summary>
        /// Amount of transaction fees, in percent, that are deposited into the foundation wallet, which funds the development of Ixian technology. (Used in DLT Node executable.)
        /// </summary>
        public static readonly IxiNumber foundationFeePercent = 3;
        /// <summary>
        /// Address of the Ixian foundation wallet, which is used to fund development of the Ixian technology stack. (Used in DLT Node executable.)
        /// </summary>
        public static readonly byte[] foundationAddress = Base58Check.Base58CheckEncoding.DecodePlain("153xXfVi1sznPcRqJur8tutgrZecNVYGSzetp47bQvRfNuDix"); // Foundation wallet address
        /// <summary>
        /// Initial price for relaying a kilobyte of data through an S2 node. (Used in S2 Node executable.)
        /// </summary>
        public static readonly IxiNumber relayPriceInitial = new IxiNumber("0.0002");
        /// <summary>
        /// Maximum number of transactions in each block that the node will accept. (Used in DLT Node executable.)
        /// </summary>
        public static readonly ulong maximumTransactionsPerBlock = 70200;

        /// <summary>
        /// Initial value for seeding the Transaction SHA512 checksum generator.
        /// </summary>
        public static readonly byte[] ixianChecksumLock = Encoding.UTF8.GetBytes("Ixian");
        /// <summary>
        /// Initial value for seeding various SHA512 checksums throughout Ixian.
        /// </summary>
        public static readonly string ixianChecksumLockString = "Ixian";

        /// <summary>
        /// Block height after which mining/PoW transactions are not accepted anymore.
        /// </summary>
        public static readonly ulong miningExpirationBlockHeight = 5256000;


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
            if (block_version >= 2)
            {
                return minRedactedWindowSize_v2;
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
            }
            else if (blockNum < 2102400) // second year
            {
                pow_reward = (1051200 * 9);
            }
            else if (blockNum < 3153600) // third year
            {
                pow_reward = (1051200 * 9) + ((blockNum - 2102400) * 9) + 9; // +0.009 IXI
            }
            else if (blockNum < 4204800) // fourth year
            {
                pow_reward = (2102400 * 9) + ((blockNum - 3153600) * 2) + 2; // +0.0020 IXI
            }
            else if (blockNum < 5256001) // fifth year
            {
                pow_reward = (2102400 * 9) + (1051200 * 2) + ((blockNum - 4204800) * 9) + 9; // +0.009 IXI
            }
            else // after fifth year if mining is still operational
            {
                pow_reward = ((3153600 * 9) + (1051200 * 2)) / 2;
            }

            pow_reward = (pow_reward / 2 + 10000) * 100000; // Divide by 2 (assuming 50% block coverage) + add inital 10 IXI block reward + add the full amount of 0s to cover IxiNumber decimals
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
            IxiNumber inflationPA = new IxiNumber("0.1"); // 0.1% inflation per year for the first month

            if (target_block_num > 86400) // increase inflation to 5% after 1 month
            {
                inflationPA = new IxiNumber("5");
            }

            IxiNumber reward = 0;
            if (!CoreConfig.isTestNet)
            {
                if (current_supply > new IxiNumber("100000000000"))
                {
                    reward = 1000;
                }
                else if (current_supply > new IxiNumber("50000000000"))
                {
                    // Set the annual inflation to 1% after 50bn IXIs in circulation 
                    inflationPA = new IxiNumber("1");
                    reward = current_supply * inflationPA / new IxiNumber("100000000"); // approximation of 2*60*24*365*100
                }
                else
                {
                    // Calculate the amount of new IXIs to be minted
                    reward = current_supply * inflationPA / new IxiNumber("100000000"); // approximation of 2*60*24*365*100
                }
            }
            else
            {
                if (current_supply > new IxiNumber("200000000000"))
                {
                    reward = 1000;
                }
                else if (current_supply > new IxiNumber("50000000000"))
                {
                    // Set the annual inflation to 1% after 50bn IXIs in circulation
                    inflationPA = new IxiNumber("1");
                    reward = current_supply * inflationPA / new IxiNumber("100000000"); // approximation of 2*60*24*365*100
                }
                else
                {
                    // Calculate the amount of new IXIs to be minted
                    reward = current_supply * inflationPA / new IxiNumber("100000000"); // approximation of 2*60*24*365*100
                }
            }
            return reward;
        }
    }
}
