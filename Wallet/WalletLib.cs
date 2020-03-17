using System;
using System.Collections.Generic;
using System.Text;

namespace IXICore
{
    namespace ExternalWallets
    {
        public class ExternalWalletException : Exception
        {
            // TODO: Something nicer here for easier error handling
            public string reason;
            public ExtWalletLibStatus libStatus;

            public ExternalWalletException(string r, ExtWalletLibStatus lib_status)
            {
                libStatus = lib_status;
                reason = r;
            }
        }
        /// <summary>
        /// Status of the external wallet library, with regards to its initialization or connection state.
        /// </summary>
        public enum ExtWalletLibStatus
        {
            /// <summary>
            /// Has not connected to the network and connection has not been started.
            /// </summary>
            /// <remarks>
            ///  At this point, the function `IExtWalletLib.connect()` should be called.
            /// </remarks>
            Offline,
            /// <summary>
            /// The function function `IExtWalletLib.connect()` has been called and the external library is attempting
            /// to connect to the specified network.
            /// </summary>
            Connecting,
            /// <summary>
            /// The external library has established connection to at least one network node and is synchronizing
            /// the required data before it can serve requests.
            /// </summary>
            Synchronizing,
            /// <summary>
            /// The external library is synchronized and ready to serve requests.
            /// </summary>
            OK,
            /// <summary>
            /// There was an error during connecting, synchronization, or the external library had been unexpectedly disconnected
            /// from its network.
            /// </summary>
            Failure
        }
        /// <summary>
        /// Status of transactions in the external network.
        /// </summary>
        /// <remarks>
        ///  Some of these states are used for transactions posted through the external network library, and
        ///  some are used to check SPV-style transaction inclusion, if supported.
        /// </remarks>
        public enum ExtTransactionState
        {
            /// <summary>
            /// The transaction has been posted to the external library, but it has not yet been processed.
            /// This usually means that the library is in the `Connecting` or `Synchronizing` state. The transaction
            /// will be sent automatically when the library is fully synchronized.
            /// This state is also used when performing a SPV check and results are not yet available.
            /// </summary>
            Pending,
            /// <summary>
            /// The transaction has been sent to at least one network node and is in queue for inclusion in a block.
            /// </summary>
            SentToNetwork,
            /// <summary>
            /// The transaction has been included in an accepted, valid block.
            /// This state is also returned when SPV check is completed and results have been returned
            /// </summary>
            Confirmed,
            /// <summary>
            /// There has been an error while validating the transaction, or some of the values are incorrect.
            /// <list type="bullet">
            /// <item>Transaction inputs and outputs add up to different amounts.</item>
            /// <item>Invalid signature.</item>
            /// <item>Invalid input or output addresses.</item>
            /// </list>
            /// </summary>
            InvalidTransaction,
            /// <summary>
            /// This status is only used when performing a SPV validation and the check has returned negative - i.e.: the transaction id
            /// is not included in a previous block.
            /// </summary>
            FailedConfirmation,
        }
        /// <summary>
        /// Stores information about a walley for an external blockchain network.
        /// The binary format is undefined and depends on the specific library. It is expected that
        /// the values returned from the library when creating a wallet will be accepted on subsequent starts as
        /// a valid wallet.
        /// If `privateKey` is `null`, then this WalletKeyPair represents a public address only in the library's
        /// native format.
        /// </summary>
        public abstract class ExtWalletKeyPair
        {
            /// <summary>
            /// Private key bytes - set by the external library and not touched by Ixian, except for encrypting when saving into a wallet file.
            /// This field may be null if the wallet only represents the public key or address.
            /// </summary>
            public byte[] privateKey;
            /// <summary>
            /// Public key bytes - set by the external library and not touched by Ixian, except for encrypting when saving into a wallet file.
            /// This field must always be present, otherwise this wallet is considered invalid or null.
            /// </summary>
            public byte[] publicKey;
            /// <summary>
            /// For external blockchains which support the functionality of derived wallets (e.g.: Bitcoin's HD wallet), this field is set
            /// to an identifier which was used to create the derived wallet, if applicable.
            /// The value of this field may be null.
            /// </summary>
            public byte[] derivationIndex;

            /// <summary>
            /// Returns a textual representation of the public key or address, such as is displayed to the user when referencing this wallet.
            /// </summary>
            /// <returns>Human-readable address format.</returns>
            public abstract string getPublicAddress();
            /// <summary>
            /// Shows if the private key is available for this wallet or address.
            /// </summary>
            /// <returns>True, if the private key exists.</returns>
            public abstract bool hasPrivateKey();

            // TODO: Save/Load (connected with IxiWalletFile?)
        }
        /// <summary>
        /// Represents the concept of a sender/receiver wallet, combined with an amount.
        /// Used in transactions to specify which wallets will be withdrawn and which deposited, and how much.
        /// </summary>
        public interface IExtTXInputOuput
        {
            /// <summary>
            /// Retrieves the wallet, connected with this input or output. If input, then the wallet must contain a private key.
            /// </summary>
            /// <returns>Wallet or address connected with this sender or receiver.</returns>
            ExtWalletKeyPair getAddress();
            /// <summary>
            /// Amount of money to withdraw from or deposit to the sender or receiver.
            /// </summary>
            /// <returns>Number of coins to widthraw or deposit.</returns>
            IxiNumber getAmount();
        }
        /// <summary>
        /// Represents an abstract, universal notion of a financial transaction. Currency may be withdrawn from multiple source wallets,
        /// but private keys must be available for each of them. Furthermore, currency may be deposited to multiple destination wallets,
        /// as long as appropriate public keys or addresses are listed.
        /// The amount of money withdrawn must be equal to the amount of money deposited, minus fee (if applicable)
        /// </summary>
        public interface IExtTransaction
        {
            /// <summary>
            ///  Generate a human-readable transaction ID, which is used in the user interface.
            /// </summary>
            /// <returns>Human readable transaction ID.</returns>
            string getTransactionID();
            /// <summary>
            /// Retrieves the list of source/input/withdrawal addresses for this transaction and their amounts.
            /// </summary>
            /// <returns>List of source wallets.</returns>
            IEnumerable<IExtTXInputOuput> getInputs();
            /// <summary>
            /// Retrieves the list of destination/output/deposit addresses for this transactions and their amounts.
            /// </summary>
            /// <returns>List of destination wallets.</returns>
            IEnumerable<IExtTXInputOuput> getOutputs();
            /// <summary>
            /// Retrives the total amount of currency being moved by this transaction, which includes the fee.
            /// The number is equal to the sum of all amounts for all inputs.
            /// </summary>
            /// <remarks>
            ///  The total amount being deposited can be calculated with `getTotalAmount() - getFee()`.
            /// </remarks>
            /// <returns>Total amount of currency being withdrawn from source wallets.</returns>
            IxiNumber getTotalAmount();
            /// <summary>
            /// Retrives the fee for this transaction, if applicable.
            /// </summary>
            /// <returns>Transaction fee.</returns>
            IxiNumber getFee();

        }
        /// <summary>
        /// Interface to an external library, which allows basic transaction and wallet operations on a
        /// cryptocurrency/DLT network other than Ixian. This is used primarily in clients (e.g.: SPIXI) to integrate
        /// other wallets and blockchains into the user experience.
        /// </summary>
        public interface IExtWalletLib
        {
            /// <summary>
            /// Establishes the connection to the alternative blockchain network.
            /// </summary>
            /// <param name="mainNet">If true, the connection will be established to the main network, otherwise test network.</param>
            void connect(bool mainNet);
            /// <summary>
            /// Establishes the connection to the alternative blockchain network, but provides some addresses to speed up the bootstrap process.
            /// Using this function ignores the built-in list of seed nodes.
            /// </summary>
            /// <param name="mainNet">If true, the connection will be established to the main network, otherwise test network.</param>
            /// <param name="seed_nodes">List of addresses for nodes which should be contacted first.</param>
            void connect(bool mainNet, IEnumerable<string> seed_nodes);
            /// <summary>
            /// Disconnects the external library from its network.
            /// </summary>
            void disconnect();
            /// <summary>
            /// Returns the external library connection and synchronization status.
            /// </summary>
            /// <returns>Status of the connection to the external blockchain network.</returns>
            ExtWalletLibStatus getStatus();
            /// <summary>
            /// Returns the list of neighboring nodes which are currently connected.
            /// </summary>
            /// <returns>List of addresses of neighboring nodes.</returns>
            IEnumerable<string> getNeighbors();

            /// <summary>
            /// Retrieves the current block height of the external blockchain network. If the value does not apply
            /// to the specific network, a zero is returned.
            /// </summary>
            /// <returns>External network block height.</returns>
            ulong getNetworkBlockHeight();

            /// <summary>
            /// Generates a new, empty wallet suitable for use with the external blockchain network.
            /// This function must also generate the private key for this wallet and set it accordingly.
            /// </summary>
            /// <returns>Wallet with private key</returns>
            ExtWalletKeyPair generateWallet();
            /// <summary>
            /// If the external blockchain supports deterministic wallets, this function generates
            /// such a wallet based on the `base_wallet`. A derivation key may be provided, if the 
            /// blockchain supports this function. The key should also be returned within the new wallet.
            /// If the external blockchain supports generating public keys only, then this function must accept
            /// a wallet without private key and return a derived wallet with only public key set. In order to
            /// obtain the private key for a such wallet, the original full wallet should be sent into this function
            /// with the same derivation_key as was returned when the public key was generated.
            /// </summary>
            /// <param name="base_wallet">Original wallet which should be derived into a new one.</param>
            /// <param name="derivation_key">Optional key, which is used in the derivation process.</param>
            /// <returns>A new wallet, derived from the base wallet.</returns>
            ExtWalletKeyPair deriveWallet(ExtWalletKeyPair base_wallet, byte[] derivation_key =  null);

            /// <summary>
            /// Converts the given wallet into a valid transaction input object, which can then be used to create transactions.
            /// </summary>
            /// <param name="wallet">Wallet to withdraw from.</param>
            /// <param name="amount">Amount of currency to withdraw from wallet.</param>
            /// <returns>A valid transaction input object.</returns>
            IExtTXInputOuput walletAsInput(ExtWalletKeyPair wallet, IxiNumber amount);
            /// <summary>
            /// Converts the given wallet into a valid transaction output object, which can then be used to create transactions.
            /// </summary>
            /// <param name="wallet">Destination wallet.</param>
            /// <param name="amount">Amount of currency to be deposited.</param>
            /// <returns>A valid transaction output object.</returns>
            IExtTXInputOuput walletAsOutput(ExtWalletKeyPair wallet, IxiNumber amount);
            /// <summary>
            /// Converts the address into a valid transaction output object, which can then be used to create transactions.
            /// </summary>
            /// <param name="address">Public address of the destination wallet.</param>
            /// <param name="amount">Amount of currency to be deposited.</param>
            /// <returns>A valid transaction output object.</returns>
            IExtTXInputOuput addressAsOutput(string address, IxiNumber amount);

            /// <summary>
            /// Generates a transaction object appropriate for the external blockchain network. Withdrawal wallets and destination
            /// addresses are provided in the abstract form of `IExtTXInputOutput`, which should be generated using the functions
            /// `walletAsInput`, `walletAsOuput` and `addressAsOutput`. This allows withdrawing from multiple wallets and depositing
            /// into multiple destination addresses in a single transaction.
            /// If the external blockchain network does not support this, it must return an error if more than one inputs or outputs are 
            /// used (depending on the capabilities of the target blockchain).
            /// </summary>
            /// <remarks>
            ///  Please note that this transaction is not sent to the external network automatically. In order to post the transaction to the 
            ///  network, the function `postTransaction()` should be called.
            /// </remarks>
            /// <param name="inputs">List of transaction inputs.</param>
            /// <param name="outputs">List of transaction outputs.</param>
            /// <param name="fee">Fee, if required. If set to 0, the external library will choose a default minimal fee.</param>
            /// <returns>Transaction object, appropriate for the external blockchain network.</returns>
            IExtTransaction createTransaction(IEnumerable<IExtTXInputOuput> inputs, IEnumerable<IExtTXInputOuput> outputs, IxiNumber fee);
            /// <summary>
            /// Sends a previously prepared transaction to the external blockchain network.
            /// </summary>
            /// <remarks>
            ///  Note that the transaction may not be posted immediately, if the network is not yet connected or synchronized.
            ///  Use `getTransactionStatus()` to see the state of the transaction.
            /// </remarks>
            /// <param name="tx">Transaction to sent, as prepared by `createTransaction()`.</param>
            void postTransaction(IExtTransaction tx);

            /// <summary>
            /// Gets the status of the given transaction to check whether it has been posted and/or confirmed by the external
            /// blockchain network.
            /// </summary>
            /// <param name="tx">Transaction object as prepared by `createTransaction()`.</param>
            /// <returns>Status of the transaction.</returns>
            ExtTransactionState getTransactionStatus(IExtTransaction tx);
            /// <summary>
            /// Gets the status of the given transaction ID. This can be used for transactions, prepared locally (if, for some reason, only
            /// transaction IDs are saved, rather than full transaction objects).
            /// This function retrieves results of a SPV-style check of the transaction inclusion, if the target network supports this function.
            /// </summary>
            /// <param name="txid">Human-readable ID of the transaction.</param>
            /// <returns>Status of the transaction.</returns>
            ExtTransactionState getTransactionStatus(string txid);

            /// <summary>
            /// Used to initiate a SPV-style transaction inclusion check, if the target network supports such functionality.
            /// Once the validation has been posted, use `getTransactionStatus()` with the same `txid` to get results.
            /// </summary>
            /// <param name="txid">Human readable transaction ID to verify for inclusion.</param>
            void validateSPVTransaction(string txid);
        }
    }
}