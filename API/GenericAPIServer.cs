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
using IXICore.Network;
using IXICore.Utils;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;

namespace IXICore
{
    //! RPC error codes
    public enum RPCErrorCode
    {
        //! Standard JSON-RPC 2.0 errors
        RPC_INVALID_REQUEST = -32600,
        RPC_METHOD_NOT_FOUND = -32601,
        RPC_INVALID_PARAMS = -32602,
        RPC_INTERNAL_ERROR = -32603,
        RPC_PARSE_ERROR = -32700,

        //! General application defined errors
        RPC_MISC_ERROR = -1,  //! std::exception thrown in command handling
        RPC_FORBIDDEN_BY_SAFE_MODE = -2,  //! Server is in safe mode, and command is not allowed in safe mode
        RPC_TYPE_ERROR = -3,  //! Unexpected type was passed as parameter
        RPC_INVALID_ADDRESS_OR_KEY = -5,  //! Invalid address or key
        RPC_OUT_OF_MEMORY = -7,  //! Ran out of memory during operation
        RPC_INVALID_PARAMETER = -8,  //! Invalid, missing or duplicate parameter
        RPC_DATABASE_ERROR = -20, //! Database error
        RPC_DESERIALIZATION_ERROR = -22, //! Error parsing or validating structure in raw format
        RPC_VERIFY_ERROR = -25, //! General error during transaction or block submission
        RPC_VERIFY_REJECTED = -26, //! Transaction or block was rejected by network rules
        RPC_VERIFY_ALREADY_IN_CHAIN = -27, //! Transaction already in chain
        RPC_IN_WARMUP = -28, //! Client still warming up

        //! P2P client errors
        RPC_CLIENT_NOT_CONNECTED = -9,  //! not connected
        RPC_CLIENT_IN_INITIAL_DOWNLOAD = -10, //! Still downloading initial blocks
        RPC_CLIENT_NODE_ALREADY_ADDED = -23, //! Node is already added
        RPC_CLIENT_NODE_NOT_ADDED = -24, //! Node has not been added before

        //! Wallet errors
        RPC_WALLET_ERROR = -4,  //! Unspecified problem with wallet (key not found etc.)
        RPC_WALLET_INSUFFICIENT_FUNDS = -6,  //! Not enough funds in wallet or account
        RPC_WALLET_INVALID_ACCOUNT_NAME = -11, //! Invalid account name
        RPC_WALLET_KEYPOOL_RAN_OUT = -12, //! Keypool ran out, call keypoolrefill first
        RPC_WALLET_UNLOCK_NEEDED = -13, //! Enter the wallet passphrase with walletpassphrase first
        RPC_WALLET_PASSPHRASE_INCORRECT = -14, //! The wallet passphrase entered was incorrect
        RPC_WALLET_WRONG_ENC_STATE = -15, //! Command given in wrong wallet encryption state (encrypting an encrypted wallet etc.)
        RPC_WALLET_ENCRYPTION_FAILED = -16, //! Failed to encrypt the wallet
        RPC_WALLET_ALREADY_UNLOCKED = -17, //! Wallet is already unlocked
    };

    public class JsonRpcRequest
    {
        public string id = null;
        public string method = null;
        public Dictionary<string, object> @params = null;
    }

    public class JsonError
    {
        public int code = 0;
        public string message = null;
    }

    public class JsonResponse
    {
        public object result = null;
        public JsonError error = null;
        public string id = null;
    }

    public class GenericAPIServer
    {
        protected HttpListener listener;
        protected Thread apiControllerThread;
        protected bool continueRunning;
        protected List<string> listenURLs;
        protected List<string> allowedIPs;
        protected ThreadLiveCheck TLC;

        protected Dictionary<string, string> authorizedUsers;

        // Start the API server
        public void start(List<string> listen_URLs, Dictionary<string, string> authorized_users = null, List<string> allowed_IPs = null)
        {
            continueRunning = true;

            listenURLs = listen_URLs;

            authorizedUsers = authorized_users;
            allowedIPs = allowed_IPs;

            apiControllerThread = new Thread(apiLoop);
            apiControllerThread.Name = "API_Controller_Thread";
            TLC = new ThreadLiveCheck();
            apiControllerThread.Start();
        }

        // Stop the API server
        public void stop()
        {
            continueRunning = false;
            try
            {
                // Stop the listener
                listener.Stop();
            }
            catch (Exception)
            {
                Logging.info("API server already stopped.");
            }
        }

        // Override the onUpdate handler
        protected virtual void onUpdate(HttpListenerContext context)
        {
            try
            {
                if (ConsoleHelpers.verboseConsoleOutput)
                    Console.Write("*");


                string post_data = "";
                string method_name = "";
                Dictionary<string, object> method_params = null;

                HttpListenerRequest request = context.Request;
                using (var reader = new StreamReader(request.InputStream, request.ContentEncoding))
                {
                    post_data = reader.ReadToEnd();
                }


                if (post_data.Length > 0)
                {
                    JsonRpcRequest post_data_json = JsonConvert.DeserializeObject<JsonRpcRequest>(post_data);
                    method_name = post_data_json.method;
                    method_params = post_data_json.@params;
                }
                else
                {
                    if (context.Request.Url.Segments.Length < 2)
                    {
                        // We will now show an embedded wallet if the API is called with no parameters
                        sendWallet(context);
                        return;
                    }

                    method_name = context.Request.Url.Segments[1].Replace("/", "");
                    method_params = new Dictionary<string, object>();
                    foreach(string key in context.Request.QueryString.Keys)
                    {
                        if (key != null && key != "")
                        {
                            string value = context.Request.QueryString[key];
                            if(value == null)
                            {
                                value = "";
                            }
                            method_params.Add(key, value);
                        }
                    }
                }

                if (method_name == null)
                {
                    context.Response.ContentType = "application/json";
                    JsonError error = new JsonError { code = (int)RPCErrorCode.RPC_INVALID_REQUEST, message = "Unknown action." };
                    sendResponse(context.Response, new JsonResponse { error = error });
                    return;
                }

                try
                {
                    Logging.trace("Processing request " + context.Request.Url);
                    if (!processRequest(context, method_name, method_params))
                    {
                        processGenericRequest(context, method_name, method_params);
                    }
                }
                catch (Exception e)
                {
                    context.Response.ContentType = "application/json";
                    JsonError error = new JsonError { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "Unknown error occured, see log for details." };
                    sendResponse(context.Response, new JsonResponse { error = error });
                    Logging.error("Exception occured in API server while processing '{0}'. {1}", context.Request.Url, e);
                }
            }
            catch (Exception e)
            {
                context.Response.ContentType = "application/json";
                JsonError error = new JsonError { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "Unknown error occured, see log for details." };
                sendResponse(context.Response, new JsonResponse { error = error });
                Logging.error("Exception occured in API server. {0}", e);
            }
        }

        protected virtual bool processGenericRequest(HttpListenerContext context, string methodName, Dictionary<string, object> parameters)
        {
            JsonResponse response = null;

            if (methodName.Equals("shutdown", StringComparison.OrdinalIgnoreCase))
            {
                response = onShutdown();
            }

            if (methodName.Equals("reconnect", StringComparison.OrdinalIgnoreCase))
            {
                response = onReconnect();
            }

            if (methodName.Equals("connect", StringComparison.OrdinalIgnoreCase))
            {
                response = onConnect(parameters);
            }

            if (methodName.Equals("isolate", StringComparison.OrdinalIgnoreCase))
            {
                response = onIsolate();
            }

            if (methodName.Equals("addtransaction", StringComparison.OrdinalIgnoreCase))
            {
                response = onAddTransaction(parameters);
            }

            if (methodName.Equals("createrawtransaction", StringComparison.OrdinalIgnoreCase))
            {
                response = onCreateRawTransaction(parameters);
            }

            if (methodName.Equals("decoderawtransaction", StringComparison.OrdinalIgnoreCase))
            {
                response = onDecodeRawTransaction(parameters);
            }

            if (methodName.Equals("signrawtransaction", StringComparison.OrdinalIgnoreCase))
            {
                response = onSignRawTransaction(parameters);
            }

            if (methodName.Equals("sendrawtransaction", StringComparison.OrdinalIgnoreCase))
            {
                response = onSendRawTransaction(parameters);
            }

            if (methodName.Equals("calculatetransactionfee", StringComparison.OrdinalIgnoreCase))
            {
                if (parameters.ContainsKey("autofee"))
                {
                    response = new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "Automatic fee generation is invalid for `calculatetransactionfee`." } };
                }
                else
                {
                    response = onCalculateTransactionFee(parameters);
                }
            }

            if (methodName.Equals("addmultisigtransaction", StringComparison.OrdinalIgnoreCase))
            {
                response = onAddMultiSigTransaction(parameters);
            }

            if (methodName.Equals("addmultisigtxsignature", StringComparison.OrdinalIgnoreCase))
            {
                response = onAddMultiSigTxSignature(parameters);
            }

            if (methodName.Equals("addmultisigkey", StringComparison.OrdinalIgnoreCase))
            {
                response = onAddMultiSigKey(parameters);
            }

            if (methodName.Equals("delmultisigkey", StringComparison.OrdinalIgnoreCase))
            {
                response = onDelMultiSigKey(parameters);
            }

            if (methodName.Equals("changemultisigs", StringComparison.OrdinalIgnoreCase))
            {
                response = onChangeMultiSigs(parameters);
            }

            if (methodName.Equals("gettotalbalance", StringComparison.OrdinalIgnoreCase))
            {
                response = onGetTotalBalance(parameters);
            }
            
            if (methodName.Equals("mywallet", StringComparison.OrdinalIgnoreCase))
            {
                response = onMyWallet(parameters);
            }

            if (methodName.Equals("mypubkey", StringComparison.OrdinalIgnoreCase))
            {
                response = onMyPubKey(parameters);
            }
            
            if (methodName.Equals("clients", StringComparison.OrdinalIgnoreCase))
            {
                response = onClients();
            }

            if (methodName.Equals("servers", StringComparison.OrdinalIgnoreCase))
            {
                response = onServers();
            }

            if (methodName.Equals("status", StringComparison.OrdinalIgnoreCase))
            {
                response = onStatus(parameters);
            }

            if (methodName.Equals("blockheight", StringComparison.OrdinalIgnoreCase))
            {
                response = onBlockHeight();
            }

            if (methodName.Equals("activity", StringComparison.OrdinalIgnoreCase))
            {
                response = onActivity(parameters);
            }

            if (methodName.Equals("generatenewaddress", StringComparison.OrdinalIgnoreCase))
            {
                response = onGenerateNewAddress(parameters);
            }

            if (methodName.Equals("getwalletbackup", StringComparison.OrdinalIgnoreCase))
            {
                response = onGetWalletBackup(parameters);
            }

            if (methodName.Equals("getviewingwallet", StringComparison.OrdinalIgnoreCase))
            {
                response = onGetViewingWallet(parameters);
            }

            if (methodName.Equals("loadwallet", StringComparison.OrdinalIgnoreCase))
            {
                response = onLoadWallet(parameters);
            }

            if (methodName.Equals("unloadwallet", StringComparison.OrdinalIgnoreCase))
            {
                response = onUnloadWallet(parameters);
            }

            if (methodName.Equals("sign", StringComparison.OrdinalIgnoreCase))
            {
                response = onSign(parameters);
            }

            if (methodName.Equals("verify", StringComparison.OrdinalIgnoreCase))
            {
                response = onVerify(parameters);
            }

            if (methodName.Equals("listwallets", StringComparison.OrdinalIgnoreCase))
            {
                response = onListWallets();
            }

            if (methodName.Equals("validateaddress", StringComparison.OrdinalIgnoreCase))
            {
                response = onValidateAddress(parameters);
            }

            if (methodName.Equals("blacklistpeer", StringComparison.OrdinalIgnoreCase))
            {
                response = onBlacklistPeer(parameters);
            }

            if (methodName.Equals("clearpeerblacklist", StringComparison.OrdinalIgnoreCase))
            {
                response = onClearPeerBlacklist();
            }

            if (methodName.Equals("getpresence", StringComparison.OrdinalIgnoreCase))
            {
                response = onGetPresence(parameters);
            }

            bool resources = false;

            if (methodName.Equals("resources", StringComparison.OrdinalIgnoreCase))
            {
                onResources(context);
                resources = true;
            }

            bool processed_request = false;

            if (!resources)
            {
                // Set the content type to plain to prevent xml parsing errors in various browsers
                context.Response.ContentType = "application/json";

                if (response == null)
                {
                    response = new JsonResponse() { error = new JsonError() { code = (int)RPCErrorCode.RPC_METHOD_NOT_FOUND, message = "Unknown API request '" + methodName + "'" } };
                    processed_request = false;
                }else
                {
                    processed_request = true;
                }

                sendResponse(context.Response, response);
            }else
            {
                processed_request = true;
            }
            context.Response.Close();
            return processed_request;
        }

        protected virtual bool processRequest(HttpListenerContext context, string methodName, Dictionary<string, object> parameters)
        {
            return false;
        }

        protected bool isAuthorized(HttpListenerContext context)
        {
            if(authorizedUsers == null)
            {
                return true;
            }

            // No authorized users provided, allow access to everyone
            if(authorizedUsers.Count < 1)
            {
                return true;
            }

            if(context.User == null)
            {
                return false;
            }

            HttpListenerBasicIdentity identity = (HttpListenerBasicIdentity)context.User.Identity;

            if(authorizedUsers.ContainsKey(identity.Name))
            {
                if(authorizedUsers[identity.Name] == identity.Password)
                {
                    return true;
                }
            }

            return false;
        }

        protected void apiLoop()
        {
            // Start a listener on the loopback interface
            listener = new HttpListener();
            try
            {
                foreach (string url in listenURLs)
                {
                    listener.Prefixes.Add(url);
                }

                if (authorizedUsers != null && authorizedUsers.Count > 0)
                {
                    listener.AuthenticationSchemes = AuthenticationSchemes.Basic;
                }

                listener.Start();
            }
            catch (Exception ex)
            {
                Logging.error("Cannot initialize API server! The error was: " + ex.Message);
                IxianHandler.forceShutdown = true;
                return;
            }

            while (continueRunning)
            {
                HttpListenerContext context = null;
                try
                {
                    context = listener.GetContext();
                }
                catch(Exception ex)
                {
                    if (continueRunning)
                    {
                        Logging.error("Error in API server! " + ex.Message);
                    }
                    return;
                }

                try
                {
                    if (context != null)
                    {
                        if (allowedIPs != null && allowedIPs.Count() > 0 && !allowedIPs.Contains(context.Request.RemoteEndPoint.Address.ToString()))
                        {
                            context.Response.Close();
                            Thread.Yield();
                            continue;
                        }
                        if (isAuthorized(context))
                        {
                            onUpdate(context);
                        }
                        else
                        {
                            context.Response.StatusCode = 401;
                            context.Response.StatusDescription = "401 Unauthorized";
                        }
                        context.Response.Close();
                    }
                }catch(Exception e)
                {
                    Logging.error("Error processing api request in GenericAPIServer.apiLoop: " + e);
                }
                TLC.Report();
                Thread.Yield();
            }

        }

        protected void sendError(HttpListenerContext context, string errorString)
        {
            sendResponse(context.Response, errorString);
        }

        protected void sendResponse(HttpListenerResponse responseObject, string responseString)
        {
            byte[] buffer = System.Text.Encoding.UTF8.GetBytes(responseString);

            try
            {
                responseObject.ContentLength64 = buffer.Length;
                System.IO.Stream output = responseObject.OutputStream;
                output.Write(buffer, 0, buffer.Length);
                output.Close();
            }
            catch (Exception e)
            {
                if (continueRunning)
                {
                    Logging.error("APIServer: {0}", e);
                }
            }
        }

        public void sendResponse(HttpListenerResponse responseObject, JsonResponse response)
        {
            string responseString = JsonConvert.SerializeObject(response);

            string responseError = "null";
            if (response.error != null)
            {
                try
                {
                    responseError = JsonConvert.SerializeObject(response.error);
                }catch(Exception)
                {
                    responseError = response.error.ToString();
                }
            }

            Logging.trace("Processed request, sending response with error code: {0}", responseError);

            byte[] buffer = Encoding.UTF8.GetBytes(responseString);

            try
            {
                responseObject.ContentLength64 = buffer.Length;
                Stream output = responseObject.OutputStream;
                output.Write(buffer, 0, buffer.Length);
                output.Close();
            }
            catch (Exception e)
            {
                if (continueRunning)
                {
                    Logging.error("APIServer: {0}", e);
                }
            }
        }

        public void sendResponse(HttpListenerResponse responseObject, byte[] buffer)
        {
            try
            {
                responseObject.ContentLength64 = buffer.Length;
                Stream output = responseObject.OutputStream;
                output.Write(buffer, 0, buffer.Length);
                output.Close();
            }
            catch (Exception e)
            {
                if (continueRunning)
                {
                    Logging.error("APIServer: {0}", e);
                }
            }
        }

        protected void onResources(HttpListenerContext context)
        {
            string name = "";
            for (int i = 2; i < context.Request.Url.Segments.Count(); i++)
            {
                name += context.Request.Url.Segments[i];
            }

            if (name != null && name.Length > 1 && !name.EndsWith("/"))
            {
                name = name.Replace('/', Path.DirectorySeparatorChar);
                string file_path = "html" + Path.DirectorySeparatorChar + name;
                if (File.Exists(file_path))
                {
                    if (name.EndsWith(".css", StringComparison.OrdinalIgnoreCase))
                    {
                        context.Response.ContentType = "text/css";
                    }
                    else if (name.EndsWith(".js", StringComparison.OrdinalIgnoreCase))
                    {
                        context.Response.ContentType = "text/javascript";
                    }
                    else if (name.EndsWith(".html", StringComparison.OrdinalIgnoreCase))
                    {
                        context.Response.ContentType = "text/html";
                    }
                    else
                    {
                        context.Response.ContentType = "application/octet-stream";
                    }
                    sendResponse(context.Response, File.ReadAllBytes(file_path));
                    return;
                }else
                {
                    Logging.error("File {0} is missing.", file_path);
                }
            }
            // 404
            context.Response.ContentType = "text/plain";
            context.Response.StatusCode = 404;
            context.Response.StatusDescription = "404 File not found";
            sendResponse(context.Response, "404 File not found");
        }

        // Send the embedded wallet html file
        protected void sendWallet(HttpListenerContext context)
        {
            string wallet_path = "html" + Path.DirectorySeparatorChar + "wallet.html";
            if (!File.Exists(wallet_path))
            {
                Logging.error("File {0} is missing.", wallet_path);
                return;
            }

            string wallet_html = File.ReadAllText(wallet_path);
            
            // Set the content type to html to show the wallet page
            context.Response.ContentType = "text/html";

            sendResponse(context.Response, wallet_html);
        }




        // Generic API Calls

        private JsonResponse onShutdown()
        {
            JsonError error = null;

            IxianHandler.shutdown();

            return new JsonResponse { result = "Node shutdown", error = error };
        }

        private JsonResponse onReconnect()
        {
            JsonError error = null;

            CoreNetworkUtils.reconnect();

            return new JsonResponse { result = "Reconnecting node to network now.", error = error };
        }

        private JsonResponse onConnect(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            if (!parameters.ContainsKey("to"))
            {
                error = new JsonError { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "to parameter is missing" };
                return new JsonResponse { result = null, error = error };
            }

            string to = (string)parameters["to"];

            NetworkClientManager.connectTo(to, null);

            return new JsonResponse { result = string.Format("Connecting to node {0}", to), error = error };
        }

        private JsonResponse onIsolate()
        {
            JsonError error = null;

            CoreNetworkUtils.isolate();

            return new JsonResponse { result = "Isolating from network now.", error = error };
        }


        public JsonResponse onAddTransaction(Dictionary<string, object> parameters)
        {
            if (IxianHandler.status != NodeStatus.ready)
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_IN_WARMUP, message = String.Format("There was an error while creating the transaction: The node isn't ready to process this request yet.") } };
            }

            object r = createTransactionHelper(parameters);
            Transaction transaction = null;
            if (r is JsonResponse)
            {
                // there was an error
                return (JsonResponse)r;
            }
            else if (r is Transaction)
            {
                transaction = (Transaction)r;
            }
            else
            {
                return new JsonResponse
                {
                    result = null,
                    error = new JsonError()
                    {
                        code = (int)RPCErrorCode.RPC_INTERNAL_ERROR,
                        message = String.Format("There was an error while creating the transaction: Unexpected object: {0}", r.GetType().Name)
                    }
                };
            }
            if (IxianHandler.addTransaction(transaction, true))
            {
                PendingTransactions.addPendingLocalTransaction(transaction);
                return new JsonResponse { result = transaction.toDictionary(), error = null };
            }

            return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "An unknown error occured while adding the transaction" } };
        }

        private JsonResponse onCreateRawTransaction(Dictionary<string, object> parameters)
        {
            // Create a transaction, but do not add it to the TX pool on the node. Useful for:
            // - offline transactions
            // - manually adjusting fee

            if (IxianHandler.status != NodeStatus.ready)
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_IN_WARMUP, message = String.Format("There was an error while creating the transaction: The node isn't ready to process this request yet.") } };
            }

            bool sign = false;
            if (parameters.ContainsKey("sign"))
            {
                sign = true;
            }

            object r = createTransactionHelper(parameters, sign);
            Transaction transaction = null;
            if (r is JsonResponse)
            {
                // there was an error
                return (JsonResponse)r;
            }
            else if (r is Transaction)
            {
                transaction = (Transaction)r;
            }
            else
            {
                return new JsonResponse
                {
                    result = null,
                    error = new JsonError()
                    {
                        code = (int)RPCErrorCode.RPC_INTERNAL_ERROR,
                        message = String.Format("There was an error while creating the transaction: Unexpected object: {0}", r.GetType().Name)
                    }
                };
            }
            if (parameters.ContainsKey("json"))
            {
                return new JsonResponse { result = transaction.toDictionary(), error = null };
            }
            else
            {
                return new JsonResponse { result = Crypto.hashToString(transaction.getBytes()), error = null };
            }
        }

        private JsonResponse onDecodeRawTransaction(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            // transaction which alters a multisig wallet
            if (!parameters.ContainsKey("transaction"))
            {
                error = new JsonError { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "transaction parameter is missing" };
                return new JsonResponse { result = null, error = error };
            }

            string raw_transaction_hex = (string)parameters["transaction"];

            Transaction raw_transaction = new Transaction(Crypto.stringToHash(raw_transaction_hex));
            return new JsonResponse { result = raw_transaction.toDictionary(), error = null };
        }

        private JsonResponse onSignRawTransaction(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            // transaction which alters a multisig wallet
            object res = "Incorrect transaction parameters.";

            if (!parameters.ContainsKey("transaction"))
            {
                error = new JsonError { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "transaction parameter is missing" };
                return new JsonResponse { result = null, error = error };
            }

            string raw_transaction_hex = (string)parameters["transaction"];

            Transaction raw_transaction = new Transaction(Crypto.stringToHash(raw_transaction_hex));
            raw_transaction.signature = raw_transaction.getSignature(raw_transaction.checksum);
            return new JsonResponse { result = Crypto.hashToString(raw_transaction.getBytes()), error = null };
        }

        private JsonResponse onSendRawTransaction(Dictionary<string, object> parameters)
        {
            if (IxianHandler.status != NodeStatus.ready)
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_IN_WARMUP, message = String.Format("There was an error while creating the transaction: The node isn't ready to process this request yet.") } };
            }

            JsonError error = null;

            // transaction which alters a multisig wallet
            object res = "Incorrect transaction parameters.";

            if (!parameters.ContainsKey("transaction"))
            {
                error = new JsonError { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "transaction parameter is missing" };
                return new JsonResponse { result = null, error = error };
            }

            string raw_transaction_hex = (string)parameters["transaction"];

            Transaction raw_transaction = new Transaction(Crypto.stringToHash(raw_transaction_hex));

            if (IxianHandler.addTransaction(raw_transaction, true))
            {
                PendingTransactions.addPendingLocalTransaction(raw_transaction);
                return new JsonResponse { result = raw_transaction.toDictionary(), error = null };
            }

            return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_VERIFY_ERROR, message = "An unknown error occured while adding the transaction" } };
        }

        private JsonResponse onCalculateTransactionFee(Dictionary<string, object> parameters)
        {
            // Create a dummy transaction, just so that we can calculate the appropriate fee required to process this (minimum fee)
            object r = createTransactionHelper(parameters);
            Transaction transaction = null;
            if (r is JsonResponse)
            {
                // there was an error
                return (JsonResponse)r;
            }
            else if (r is Transaction)
            {
                transaction = (Transaction)r;
            }
            else
            {
                return new JsonResponse
                {
                    result = null,
                    error = new JsonError()
                    {
                        code = (int)RPCErrorCode.RPC_INTERNAL_ERROR,
                        message = String.Format("There was an error while creating the transaction: Unexpected object: {0}", r.GetType().Name)
                    }
                };
            }
            return new JsonResponse { result = transaction.fee.ToString(), error = null };
        }

        private JsonResponse onAddMultiSigTxSignature(Dictionary<string, object> parameters)
        {
            if (IxianHandler.status != NodeStatus.ready)
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_IN_WARMUP, message = String.Format("There was an error while creating the transaction: The node isn't ready to process this request yet.") } };
            }

            JsonError error = null;

            // transaction which alters a multisig wallet
            object res = "Incorrect transaction parameters.";

            if (!parameters.ContainsKey("wallet"))
            {
                error = new JsonError { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "wallet parameter is missing" };
                return new JsonResponse { result = null, error = error };
            }
            byte[] destWallet = Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]);

            if (!parameters.ContainsKey("origtx"))
            {
                error = new JsonError { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "origtx parameter is missing" };
                return new JsonResponse { result = null, error = error };
            }
            byte[] orig_txid = Transaction.txIdLegacyToV8((string)parameters["origtx"]);
            // no need to check if orig_txid exists as it may not (yet) because we're C/W node, TODO TODO in the future we could query a M/H node

            IxiNumber fee = ConsensusConfig.transactionPrice;

            Transaction transaction = Transaction.multisigAddTxSignature(orig_txid, fee, destWallet, IxianHandler.getHighestKnownNetworkBlockHeight());
            if (IxianHandler.addTransaction(transaction, true))
            {
                PendingTransactions.addPendingLocalTransaction(transaction);
                res = transaction.toDictionary();
            }
            else
            {
                error = new JsonError { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "There was an error adding the transaction." };
                res = null;
            }

            return new JsonResponse { result = res, error = error };
        }

        private JsonResponse onAddMultiSigTransaction(Dictionary<string, object> parameters)
        {
            if (IxianHandler.status != NodeStatus.ready)
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_IN_WARMUP, message = String.Format("There was an error while creating the transaction: The node isn't ready to process this request yet.") } };
            }

            JsonError error = null;

            // Add a new transaction. This test allows sending and receiving from arbitrary addresses
            object res = "Incorrect transaction parameters.";

            if (!parameters.ContainsKey("to"))
            {
                error = new JsonError { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "to parameter is missing" };
                return new JsonResponse { result = null, error = error };
            }

            IxiNumber amount = 0;
            IxiNumber fee = ConsensusConfig.transactionPrice;
            SortedDictionary<byte[], IxiNumber> toList = new SortedDictionary<byte[], IxiNumber>(new ByteArrayComparer());
            string[] to_split = ((string)parameters["to"]).Split('-');
            if (to_split.Length > 0)
            {
                foreach (string single_to in to_split)
                {
                    string[] single_to_split = single_to.Split('_');
                    byte[] single_to_address = Base58Check.Base58CheckEncoding.DecodePlain(single_to_split[0]);
                    if (!Address.validateChecksum(single_to_address))
                    {
                        res = "Incorrect to address.";
                        amount = 0;
                        break;
                    }
                    IxiNumber singleToAmount = new IxiNumber(single_to_split[1]);
                    if (singleToAmount < 0 || singleToAmount == 0)
                    {
                        res = "Incorrect amount.";
                        amount = 0;
                        break;
                    }
                    amount += singleToAmount;
                    toList.Add(single_to_address, singleToAmount);
                }
            }
            if (parameters.ContainsKey("fee") && ((string)parameters["fee"]).Length > 0)
            {
                string fee_string = (string)parameters["fee"];
                fee = new IxiNumber(fee_string);
            }

            if (!parameters.ContainsKey("from"))
            {
                error = new JsonError { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "from parameter is missing" };
                return new JsonResponse { result = null, error = error };
            }

            byte[] from = Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["from"]);
            if (IxianHandler.getWallet(from).type != WalletType.Multisig)
            {
                error = new JsonError { code = (int)RPCErrorCode.RPC_WALLET_ERROR, message = "The specified 'from' wallet is not a multisig wallet." };
                return new JsonResponse { result = null, error = error };
            }
            // Only create a transaction if there is a valid amount
            if (amount > 0)
            {
                Transaction transaction = Transaction.multisigTransaction(fee, toList, from, IxianHandler.getHighestKnownNetworkBlockHeight());
                if (transaction == null)
                {
                    error = new JsonError { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "An error occured while creating multisig transaction" };
                    return new JsonResponse { result = null, error = error };
                }
                Wallet wallet = IxianHandler.getWallet(from);
                if (wallet.balance < transaction.amount + transaction.fee)
                {
                    error = new JsonError { code = (int)RPCErrorCode.RPC_WALLET_INSUFFICIENT_FUNDS, message = "Your account's balance is less than the sending amount + fee." };
                    return new JsonResponse { result = null, error = error };
                }
                else
                {
                    if (IxianHandler.addTransaction(transaction, true))
                    {
                        PendingTransactions.addPendingLocalTransaction(transaction);
                        res = transaction.toDictionary();
                    }
                    else
                    {
                        error = new JsonError { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "An error occured while creating multisig transaction" };
                        return new JsonResponse { result = null, error = error };
                    }
                }
            }

            return new JsonResponse { result = res, error = error };
        }

        private JsonResponse onAddMultiSigKey(Dictionary<string, object> parameters)
        {
            if (IxianHandler.status != NodeStatus.ready)
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_IN_WARMUP, message = String.Format("There was an error while creating the transaction: The node isn't ready to process this request yet.") } };
            }

            // transaction which alters a multisig wallet
            if (!parameters.ContainsKey("wallet"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Parameter 'wallet' is missing." } };
            }
            byte[] destWallet = Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]);

            if (!parameters.ContainsKey("signer"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Parameter 'signer' is missing." } };
            }
            string signer = (string)parameters["signer"];

            byte[] signer_address = new Address(Base58Check.Base58CheckEncoding.DecodePlain(signer)).address;
            IxiNumber fee = ConsensusConfig.transactionPrice;

            Transaction transaction = Transaction.multisigAddKeyTransaction(signer_address, fee, destWallet, IxianHandler.getHighestKnownNetworkBlockHeight());
            if (IxianHandler.addTransaction(transaction, true))
            {
                PendingTransactions.addPendingLocalTransaction(transaction);
                return new JsonResponse { result = transaction.toDictionary(), error = null };
            }
            return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "Error while creating the transaction." } };
        }

        private JsonResponse onDelMultiSigKey(Dictionary<string, object> parameters)
        {
            if (IxianHandler.status != NodeStatus.ready)
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_IN_WARMUP, message = String.Format("There was an error while creating the transaction: The node isn't ready to process this request yet.") }};
            }

            // transaction which alters a multisig wallet
            object res = "Incorrect transaction parameters.";

            if (!parameters.ContainsKey("wallet"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Parameter 'wallet' is missing." } };
            }
            byte[] destWallet = Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]);

            if (!parameters.ContainsKey("signer"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Parameter 'signer' is missing." } };
            }
            string signer = (string)parameters["signer"];

            byte[] signer_address = new Address(Base58Check.Base58CheckEncoding.DecodePlain(signer)).address;

            IxiNumber fee = ConsensusConfig.transactionPrice;

            Transaction transaction = Transaction.multisigDelKeyTransaction(signer_address, fee, destWallet, IxianHandler.getHighestKnownNetworkBlockHeight());
            if (IxianHandler.addTransaction(transaction, true))
            {
                PendingTransactions.addPendingLocalTransaction(transaction);
                return new JsonResponse { result = transaction.toDictionary(), error = null };
            }
            return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "Error while creating the transaction." } };
        }

        private JsonResponse onChangeMultiSigs(Dictionary<string, object> parameters)
        {
            if (IxianHandler.status != NodeStatus.ready)
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_IN_WARMUP, message = String.Format("There was an error while creating the transaction: The node isn't ready to process this request yet.") } };
            }

            // transaction which alters a multisig wallet
            object res = "Incorrect transaction parameters.";

            if (!parameters.ContainsKey("wallet"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Parameter 'wallet' is missing." } };
            }
            byte[] destWallet = Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]);

            if (!parameters.ContainsKey("sigs"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Parameter 'sigs' is missing." } };
            }
            string sigs = (string)parameters["sigs"];

            IxiNumber fee = ConsensusConfig.transactionPrice;
            if (byte.TryParse(sigs, out byte reqSigs))
            {

                Transaction transaction = Transaction.multisigChangeReqSigs(reqSigs, fee, destWallet, IxianHandler.getHighestKnownNetworkBlockHeight());
                if (IxianHandler.addTransaction(transaction, true))
                {
                    PendingTransactions.addPendingLocalTransaction(transaction);
                    return new JsonResponse { result = transaction.toDictionary(), error = null };
                }
            }
            else
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "Parameter 'sigs' must be a number between 1 and 255." } };
            }

            return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "Error while creating the transaction." } };
        }

        private JsonResponse onGetTotalBalance(Dictionary<string, object> parameters)
        {
            byte[] wallet = null;
            if (parameters.ContainsKey("wallet"))
            {
                wallet = Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]);
            }

            IxiNumber balance = IxianHandler.getWalletStorage(wallet).getMyTotalBalance(IxianHandler.getWalletStorage(wallet).getPrimaryAddress());
            // TODO TODO TODO TODO adapt the following line for v3 wallets
            balance -= PendingTransactions.getPendingSendingTransactionsAmount(null);
            return new JsonResponse { result = balance.ToString(), error = null };
        }


        private JsonResponse onMyWallet(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            byte[] wallet = null;
            if (parameters.ContainsKey("wallet"))
            {
                wallet = Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]);
            }

            // Show own address, balance and blockchain synchronization status
            List<Address> address_list = IxianHandler.getWalletStorage(wallet).getMyAddresses();

            Dictionary<string, string> address_balance_list = new Dictionary<string, string>();

            foreach (Address addr in address_list)
            {
                address_balance_list.Add(addr.ToString(), IxianHandler.getWalletBalance(addr.address).ToString());
            }

            return new JsonResponse { result = address_balance_list, error = error };
        }

        private JsonResponse onMyPubKey(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            byte[] wallet = null;
            if (parameters.ContainsKey("wallet"))
            {
                wallet = Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]);
            }

            return new JsonResponse { result = Crypto.hashToString(IxianHandler.getWalletStorage(wallet).getPrimaryPublicKey()), error = error };
        }

        private JsonResponse onClients()
        {
            JsonError error = null;

            String[] res = NetworkServer.getConnectedClients();

            return new JsonResponse { result = res, error = error };
        }

        private JsonResponse onServers()
        {
            JsonError error = null;

            String[] res = NetworkClientManager.getConnectedClients(true);

            return new JsonResponse { result = res, error = error };
        }

        private JsonResponse onStatus(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            Dictionary<string, object> networkArray = new Dictionary<string, object>();

            networkArray.Add("Core Version", CoreConfig.version);
            networkArray.Add("Node Version", CoreConfig.productVersion);
            networkArray.Add("Network type", IxianHandler.networkType.ToString());
            networkArray.Add("My time", Clock.getTimestamp());
            networkArray.Add("Network time difference", Clock.networkTimeDifference);
            networkArray.Add("Real network time difference", Clock.realNetworkTimeDifference);
            networkArray.Add("My External IP", IxianHandler.publicIP);
            networkArray.Add("My Listening Port", IxianHandler.publicPort);
            //networkArray.Add("Listening interface", context.Request.RemoteEndPoint.Address.ToString());

            networkArray.Add("Core Status", IxianHandler.status);

            networkArray.Add("Block Height", IxianHandler.getLastBlockHeight());
            networkArray.Add("Block Version", IxianHandler.getLastBlockVersion());
            networkArray.Add("Network Block Height", IxianHandler.getHighestKnownNetworkBlockHeight());
            networkArray.Add("Node Type", PresenceList.myPresenceType);
            networkArray.Add("Connectable", NetworkServer.isConnectable());

            if (parameters.ContainsKey("verbose"))
            {
                Dictionary<string, object> queues = new Dictionary<string, object>();
                queues.Add("RcvLow", NetworkQueue.getLowPriorityMessageCount());
                queues.Add("RcvMedium", NetworkQueue.getMediumPriorityMessageCount());
                queues.Add("RcvHigh", NetworkQueue.getHighPriorityMessageCount());
                queues.Add("SendClients", NetworkServer.getQueuedMessageCount());
                queues.Add("SendServers", NetworkClientManager.getQueuedMessageCount());
                queues.Add("Logging", Logging.getRemainingStatementsCount());
                queues.Add("Pending Transactions", PendingTransactions.pendingTransactionCount());

                networkArray.Add("Queues", queues);

                networkArray.Add("Presences", PresenceList.getTotalPresences());

                networkArray.Add("Masters", PresenceList.countPresences('M'));
                networkArray.Add("Relays", PresenceList.countPresences('R'));
                networkArray.Add("Clients", PresenceList.countPresences('C'));
            }

            networkArray.Add("Network Clients", NetworkServer.getConnectedClients());
            networkArray.Add("Network Servers", NetworkClientManager.getConnectedClients(true));

            return new JsonResponse { result = networkArray, error = error };
        }

        private JsonResponse onBlockHeight()
        {
            JsonError error = null;

            ulong blockheight = IxianHandler.getLastBlockHeight();

            return new JsonResponse { result = blockheight, error = error };
        }

        private JsonResponse onActivity(Dictionary<string, object> parameters)
        {
#if !__MOBILE__
            JsonError error = null;

            string fromIndex = "0";
            if (parameters.ContainsKey("fromIndex"))
            {
                fromIndex = (string)parameters["fromIndex"];
            }

            string count = "50";
            if(parameters.ContainsKey("count"))
            {
                count = (string)parameters["count"];
            }

            int type = -1;
            if (parameters.ContainsKey("type"))
            {
                type = Int32.Parse((string)parameters["type"]);
            }

            bool descending = false;
            if(parameters.ContainsKey("descending") && (string)parameters["descending"] == "true")
            {
                descending = true;
            }

            byte[] wallet = null;
            if (parameters.ContainsKey("wallet"))
            {
                wallet = Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]);
            }

            List<Activity> res = null;

            if (type == -1)
            {
                res = ActivityStorage.getActivitiesBySeedHash(IxianHandler.getWalletStorage(wallet).getSeedHash(), Int32.Parse(fromIndex), Int32.Parse(count), descending);
            }
            else
            {
                res = ActivityStorage.getActivitiesBySeedHashAndType(IxianHandler.getWalletStorage(wallet).getSeedHash(), (ActivityType)type, Int32.Parse(fromIndex), Int32.Parse(count), descending);
            }
            return new JsonResponse { result = res, error = error };
#else
            return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "Activity not implemented" } };
#endif
        }

        private JsonResponse onGenerateNewAddress(Dictionary<string, object> parameters)
        {
            byte[] wallet_address = null;
            if (parameters.ContainsKey("wallet"))
            {
                wallet_address = Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]);
            }

            string base_address_str = null;
            if (parameters.ContainsKey("address"))
            {
                base_address_str = (string)parameters["address"];
            }

            byte[] base_address;
            if (base_address_str == null)
            {
                base_address = IxianHandler.getWalletStorage(wallet_address).getPrimaryAddress();
            }
            else
            {
                base_address = Base58Check.Base58CheckEncoding.DecodePlain(base_address_str);
            }

            Address new_address = IxianHandler.getWalletStorage(wallet_address).generateNewAddress(new Address(base_address), null);
            if (new_address != null)
            {
                return new JsonResponse { result = new_address.ToString(), error = null };
            }
            else
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_WALLET_ERROR, message = "Error occured while generating a new address" } };
            }
        }

        private JsonResponse onGetWalletBackup(Dictionary<string, object> parameters)
        {
            byte[] wallet = null;
            if (parameters.ContainsKey("wallet"))
            {
                wallet = Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]);
            }
            return new JsonResponse { result = "IXIHEX" + Crypto.hashToString(IxianHandler.getWalletStorage(wallet).getRawWallet()), error = null };
        }

        private JsonResponse onGetViewingWallet(Dictionary<string, object> parameters)
        {
            byte[] wallet = null;
            if (parameters.ContainsKey("wallet"))
            {
                wallet = Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]);
            }
            return new JsonResponse { result = "IXIHEX" + Crypto.hashToString(IxianHandler.getWalletStorage(wallet).getRawViewingWallet()), error = null };
        }

        private JsonResponse onLoadWallet(Dictionary<string, object> parameters)
        {
            if (!parameters.ContainsKey("file"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter 'file'." } };
            }
            if (!parameters.ContainsKey("password"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter 'password'." } };
            }

            string file = (string)parameters["file"];
            string password = (string)parameters["password"];
            
            WalletStorage ws = IxianHandler.getWalletStorageByFilename(file);
            if(ws == null)
            {
                ws = new WalletStorage(file);
                if (!ws.readWallet(password))
                {
                    return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_WALLET_ERROR, message = "Error occured while reading wallet file - incorrect password or file doesn't exist." } };
                }

                IxianHandler.addWallet(ws);
                ws.scanForLostAddresses();
            }

            return new JsonResponse { result = Base58Check.Base58CheckEncoding.EncodePlain(ws.getPrimaryAddress()), error = null };
        }

        private JsonResponse onUnloadWallet(Dictionary<string, object> parameters)
        {
            if (!parameters.ContainsKey("wallet"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter 'wallet'." } };
            }

            byte[] wallet = Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]);
            if (IxianHandler.removeWallet(wallet))
            {
                return new JsonResponse { result = "OK", error = null };
            }
            else
            {
                return new JsonResponse { result = "FAIL", error = null };
            }
        }

        // Signs message or hash
        private JsonResponse onSign(Dictionary<string, object> parameters)
        {
            byte[] wallet = null;
            if (parameters.ContainsKey("wallet"))
            {
                wallet = Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]);
            }


            string signature;

            if (parameters.ContainsKey("message"))
            {
                string message = (string)parameters["message"];
                byte[] hash = Crypto.sha512sqTrunc(UTF8Encoding.UTF8.GetBytes(message));
                signature = Crypto.hashToString(CryptoManager.lib.getSignature(hash, IxianHandler.getWalletStorage(wallet).getPrimaryPrivateKey()));

            }else if (parameters.ContainsKey("hash"))
            {
                byte[] hash = Crypto.stringToHash((string)parameters["hash"]);
                signature = Crypto.hashToString(CryptoManager.lib.getSignature(hash, IxianHandler.getWalletStorage(wallet).getPrimaryPrivateKey()));
            }else
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter 'message' or 'hash'." } };
            }

            return new JsonResponse { result = signature, error = null };
        }

        // Verifies message or hash
        private JsonResponse onVerify(Dictionary<string, object> parameters)
        {
            if (!parameters.ContainsKey("publicKey"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter 'publicKey'." } };
            }

            if (!parameters.ContainsKey("signature"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter 'signature'." } };
            }

            byte[] publicKey = Crypto.stringToHash((string)parameters["publicKey"]);
            byte[] signature = Crypto.stringToHash((string)parameters["signature"]);

            bool sigOk = false;

            if (parameters.ContainsKey("message"))
            {
                string message = (string)parameters["message"];
                byte[] hash = Crypto.sha512sqTrunc(UTF8Encoding.UTF8.GetBytes(message));
                sigOk = CryptoManager.lib.verifySignature(hash, publicKey, signature);

            }
            else if (parameters.ContainsKey("hash"))
            {
                byte[] hash = Crypto.stringToHash((string)parameters["hash"]);
                sigOk = CryptoManager.lib.verifySignature(hash, publicKey, signature);
            }
            else
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter 'message' or 'hash'." } };
            }

            if (sigOk)
            {
                return new JsonResponse { result = "OK", error = null };
            }else
            {
                return new JsonResponse { result = "FAIL", error = null };
            }
        }

        private JsonResponse onListWallets()
        {
            return new JsonResponse { result = IxianHandler.getWalletList(), error = null };
        }

        // Returns "OK" if checksum of the address passes and error RPC_INVALID_ADDRESS_OR_KEY if the address is incorrect
        private JsonResponse onValidateAddress(Dictionary<string, object> parameters)
        {
            string address = null;
            if (parameters.ContainsKey("address"))
            {
                address = (string)parameters["address"];
            }

            byte[] address_bytes = null;
            try
            {
                address_bytes = Base58Check.Base58CheckEncoding.DecodePlain(address);
            }
            catch(Exception)
            {
                address_bytes = null;
            }

            if (address_bytes == null || !Address.validateChecksum(address_bytes))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_ADDRESS_OR_KEY, message = "Invalid address was specified" } };
            }

            return new JsonResponse { result = "OK", error = null };
        }

        private JsonResponse onBlacklistPeer(Dictionary<string, object> parameters)
        {
            if (parameters.ContainsKey("host"))
            {
                string host = (string)parameters["host"];
                PeerStorage.blacklist(host);
            }
            if (parameters.ContainsKey("wallet"))
            {
                byte[] address = Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]);
                PeerStorage.blacklist(address);
            }
            return new JsonResponse { result = "OK", error = null };
        }

        private JsonResponse onClearPeerBlacklist()
        {
            PeerStorage.clearBlacklist();
            return new JsonResponse { result = "OK", error = null };
        }

        private JsonResponse onGetPresence(Dictionary<string, object> parameters)
        {
            if (!parameters.ContainsKey("wallet"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter 'wallet'" } };
            }
            byte[] address = Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]);
            Presence p = PresenceList.getPresenceByAddress(address);
            if(p != null)
            {
                return new JsonResponse { result = p, error = null };
            }
            return new JsonResponse { result = null, error = null };
        }

        // This is a bit hacky way to return useful error values
        // returns either Transaction or JsonResponse
        private object createTransactionHelper(Dictionary<string, object> parameters, bool sign_transaction = true)
        {
            IxiNumber from_amount = 0;
            IxiNumber fee = ConsensusConfig.transactionPrice;

            bool auto_fee = false;
            if (parameters.ContainsKey("autofee"))
            {
                string r_auto_fee = (string)parameters["autofee"];
                if (r_auto_fee.ToLower() == "true" || r_auto_fee == "1")
                {
                    auto_fee = true;
                }
            }

            byte[] walletAddress = null;
            if (parameters.ContainsKey("wallet"))
            {
                walletAddress = Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]);
            }

            WalletStorage ws = IxianHandler.getWalletStorage(walletAddress);

            byte[] primary_address_bytes = null;
            if (!parameters.ContainsKey("primaryAddress"))
            {
                primary_address_bytes = ws.getPrimaryAddress();
            }
            else
            {
                primary_address_bytes = Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["primaryAddress"]);
            }

            SortedDictionary<byte[], IxiNumber> fromList = new SortedDictionary<byte[], IxiNumber>(new ByteArrayComparer());
            if (parameters.ContainsKey("from"))
            {
                string[] from_split = ((string)parameters["from"]).Split('-');
                if (from_split.Length > 0)
                {
                    foreach (string single_from in from_split)
                    {
                        string[] single_from_split = single_from.Split('_');
                        byte[] single_from_address = Base58Check.Base58CheckEncoding.DecodePlain(single_from_split[0]);
                        if (!ws.isMyAddress(single_from_address))
                        {
                            return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_ADDRESS_OR_KEY, message = "Invalid from address was specified" } };
                        }
                        byte[] single_from_nonce = ws.getAddress(single_from_address).nonce;
                        IxiNumber singleFromAmount = new IxiNumber(single_from_split[1]);
                        if (singleFromAmount < 0 || singleFromAmount == 0)
                        {
                            from_amount = 0;
                            break;
                        }
                        from_amount += singleFromAmount;
                        fromList.Add(single_from_nonce, singleFromAmount);
                    }
                }
                // Only create a transaction if there is a valid amount
                if (from_amount < 0 || from_amount == 0)
                {
                    return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Invalid from amount was specified" } };
                }
            }

            if (!parameters.ContainsKey("to"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Parameter 'to' is missing." } };
            }

            IxiNumber to_amount = 0;
            SortedDictionary<byte[], IxiNumber> toList = new SortedDictionary<byte[], IxiNumber>(new ByteArrayComparer());
            string[] to_split = ((string)parameters["to"]).Split('-');
            if (to_split.Length > 0)
            {
                foreach (string single_to in to_split)
                {
                    string[] single_to_split = single_to.Split('_');
                    byte[] single_to_address = Base58Check.Base58CheckEncoding.DecodePlain(single_to_split[0]);
                    if (!Address.validateChecksum(single_to_address))
                    {
                        return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_ADDRESS_OR_KEY, message = "Invalid to address was specified" } };
                    }
                    IxiNumber singleToAmount = new IxiNumber(single_to_split[1]);
                    if (singleToAmount < 0 || singleToAmount == 0)
                    {
                        return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Invalid to amount was specified" } };
                    }
                    to_amount += singleToAmount;
                    toList.Add(single_to_address, singleToAmount);
                }
            }

            if (parameters.ContainsKey("fee") && ((string)parameters["fee"]).Length > 0)
            {
                fee = new IxiNumber((string)parameters["fee"]);
            }

            // Only create a transaction if there is a valid amount
            if (to_amount < 0 || to_amount == 0)
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Invalid to amount was specified" } };
            }

            byte[] pubKey = ws.getKeyPair(primary_address_bytes).publicKeyBytes;

            // Check if this wallet's public key is already in the WalletState
            Wallet mywallet = IxianHandler.getWallet(primary_address_bytes);
            if (mywallet.publicKey != null && mywallet.publicKey.SequenceEqual(pubKey))
            {
                // Walletstate public key matches, we don't need to send the public key in the transaction
                pubKey = primary_address_bytes;
            }

            bool adjust_amount = false;
            if (fromList.Count == 0)
            {
                lock (PendingTransactions.pendingTransactions)
                {
                    fromList = ws.generateFromList(primary_address_bytes, to_amount + fee, toList.Keys.ToList(), PendingTransactions.pendingTransactions.Select(x => x.transaction).ToList());
                }
                adjust_amount = true;
            }

            if (fromList == null || fromList.Count == 0)
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_VERIFY_ERROR, message = "From list is empty" } };
            }

            Transaction transaction = new Transaction((int)Transaction.Type.Normal, fee, toList, fromList, null, pubKey, IxianHandler.getHighestKnownNetworkBlockHeight(), -1, sign_transaction);
            //Logging.info(String.Format("Intial transaction size: {0}.", transaction.getBytes().Length));
            //Logging.info(String.Format("Intial transaction set fee: {0}.", transaction.fee));
            if (adjust_amount) //true only if automatically generating from address
            {
                IxiNumber total_tx_fee = fee;
                for (int i = 0; i < 2 && transaction.fee != total_tx_fee; i++)
                {
                    total_tx_fee = transaction.fee;
                    lock (PendingTransactions.pendingTransactions)
                    {
                        fromList = ws.generateFromList(primary_address_bytes, to_amount + total_tx_fee, toList.Keys.ToList(), PendingTransactions.pendingTransactions.Select(x => x.transaction).ToList());
                    }
                    if (fromList == null || fromList.Count == 0)
                    {
                        return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_VERIFY_ERROR, message = "From list is empty" } };
                    }
                    transaction = new Transaction((int)Transaction.Type.Normal, fee, toList, fromList, null, pubKey, IxianHandler.getHighestKnownNetworkBlockHeight(), -1, sign_transaction);
                }
            }
            else if (auto_fee) // true if user specified both a valid from address and the parameter autofee=true
            {
                // fee is taken from the first specified address
                byte[] first_address = fromList.Keys.First();
                fromList[first_address] = fromList[first_address] + transaction.fee;
                if (fromList[first_address] > IxianHandler.getWalletBalance((new Address(transaction.pubKey, first_address)).address))
                {
                    return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_WALLET_INSUFFICIENT_FUNDS, message = "Balance is too low" } };
                }
                transaction = new Transaction((int)Transaction.Type.Normal, fee, toList, fromList, null, pubKey, IxianHandler.getHighestKnownNetworkBlockHeight(), -1, sign_transaction);
            }
            //Logging.info(String.Format("Transaction size after automatic adjustments: {0}.", transaction.getBytes().Length));
            //Logging.info(String.Format("Transaction fee after automatic adjustments: {0}.", transaction.fee));
            // verify that all "from amounts" match all "to_amounts" and that the fee is included in "from_amounts"
            // we need to recalculate "from_amount"
            from_amount = fromList.Aggregate(new IxiNumber(), (sum, next) => sum + next.Value, sum => sum);
            if (from_amount != (to_amount + transaction.fee))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_VERIFY_ERROR, message = "From amounts (incl. fee) do not match to amounts. If you haven't accounted for the transaction fee in the from amounts, use the parameter 'autofee' to have the node do it automatically." } };
            }
            if (to_amount + transaction.fee > ws.getMyTotalBalance(primary_address_bytes))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_WALLET_INSUFFICIENT_FUNDS, message = "Balance is too low" } };
            }

            // the transaction appears valid
            return transaction;
        }
    }
}
