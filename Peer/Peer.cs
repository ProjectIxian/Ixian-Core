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

using System;

namespace IXICore
{
    /// <summary>
    ///  A network peer (remote endpoint).
    /// </summary>
    public class Peer
    {
        /// <summary>
        ///  Hostname or IP of the remote peer.
        /// </summary>
        public string hostname;
        /// <summary>
        ///  Ixian Wallet address associated with the peer.
        /// </summary>
        public byte[] walletAddress;
        /// <summary>
        /// Timestamp of the last time the peer has been seen on the network.
        /// </summary>
        public long lastSeen;
        /// <summary>
        ///  Unix epoch value of the last time we have attempted to connect to the peer.
        /// </summary>
        public long lastConnectAttempt;
        /// <summary>
        ///  Unix epoch value of the last time we have fully connected to the peer.
        /// </summary>
        public long lastConnected;
        /// <summary>
        ///  Peer rating.
        /// </summary>
        public int rating;

        /// <summary>
        ///  Unix epoch value of when the peer was blacklisted.
        /// </summary>
        public long blacklisted;

        public Peer(string iHostname, byte[] iWalletAddress, long iLastSeen, long iLastConnectAttempt, long iLastConnected, int iRating)
        {
            hostname = iHostname;
            walletAddress = iWalletAddress;
            lastSeen = iLastSeen;
            lastConnectAttempt = iLastConnectAttempt;
            lastConnected = iLastConnected;
            rating = iRating;
            blacklisted = 0;
        }
    };
}