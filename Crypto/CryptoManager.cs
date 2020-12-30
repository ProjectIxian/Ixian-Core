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
    public class CryptoManager
    {
        static private CryptoLib _lib;

        static public CryptoLib lib
        {
            get
            {
                if (_lib == null)
                {
                    _lib = new CryptoLib(new BouncyCastle());
                }
                return _lib;
            }
        }

        [Obsolete]
        public static void initLib()
        {
        }

        // Initialize with a specific crypto library
        public static void initLib(ICryptoLib crypto_lib)
        {
            _lib = new CryptoLib(crypto_lib);
        }
    }
}
