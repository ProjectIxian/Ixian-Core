// Copyright (C) Ixian OU
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
using System.Runtime.InteropServices;
using System.Text;

namespace IXICore
{
    public class Argon2id
    {
        // Obtain the Argon2id hash from the provided data and salt
        public static byte[] getHash(byte[] data, byte[] salt, uint time_cost = 2, uint mem_cost = 2048, uint parallelism = 2)
        {
            try
            {
                byte[] hash = new byte[32];
                IntPtr data_ptr = Marshal.AllocHGlobal(data.Length);
                IntPtr salt_ptr = Marshal.AllocHGlobal(salt.Length);
                Marshal.Copy(data, 0, data_ptr, data.Length);
                Marshal.Copy(salt, 0, salt_ptr, salt.Length);
                UIntPtr data_len = (UIntPtr)data.Length;
                UIntPtr salt_len = (UIntPtr)salt.Length;
                IntPtr result_ptr = Marshal.AllocHGlobal(32);
                int result = NativeMethods.argon2id_hash_raw((UInt32)time_cost, (UInt32)mem_cost, (UInt32)parallelism, data_ptr, data_len, salt_ptr, salt_len, result_ptr, (UIntPtr)32);
                Marshal.Copy(result_ptr, hash, 0, 32);
                Marshal.FreeHGlobal(data_ptr);
                Marshal.FreeHGlobal(result_ptr);
                Marshal.FreeHGlobal(salt_ptr);
                return hash;
            }
            catch (Exception e)
            {
                Logging.error("Argon2id hash error: {0}", e.Message);
                return null;
            }
        }

        // Obtain the Argon2id hash as a string from the provided data and salt
        public static string getHashString(byte[] data, byte[] salt, uint time_cost = 2, uint mem_cost = 2048, uint parallelism = 2)
        {
            string ret = "";
            try
            {
                ret = BitConverter.ToString(getHash(data,salt,time_cost,mem_cost,parallelism)).Replace("-", string.Empty);
            }
            catch (Exception e)
            {
                Logging.error("Argon2id hash error: {0}", e.Message);
            }
            return ret;
        }

    }
}
