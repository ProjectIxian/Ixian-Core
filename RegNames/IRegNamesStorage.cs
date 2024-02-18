// Copyright (C) 2017-2024 Ixian OU
// This file is part of Ixian Core - www.github.com/ProjectIxian/Ixian-Core
//
// Ixian Core is free software: you can redistribute it and/or modify
// it under the terms of the MIT License as published
// by the Open Source Initiative.
//
// Ixian Core is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// MIT License for more details.
//

using System.Collections.Generic;

namespace IXICore.RegNames
{
    public interface IRegNameStorage
    {
        ulong count();
        byte[] getRegNameHeaderBytes(byte[] name);
        RegisteredNameRecord getRegNameHeader(byte[] name);
        bool createRegName(RegisteredNameRecord regName);
        bool updateRegName(RegisteredNameRecord regName, bool addIfNotPresent = false);
        bool removeRegName(byte[] name);
        void clear();
        RegisteredNameRecord[] debugGetRegisteredNames();
        IxiNumber getRewardPool();
        IxiNumber increaseRewardPool(IxiNumber fee);
        IxiNumber decreaseRewardPool(IxiNumber fee);
        List<RegisteredNameRecord> getExpiredNames(ulong blockHeight);
        ulong getHighestExpirationBlockHeight();
        void setHighestExpirationBlockHeight(ulong blockHeight);
        byte[] calculateRegNameStateChecksum();
    }
}
