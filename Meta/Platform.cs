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
    ///  Platform-specific utilities.
    /// </summary>
    class Platform
    {
        /// <summary>
        ///  Checks if the DLT is running on Mono.
        /// </summary>
        /// <remarks>
        ///  This is useful when certain features of the .NET framework are not implemented, or work differently on Mono vs. Microsoft.NET.
        /// </remarks>
        /// <returns>True, if the program is executing under Mono.</returns>
        public static bool onMono()
        {
            return Type.GetType("Mono.Runtime") != null;
        }

    }
}
