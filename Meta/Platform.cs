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
using System.Diagnostics;
using System.IO;

namespace IXICore
{
    /// <summary>
    ///  Platform-specific utilities.
    /// </summary>
    class Platform
    {
#if !__MOBILE__
        private static PerformanceCounter ramCounter = null;
#endif

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

        /// <summary>
        ///  Returns the number of available RAM bytes.
        /// </summary>
        /// <remarks>
        ///  If this function is called for the first time, it initializes an internal RAM PerformanceCounter
        ///  to speed up future lookups
        /// </remarks>
        /// <returns>Number of available bytes in RAM as a long</returns>
        public static long getAvailableRAM()
        {
#if !__MOBILE__
            if (ramCounter == null)
            {
                if (IXICore.Platform.onMono() == false)
                {
                    ramCounter = new PerformanceCounter("Memory", "Available Bytes", true);
                }
                else
                {
                    ramCounter = new PerformanceCounter("Mono Memory", "Available Physical Memory", true);
                }
            }

            return Convert.ToInt64(ramCounter.NextValue());
#endif
            return 0;
        }

        /// <summary>
        ///  Returns the number of available disk space bytes for the current folder's root disk.
        /// </summary>
        /// <remarks>
        ///  This function detects the current running folder's root path disk and returns the available free space
        /// </remarks>
        /// <returns>Number of available disk space bytes as a long</returns>
        public static long getAvailableDiskSpace()
        {
            string driveLetter = Path.GetPathRoot(Environment.CurrentDirectory).ToLower();
            foreach (DriveInfo drive in DriveInfo.GetDrives())
            {
                if (drive.IsReady && drive.Name.ToLower() == driveLetter)
                {
                    return drive.AvailableFreeSpace;
                }
            }
            return -1;
        }

    }
}
