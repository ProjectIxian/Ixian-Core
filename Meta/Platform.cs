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
