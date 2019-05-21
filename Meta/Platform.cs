using System;
using System.Collections.Generic;
using System.Text;

namespace IXICore
{
    // Platform-specific functions
    class Platform
    {
        // Check if we're running on Mono Runtime
        public static bool onMono()
        {
            return Type.GetType("Mono.Runtime") != null;
        }

    }
}
