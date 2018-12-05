using DLT;
using System;
using System.Collections.Generic;
using System.Text;

namespace IXICore
{
    class Core
    {
        public static long networkTimeDifference = 0;


        // TODO everything connected to networkTimeDifference can probably be solved better
        public static long getCurrentTimestamp()
        {
            return (long)(Clock.getTimestamp() - networkTimeDifference);
        }


    }
}
