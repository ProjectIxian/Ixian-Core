using DLT;
using System;
using System.Collections.Generic;
using System.Text;

namespace IXICore
{
    class Core
    {
        public static long networkTimeDifference = 0;


        public static long getCurrentTimestamp()
        {
            return (long)(Clock.getTimestamp() - networkTimeDifference);
        }

        public static long getCurrentTimestampMillis()
        {
            return (long)(Clock.getTimestampMillis() - (networkTimeDifference * 1000));
        }


    }
}
