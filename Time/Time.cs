using System;

namespace DLT
{

    public class Clock
    {
        // Obtain the unix timestamp
        public static long getTimestamp(DateTime value)
        {
            double unixTimestamp = (DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
            return (long)unixTimestamp;
        }
    }
}