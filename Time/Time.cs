using System;

namespace DLT
{

    public class Clock
    {
        // Obtain the unix timestamp
        public static String getTimestamp(DateTime value)
        {
            Int32 unixTimestamp = (Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
            return unixTimestamp.ToString();
        }
    }
    
}