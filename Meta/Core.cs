namespace IXICore
{
    /// <summary>
    /// A collection of utility functions.
    /// </summary>
    public class Core
    {
        /// <summary>
        ///  Value represents the detected time offset from the network majority and is used when time synchronization is required.
        /// </summary>
        public static long networkTimeDifference = 0;

        /// <summary>
        ///  Retrieves the current time as a 64-bit unix epoch value, adjusted for the detected time offset from the network majority.
        /// </summary>
        /// <returns>Unix epoch (number of seconds since 1970-01-01)</returns>
        public static long getCurrentTimestamp()
        {
            return (long)(Clock.getTimestamp() - networkTimeDifference);
        }

        /// <summary>
        ///  Retrieves the current time as a 64-bit unix epoch value with the millisecon precision. The value is already adjusted for the detected
        ///  time offset from the network majority.
        /// </summary>
        /// <returns>Number of milliseconds since the unix epoch - 1970-01-01.</returns>
        public static long getCurrentTimestampMillis()
        {
            return (long)(Clock.getTimestampMillis() - (networkTimeDifference * 1000));
        }


    }
}
