using System;

namespace IXICore
{

    public class Clock
    {
        /// <summary>
        ///  Value represents the detected time offset from the network majority and is used when time synchronization is required.
        /// </summary>
        public static long realNetworkTimeDifference = 0;

        /// <summary>
        ///  Value represents the normalized time offset from the network majority and is used when time synchronization is required.
        /// </summary>
        public static long networkTimeDifference = 0;

        /// <summary>
        ///  Retrieves the current time as a 64-bit unix epoch value, adjusted for the detected time offset from the network majority.
        ///  Should only be used for network related time operations.
        /// </summary>
        /// <returns>Unix epoch (number of seconds since 1970-01-01)</returns>
        public static long getNetworkTimestamp()
        {
            return (long)(getTimestamp() - networkTimeDifference);
        }

        /// <summary>
        ///  Retrieves the current time as a 64-bit unix epoch value with the millisecon precision. The value is already adjusted for the detected
        ///  time offset from the network majority.
        ///  Should only be used for network related time operations.
        /// </summary>
        /// <returns>Number of milliseconds since the unix epoch - 1970-01-01.</returns>
        public static long getNetworkTimestampMillis()
        {
            return (long)(getTimestampMillis() - (networkTimeDifference * 1000));
        }

        /// <summary>
        ///  Retrieves the current local time as a 64-bit unix epoch value.
        ///  Should be used for all local time operations.
        /// </summary>
        /// <returns>Unix epoch (number of seconds since 1970-01-01)</returns>
        public static long getTimestamp()
        {
            double unixTimestamp = (DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
            return (long)unixTimestamp;
        }

        /// <summary>
        ///  Retrieves the current local time as a 64-bit unix epoch value with the millisecon precision.
        ///  Should be used for all local time operations.
        /// </summary>
        /// <returns>Unix epoch (number of seconds since 1970-01-01)</returns>
        public static long getTimestampMillis()
        {
            double unixTimestamp = (DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalMilliseconds;
            return (long)unixTimestamp;
        }

        public static string getRelativeTime(long timestamp)
        {
            DateTime epoch = new DateTime(1970, 1, 1);
            return getRelativeTime(epoch.AddSeconds(timestamp));
        }

        public static string getRelativeTime(DateTime targetTime)
        {
            var span = new TimeSpan(DateTime.UtcNow.Ticks - targetTime.Ticks);
            double delta = Math.Abs(span.TotalSeconds);

            if (delta < 1 * 60)
                return span.Seconds == 1 ? "one second ago" : span.Seconds + " seconds ago";

            if (delta < 2 * 60)
                return "a minute ago";

            if (delta < 45 * 60)
                return span.Minutes + " minutes ago";

            if (delta < 90 * 60)
                return "an hour ago";

            if (delta < 24 * 3600)
                return span.Hours + " hours ago";

            if (delta < 48 * 3600)
                return "yesterday";

            if (delta < 30 * 86400)
                return span.Days + " days ago";

            if (delta < 12 * 2592000)
            {
                int months = Convert.ToInt32(Math.Floor((double)span.Days / 30));
                return months <= 1 ? "one month ago" : months + " months ago";
            }
            else
            {
                int years = Convert.ToInt32(Math.Floor((double)span.Days / 365));
                return years <= 1 ? "one year ago" : years + " years ago";
            }
        }

    }
}