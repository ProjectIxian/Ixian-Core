using System;

namespace DLT.Meta
{
    /// <summary>
    /// Helper object to help diagnose and detect deadlocked threads.
    /// </summary>
    public class ThreadLiveCheck
    {
        private readonly object concurrencyGuard;
        private DateTime lastReport;
        private double reportEverySeconds;

        /// <summary>
        ///  Configures the ThreadLiveCheck.
        /// </summary>
        /// <param name="reportPeriod">How often the status of the monitored thread is reported, in seconds. Default 10 seconds</param>
        public ThreadLiveCheck(double reportPeriod = 10.0)
        {
            concurrencyGuard = new object();
            lastReport = DateTime.MinValue;
            reportEverySeconds = reportPeriod;
        }

        /// <summary>
        ///  This should be called at least once per the worker thread's loop. A message will be logged
        ///  every few seconds (See `ThreadLiveCheck()` constructor).
        /// </summary>
        /// <remarks>
        ///  If one or several of the worker threads stop responding, it is often due to a deadlock.
        ///  Provided that the `Report()` function is called on each thread loop iteration, the presence of absence
        ///  of these report messages in the log may indicate which threads have locked up and ease diagnosis.
        /// </remarks>
        public void Report()
        {
            if(!IXICore.CoreConfig.threadLiveCheckEnabled)
            {
                return;
            }
            lock (concurrencyGuard)
            {
                if ((DateTime.Now - lastReport).TotalSeconds > reportEverySeconds)
                {
                    lastReport = DateTime.Now;
                    Logging.info(String.Format("Thread Keep Alive: {0} - {1}",
                        System.Threading.Thread.CurrentThread.Name,
                        System.Threading.Thread.CurrentThread.ManagedThreadId));
                }
            }
        }
    }
}
