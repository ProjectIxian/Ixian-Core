using System;

namespace DLT.Meta
{
    public class ThreadLiveCheck
    {
        private readonly object concurrencyGuard;
        private DateTime lastReport;
        private double reportEverySeconds;

        public ThreadLiveCheck(double reportPeriod = 10.0)
        {
            concurrencyGuard = new object();
            lastReport = DateTime.MinValue;
            reportEverySeconds = reportPeriod;
        }

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
