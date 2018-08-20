using System;
using System.IO;
using System.Diagnostics;
using System.Threading;

namespace DLT
{
    namespace Meta
    {
        public enum LogSeverity
        {
            trace = 0,
            info = 1,
            warn = 2,
            error = 3
        }
        public class Logging
        {
            private static Logging singletonInstance;
            private TextWriter outputFile = null;
            private LogSeverity currentSeverity;

            private Logging()
            {
                currentSeverity = LogSeverity.trace;
                try
                {
                    outputFile = File.AppendText("ixian.log");
                } catch(Exception e)
                {
                    // Ignore all exception and start anyway with console only logging.
                    Console.WriteLine(String.Format("Unable to open log file. Error was: {0}. Logging to console only.", e.Message));
                }
            }

            public static Logging singleton
            {
                get
                {
                    if (singletonInstance == null)
                    {
                        singletonInstance = new Logging();
                    }
                    return singletonInstance;
                }
            }

            public static void log(LogSeverity severity, string message)
            {
                if (severity >= Logging.singleton.currentSeverity)
                {
                    String formattedMessage = String.Format("{0}|{1}|Thread({2}): {3}", 
                        DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.ffff"), 
                        severity.ToString(), 
                        Thread.CurrentThread.ManagedThreadId,
                        message);
                    Console.WriteLine(formattedMessage);
                    Debug.WriteLine(formattedMessage);

                    if (Logging.singleton.outputFile != null)
                    {
                        Logging.singleton.outputFile.WriteLine(formattedMessage);
                        Logging.singleton.outputFile.Flush();
                    }

                }
            }

            #region Convenience methods
            public static void trace(string message)
            {
                Logging.log(LogSeverity.trace, message);
            }
            public static void info(string message)
            {
                Logging.log(LogSeverity.info, message);
            }
            public static void warn(string message)
            {
                Logging.log(LogSeverity.warn, message);
            }
            public static void error(string message)
            {
                Logging.log(LogSeverity.error, message);
            }
            #endregion
        }
    }
}