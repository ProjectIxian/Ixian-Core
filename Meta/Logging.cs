using System;
using System.IO;
using System.Diagnostics;
using System.Threading;
using System.Reflection;
using System.Linq;
using System.Text;

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
            private LogSeverity currentSeverity;


            private static string logfilename = "ixian.log";
            private static string logfilepath = ""; // Stores the full log path
            private static string folderpath = ""; // Stores just the folder path
            private static string wildcard = "*";
            private static string logfilepathpart = "";

            private Logging()
            {
                currentSeverity = LogSeverity.trace;
                try
                {
                    // Obtain paths and cache them
                    folderpath = System.IO.Path.GetDirectoryName(Assembly.GetEntryAssembly().Location);
                    logfilepath = Path.Combine(folderpath, Path.GetFileNameWithoutExtension(logfilename));
                    wildcard = Path.GetFileNameWithoutExtension(logfilename) + "*" + Path.GetExtension(logfilename);
                    logfilepathpart = Path.Combine(folderpath, Path.GetFileNameWithoutExtension(logfilename));

                    // Clear all previous logs
                    clear();

                    // Create the main log file
                    File.AppendAllText(logfilename, "Ixian Log" + Environment.NewLine, Encoding.UTF8);

                }
                catch (Exception e)
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

                    if (severity == LogSeverity.error)
                        Console.ForegroundColor = ConsoleColor.Red;

                    Console.WriteLine(formattedMessage);

                    if (severity == LogSeverity.error)
                        Console.ResetColor();

                    Debug.WriteLine(formattedMessage);

                    lock (logfilename)
                    {
                        Logging.roll();
                        File.AppendAllText(logfilename, formattedMessage + Environment.NewLine, Encoding.UTF8);
                    }

                }
            }

            // Rolls the log file
            public static void roll()
            {
                try
                {
                    var length = new FileInfo(logfilename).Length;
                    if(length > Config.maxLogFileSize)
                    {
                        Console.WriteLine("Path: {0}", folderpath);

                        string[] logFileList = Directory.GetFiles(folderpath, wildcard, SearchOption.TopDirectoryOnly);
                        if (logFileList.Length > 0)
                        {
                            // + 2 because of the . and digit [0-9]
                            var rolledLogFileList = logFileList.Where(fileName => Path.GetFileName(fileName).Length == (logfilename.Length + 2)).ToArray();
                            Array.Sort(rolledLogFileList, 0, rolledLogFileList.Length);
                            if (rolledLogFileList.Length >= 10)
                            {
                                File.Delete(rolledLogFileList[9]);
                                var list = rolledLogFileList.ToList();
                                list.RemoveAt(9);
                                rolledLogFileList = list.ToArray();
                            }
                            // move remaining rolled files
                            for (int i = rolledLogFileList.Length; i > 0; --i)
                                File.Move(rolledLogFileList[i - 1], logfilepathpart + "." + i + Path.GetExtension(logfilename));
                            var targetPath = logfilepathpart + ".0" + Path.GetExtension(logfilename);
                            // move original file
                            File.Move(logfilename, targetPath);
                        }
                    }

                }
                catch(Exception e)
                {
                    Console.WriteLine("Exception rolling log file: {0}", e.Message);
                }
            }

            // Clears the log files
            public static void clear()
            {
                lock (logfilename)
                {

                    if (File.Exists(logfilename))
                    {
                        File.Delete(logfilename);
                    }

                    string[] logFileList = Directory.GetFiles(folderpath, wildcard, SearchOption.TopDirectoryOnly);
                    var rolledLogFileList = logFileList.Where(fileName => Path.GetFileName(fileName).Length == (logfilename.Length + 2)).ToArray();

                    for (int i = rolledLogFileList.Length; i >= 0; --i)
                    {
                        string filename = logfilepathpart + "." + i + Path.GetExtension(logfilename);
                        if (File.Exists(filename))
                            File.Delete(filename);
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