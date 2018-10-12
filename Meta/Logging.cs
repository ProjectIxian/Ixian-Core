using System;
using System.IO;
using System.Diagnostics;
using System.Threading;
using System.Reflection;
using System.Linq;
using System.Text;
using System.Collections.Generic;

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
            // Public
            public static LogSeverity currentSeverity = LogSeverity.trace;


            // Private
            private static string logfilename = "ixian.log";
            private static string logfilepath = ""; // Stores the full log path
            private static string folderpath = ""; // Stores just the folder path
            private static string wildcard = "*";
            private static string logfilepathpart = "";
            private static Thread thread = null;
            private static bool running = false;

            private struct LogStatement
            {
                public LogSeverity severity;
                public string message;
                public int threadId;
                public string time;
            }

            private static List<LogStatement> statements = new List<LogStatement>();


            // Setup and start the logging thread
            public static void start()
            {        
                if(running)
                {
                    Console.WriteLine("Logging already started.");
                    return;
                }
                try
                {
                    // Obtain paths and cache them
                    folderpath = System.IO.Path.GetDirectoryName(Assembly.GetEntryAssembly().Location);
                    logfilepath = Path.Combine(folderpath, Path.GetFileNameWithoutExtension(logfilename));
                    wildcard = Path.GetFileNameWithoutExtension(logfilename) + "*" + Path.GetExtension(logfilename);
                    logfilepathpart = Path.Combine(folderpath, Path.GetFileNameWithoutExtension(logfilename));

                    // Roll the previous log
                    roll(true);

                    // Create the main log file
                    File.AppendAllText(logfilename, "Ixian Log" + Environment.NewLine, Encoding.UTF8);

                    // Start thread
                    running = true;
                    thread = new Thread(new ThreadStart(threadLoop));
                    thread.Start();
                }
                catch (Exception e)
                {
                    // Ignore all exception and start anyway with console only logging.
                    Console.WriteLine(String.Format("Unable to open log file. Error was: {0}. Logging to console only.", e.Message));
                }
            }

            // Stops the logging thread
            public static void stop()
            {
                running = false;
                thread.Abort();
            }

            // Log a statement
            public static void log(LogSeverity log_severity, string log_message)
            {
                
                if(running == false)
                {
                    Console.WriteLine("Logging is not active.");
                    return;
                }

                LogStatement statement = new LogStatement
                {
                    threadId = Thread.CurrentThread.ManagedThreadId,
                    severity = log_severity,
                    message = log_message,
                    time = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.ffff")
                };

                lock (statements)
                {

                    statements.Add(statement);
                }
            }

            // Internal log function called by the log thread
            private static void log_internal(LogSeverity severity, string message, int threadId, string time)
            {
                if (severity >= currentSeverity)
                {
                    String formattedMessage = String.Format("{0}|{1}|Thread({2}): {3}",
                        time,
                        severity.ToString(),
                        threadId,
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

            // Storage thread
            private static void threadLoop()
            {
                LogStatement statement = new LogStatement();
                bool message_found = false;

                while (running)
                {
                    message_found = false;

                    lock (statements)
                    {
                        if (statements.Count() > 0)
                        {
                            LogStatement candidate = statements[0];
                            statement = candidate;
                            statements.Remove(candidate);
                            message_found = true;
                        }
                    }

                    if (message_found)
                    {
                        log_internal(statement.severity, statement.message, statement.threadId, statement.time);
                    }
                    else
                    {
                        // Sleep for 25ms to prevent cpu waste
                        Thread.Sleep(25);
                    }
                }

                Thread.Yield();
            }

            // Rolls the log file
            public static void roll(bool forceRoll = false)
            {
                try
                {
                    var length = new FileInfo(logfilename).Length;
                    if(length > Config.maxLogFileSize || (length > 0 && forceRoll))
                    {
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

                            // Move remaining rolled files
                            for (int i = rolledLogFileList.Length; i > 0; --i)
                            {
                                File.Move(rolledLogFileList[i - 1], logfilepathpart + "." + i + Path.GetExtension(logfilename));
                            }

                            // Move original file
                            var targetPath = logfilepathpart + ".0" + Path.GetExtension(logfilename);
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

                    try
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
                    catch(Exception e)
                    {
                        Console.WriteLine("Exception clearing log files: {0}", e.Message);
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