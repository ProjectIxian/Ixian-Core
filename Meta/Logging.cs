using System;
using System.IO;
using System.Diagnostics;
using System.Threading;
using System.Reflection;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using IXICore;

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

            private static FileStream logFileStream = null;

            private static int maxLogSize = 50 * 1024 * 1024;
            private static int maxLogCount = 10;
            public static bool consoleOutput = true;

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
                    byte[] logMessage = Encoding.UTF8.GetBytes("Ixian Log" + Environment.NewLine);
                    logFileStream.Write(logMessage, 0, logMessage.Length);

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
                // Check if the logging is already stopped
                if (running == false)
                {
                    return;
                }

                running = false;
                thread.Abort();
                lock (logfilename)
                {
                    logFileStream.Flush();
                    logFileStream.Close();
                    logFileStream = null;
                }
            }

            // specify max_log_size in megabytes
            public static void setOptions(int max_log_size = 50, int max_log_count = 10, bool console_output = true)
            {
                maxLogSize = max_log_size * 1024 * 1024;
                maxLogCount = max_log_count;
                consoleOutput = console_output;
            }


            // Log a statement
            public static void log(LogSeverity log_severity, string log_message)
            {
                
                if(running == false)
                {
                    String formattedMessage = String.Format("!!! {0}|{1}|({2}): {3}",
                            DateTime.Now.ToString("MM-dd HH:mm:ss.ffff"),
                            log_severity.ToString(),
                            Thread.CurrentThread.ManagedThreadId,
                            log_message);
                    if(consoleOutput)
                        Console.WriteLine(formattedMessage);
                    return;
                }

                LogStatement statement = new LogStatement
                {
                    threadId = Thread.CurrentThread.ManagedThreadId,
                    severity = log_severity,
                    message = log_message,
                    time = DateTime.Now.ToString("MM-dd HH:mm:ss.ffff")
                };

                lock (statements)
                {

                    statements.Add(statement);
                }
            }

            // Internal log function called by the log thread
            private static void log_internal(LogSeverity severity, string message, int threadId, string time)
            {
                try
                {
                    if (severity >= currentSeverity)
                    {
                        String formattedMessage = String.Format("{0}|{1}|({2}): {3}",
                            time,
                            severity.ToString(),
                            threadId,
                            message);

                        if (severity == LogSeverity.error)
                            Console.ForegroundColor = ConsoleColor.Red;

                        if(consoleOutput)
                            Console.WriteLine(formattedMessage);

                        if (severity == LogSeverity.error)
                            Console.ResetColor();

                        Debug.WriteLine(formattedMessage);

                        lock (logfilename)
                        {
                            Logging.roll();
                            byte[] logMessage = Encoding.UTF8.GetBytes(formattedMessage + Environment.NewLine);
                            logFileStream.Write(logMessage, 0, logMessage.Length);
                            logFileStream.Flush();
                        }

                    }
                }
                catch(Exception e)
                {
                    Console.WriteLine("Logging exception: {0}", e.Message);
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
                    Thread.Yield();
                }
            }

            // Rolls the log file
            public static void roll(bool forceRoll = false)
            {
                try
                {
                    if(File.Exists(logfilename))
                    {
                        var length = new FileInfo(logfilename).Length;
                        if (length > maxLogSize || (length > 0 && forceRoll))
                        {
                            if (logFileStream != null)
                            {
                                logFileStream.Flush();
                                logFileStream.Close();
                                logFileStream = null;
                            }
                            string[] logFileList = Directory.GetFiles(folderpath, wildcard, SearchOption.TopDirectoryOnly);
                            if (logFileList.Length > 0)
                            {
                                // + 2 because of the . and digit [0-9]
                                var rolledLogFileList = logFileList.Where(fileName => Path.GetFileName(fileName).Length == (logfilename.Length + 2)).ToArray();
                                Array.Sort(rolledLogFileList, 0, rolledLogFileList.Length);
                                if (rolledLogFileList.Length >= maxLogCount)
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
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception rolling log file: {0}", e.Message);
                    return;
                }
                try
                {
                    if (logFileStream == null)
                    {
                        logFileStream = File.Open(logfilename, FileMode.OpenOrCreate, FileAccess.Write, FileShare.Read);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception opening log file: {0}", e.Message);
                }
            }

            // Clears the log files
            public static void clear()
            {
                lock (logfilename)
                {
                    if (logFileStream != null)
                    {
                        logFileStream.Flush();
                        logFileStream.Close();
                        logFileStream = null;
                    }

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

                    logFileStream = File.Open(logfilename, FileMode.OpenOrCreate, FileAccess.Write, FileShare.Read);
                }
            }

            // Returns the number of remaining log messages in the queue
            public static int getRemainingStatementsCount()
            {
                lock(statements)
                {
                    return statements.Count();
                }
            }

            public static void flush()
            {
                while (getRemainingStatementsCount() > 0)
                {
                    Thread.Sleep(100);
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

            public static void trace(string format, params object[] arguments)
            {
                Logging.log(LogSeverity.trace, string.Format(format, arguments));
            }
            public static void info(string format, params object[] arguments)
            {
                Logging.log(LogSeverity.info, string.Format(format, arguments));
            }
            public static void warn(string format, params object[] arguments)
            {
                Logging.log(LogSeverity.warn, string.Format(format, arguments));
            }
            public static void error(string format, params object[] arguments)
            {
                Logging.log(LogSeverity.error, string.Format(format, arguments));
            }
            #endregion
        }
    }
}