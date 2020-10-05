using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace IXICore.Meta
{
    /// <summary>
    /// Severity of the log message.
    /// </summary>
    public enum LogSeverity
    {
        /// <summary>
        /// Trace messages - not required during normal operation.
        /// </summary>
        trace = 0,
        /// <summary>
        /// Informative messages - normal operation.
        /// </summary>
        info = 1,
        /// <summary>
        /// Warning messages.
        /// </summary>
        warn = 2,
        /// <summary>
        /// Serious errors.
        /// </summary>
        error = 3
    }

    /// <summary>
    /// A singleton class which gathers and stores all logging messages from the Ixian executable. 
    /// It supports log rotation (on restart, or when reaching a certain size), outputting to the console
    /// and file simultaneously, automatic timestamping and thread identification.
    /// The actual work on the log files is done in a separate thread, so that the caller does not feel a performance
    /// impact for logging.
    /// </summary>
    public class Logging
    {
        /// <summary>
        /// Currently selected log severity. Messages below this severity will not be logged and will be quickly and quietly dropped.
        /// </summary>
        public static LogSeverity currentSeverity = LogSeverity.trace;


        // Private
        private static string logfilename = "ixian.log";
        private static string logfilepath = ""; // Stores the full log path
        private static string folderpath = ""; // Stores just the folder path
        private static string wildcard = "ixian*log";
        private static string logfilepathpart = "";
        private static Thread thread = null;
        private static bool running = false;

        private static FileStream logFileStream = null;

        private static int maxLogSize = 50 * 1024 * 1024;
        private static int maxLogCount = 10;
        /// <summary>
        /// If set to true, log output will go to the console, otherwise log will only go to the file.
        /// </summary>
        public static bool consoleOutput = true;

        private static long currentLogSize = 0;
        private static ThreadLiveCheck TLC;

        private struct LogStatement
        {
            public LogSeverity severity;
            public string message;
            public int threadId;
            public string time;
        }

        private static List<LogStatement> statements = new List<LogStatement>();

        /// <summary>
        /// Initialize and start the logging thread.
        /// </summary>
        public static bool start(string path)
        {
            if (running)
            {
                if (consoleOutput)
                    Console.WriteLine("Logging already started.");
                return false;
            }
            try
            {
                // Obtain paths and cache them
                folderpath = path;
                logfilepath = Path.Combine(folderpath, logfilename);
                wildcard = Path.GetFileNameWithoutExtension(logfilename) + "*" + Path.GetExtension(logfilename);
                logfilepathpart = Path.Combine(folderpath, Path.GetFileNameWithoutExtension(logfilename));

                // Roll the previous log
                roll(true);

                // Create the main log file
                byte[] logMessage = Encoding.UTF8.GetBytes("Ixian Log" + Environment.NewLine);
                logFileStream.Write(logMessage, 0, logMessage.Length);

                // Start thread
                TLC = new ThreadLiveCheck();
                running = true;
                thread = new Thread(new ThreadStart(threadLoop));
                thread.Name = "Logging_Thread";
                thread.Start();
            }
            catch (Exception e)
            {
                // Ignore all exception and start anyway with console only logging.
                Console.WriteLine(String.Format("Unable to open log file. Error was: {0}. Logging to console only.", e.Message));
                return false;
            }
            return true;
        }

        /// <summary>
        /// Stop the logging thread.
        /// </summary>
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
                currentLogSize = 0;
            }
        }

        /// <summary>
        /// Change log options while logging is active.
        /// </summary>
        /// <param name="max_log_size">Maximum log size in megabytes (MB).</param>
        /// <param name="max_log_count">Maximum number of log files for rotation.</param>
        /// <param name="console_output">Enable or disable output to console.</param>
        public static void setOptions(int max_log_size = 50, int max_log_count = 10, bool console_output = true)
        {
            maxLogSize = max_log_size * 1024 * 1024;
            maxLogCount = max_log_count;
            consoleOutput = console_output;
        }


        /// <summary>
        ///  Sends a message to the log.
        /// </summary>
        /// <remarks>
        ///  This should almost never be called directly, but rather through one of the helper functions.
        /// </remarks>
        /// <param name="log_severity">Severity of the log message.</param>
        /// <param name="log_message">Text to write into the log.</param>
        public static void log(LogSeverity log_severity, string log_message)
        {

            if (running == false)
            {
                String formattedMessage = String.Format("!!! {0}|{1}|({2}): {3}",
                        DateTime.Now.ToString("MM-dd HH:mm:ss.ffff"),
                        log_severity.ToString(),
                        Thread.CurrentThread.ManagedThreadId,
                        log_message);
                if (consoleOutput)
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

                    if (consoleOutput)
                    {
                        if (severity == LogSeverity.error)
                            Console.ForegroundColor = ConsoleColor.Red;
                        else if(severity == LogSeverity.warn)
                            Console.ForegroundColor = ConsoleColor.Yellow;

                        Console.WriteLine(formattedMessage);

                        if (severity == LogSeverity.error || severity == LogSeverity.warn)
                            Console.ResetColor();
                    }

                    Debug.WriteLine(formattedMessage);

                    lock (logfilename)
                    {
                        Logging.roll();
                        byte[] logMessage = Encoding.UTF8.GetBytes(formattedMessage + Environment.NewLine);
                        logFileStream.Write(logMessage, 0, logMessage.Length);
                        logFileStream.Flush();
                        currentLogSize += logMessage.Length;
                    }

                }
            }
            catch (Exception e)
            {
                if (consoleOutput)
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
                TLC.Report();
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

        /// <summary>
        ///  Rotates the log file, appending sequential numbers to the old log files and opening a new file.
        ///  This function will only perform the roll if the file is over the maximum specified size, unless the force parameter is specified.
        /// </summary>
        /// <remarks>
        ///  When the log is rotated, the current log is appended with the number '1'.
        ///  If there already exist older log files, they are shifted by one (.1 becomes .2, .2 becomes .3 ...).
        ///  A maximum number of rotated log files is specified in the logging options and if the rotate results in more
        ///  files, the extra ones are deleted.
        /// </remarks>
        /// <param name="forceRoll">Force log rotation even if the current file is below the threshold.</param>
        public static void roll(bool forceRoll = false)
        {
            try
            {
                if (logFileStream != null && currentLogSize < maxLogSize)
                {
                    return;
                }

                if (File.Exists(logfilepath))
                {
                    var length = new FileInfo(logfilepath).Length;
                    if (length > maxLogSize || (length > 0 && forceRoll))
                    {
                        if (logFileStream != null)
                        {
                            logFileStream.Flush();
                            logFileStream.Close();
                            logFileStream = null;
                            currentLogSize = 0;
                        }
                        string[] logFileList = Directory.GetFiles(folderpath, wildcard, SearchOption.TopDirectoryOnly);
                        if (logFileList.Length > 0)
                        {
                            // + 2 because of the . and digit [0-9]
                            var rolledLogFileList = logFileList.Where(fileName => Path.GetFileName(fileName).Length >= (logfilename.Length + 2)).ToArray();
                            Array.Sort(rolledLogFileList, 0, rolledLogFileList.Length);
                            while (rolledLogFileList.Length >= maxLogCount)
                            {
                                File.Delete(rolledLogFileList[rolledLogFileList.Length - 1]);
                                var list = rolledLogFileList.ToList();
                                list.RemoveAt(rolledLogFileList.Length - 1);
                                rolledLogFileList = list.ToArray();
                            }

                            // Move remaining rolled files
                            for (int i = rolledLogFileList.Length; i > 0; --i)
                            {
                                File.Move(rolledLogFileList[i - 1], logfilepathpart + "." + i + Path.GetExtension(logfilename));
                            }

                            // Move original file
                            var targetPath = logfilepathpart + ".0" + Path.GetExtension(logfilename);
                            File.Move(logfilepath, targetPath);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                if (consoleOutput)
                    Console.WriteLine("Exception rolling log file: {0}", e.Message);
                return;
            }
            try
            {
                if (logFileStream == null)
                {
                    logFileStream = File.Open(logfilepath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.Read);
                }
            }
            catch (Exception e)
            {
                if (consoleOutput)
                    Console.WriteLine("Exception opening log file: {0}", e.Message);
            }
        }

        /// <summary>
        /// Removes all the log files from the target directory.
        /// </summary>
        public static void clear()
        {
            lock (logfilename)
            {
                if (logFileStream != null)
                {
                    logFileStream.Flush();
                    logFileStream.Close();
                    logFileStream = null;
                    currentLogSize = 0;
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
                catch (Exception e)
                {
                    if (consoleOutput)
                        Console.WriteLine("Exception clearing log files: {0}", e.Message);
                }

                logFileStream = File.Open(logfilename, FileMode.OpenOrCreate, FileAccess.Write, FileShare.Read);
            }
        }

        /// <summary>
        /// Returns the number of log statements in the Logger's internal cache, waiting to be written to the file.
        /// </summary>
        /// <returns>Number of waiting statements.</returns>
        public static int getRemainingStatementsCount()
        {
            lock (statements)
            {
                return statements.Count();
            }
        }

        /// <summary>
        ///  Pauses execution until all the outstanding log statements are flushed to the file.
        /// </summary>
        public static void flush()
        {
            while (getRemainingStatementsCount() > 0)
            {
                Thread.Sleep(100);
            }
        }

        #region Convenience methods
        /// <summary>
        ///  Sends a message to the log with the implied severity of `Trace`.
        /// </summary>
        /// <param name="message">Log message.</param>
        public static void trace(string message)
        {
            Logging.log(LogSeverity.trace, message);
        }
        /// <summary>
        ///  Sends a message to the log with the implied severity of `Info`.
        /// </summary>
        /// <param name="message">Log message.</param>
        public static void info(string message)
        {
            Logging.log(LogSeverity.info, message);
        }
        /// <summary>
        ///  Sends a message to the log with the implied severity of `Warn`.
        /// </summary>
        /// <param name="message">Log message.</param>
        public static void warn(string message)
        {
            Logging.log(LogSeverity.warn, message);
        }
        /// <summary>
        ///  Sends a message to the log with the implied severity of `Error`.
        /// </summary>
        /// <param name="message">Log message.</param>
        public static void error(string message)
        {
            Logging.log(LogSeverity.error, message);
        }

        /// <summary>
        ///  Sends a message to the log with the implied severity of 'Trace'.
        ///  This function also accepts arguments like the function `String.Format()`.
        /// </summary>
        /// <param name="format">Format specification. See `String.Format()`</param>
        /// <param name="arguments">Optional arguments.</param>
        public static void trace(string format, params object[] arguments)
        {
            Logging.log(LogSeverity.trace, string.Format(format, arguments));
        }
        /// <summary>
        ///  Sends a message to the log with the implied severity of 'Info'.
        ///  This function also accepts arguments like the function `String.Format()`.
        /// </summary>
        /// <param name="format">Format specification. See `String.Format()`</param>
        /// <param name="arguments">Optional arguments.</param>
        public static void info(string format, params object[] arguments)
        {
            Logging.log(LogSeverity.info, string.Format(format, arguments));
        }
        /// <summary>
        ///  Sends a message to the log with the implied severity of 'Warn'.
        ///  This function also accepts arguments like the function `String.Format()`.
        /// </summary>
        /// <param name="format">Format specification. See `String.Format()`</param>
        /// <param name="arguments">Optional arguments.</param>
        public static void warn(string format, params object[] arguments)
        {
            Logging.log(LogSeverity.warn, string.Format(format, arguments));
        }
        /// <summary>
        ///  Sends a message to the log with the implied severity of 'Error'.
        ///  This function also accepts arguments like the function `String.Format()`.
        /// </summary>
        /// <param name="format">Format specification. See `String.Format()`</param>
        /// <param name="arguments">Optional arguments.</param>
        public static void error(string format, params object[] arguments)
        {
            Logging.log(LogSeverity.error, string.Format(format, arguments));
        }
        #endregion
    }
}