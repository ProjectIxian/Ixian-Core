// Copyright (C) 2017-2020 Ixian OU
// This file is part of Ixian Core - www.github.com/ProjectIxian/Ixian-Core
//
// Ixian Core is free software: you can redistribute it and/or modify
// it under the terms of the MIT License as published
// by the Open Source Initiative.
//
// Ixian Core is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// MIT License for more details.

using IXICore.Meta;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace IXICore.Meta
{
    public class UpdateVerify
    {
        private static readonly object threadLock = new object();
        private static Thread fetchUpdateThread;

        private static int checkInterval = 6 * 60 * 60;

        // artificially set last check so far into the past that next check will happen in ~2 min, no matter what the interval is
        private static DateTime lastVersionCheck = DateTime.Now.AddSeconds(-(checkInterval + 10));

        public static string signPubKey = "<RSAKeyValue><Modulus>uoqtGaAoQBTkZUuxuBsusUsHYb5sy0iYJPuE+zhM9ZMySCQK3PevZvhqj9bdEv82A/cl0lYWTWk9ZU2sLAm1n6DLFwCwC8AWShv3Il8y8L4oCbDMfyBWMY9yPq5XSQnplrfR5rER/MWt+XQX/cJeEOd0prNgIYSPluo7u+h+fM2CzMfv5vFtN/E1HSxKUVhP8wkGmOoxXo1EfIqzEHlg4BO0z+hNEIdiXopvwOVkDbetWnOXnwOkOC+bcvPWFP3RYfFiez7GStJFVJhs1lc7wM3PmotzoO7/4NyuxVueydRBERhGbq+KV0FfggPshMh/+srpbu6etiLyW7KtZX8ARgxasZVHNggIRygM4LYLk/ppcvHCohEfmYsrTo1Bk0CQe1JFIbFIWXLK+5VDhpVc0w1HpeyjuB/fL8vEHBhOfuNL8frhfpFWTzzPF2IBd59E6T8TQCM/K2DBuxWAEws8nqcNpYsjocuRw2OZmbjzPcerCo2haVaezT3YbNZHAflzSxI+VmURyuXBw+76IV63gJTwGWpZ4A+/D6ubOuqrssfTBRYdjJLTecb3D7aBd2JpKVPVfSN61zSrkt++eEgkikkFVSqQ2ILGB7azzaGPCm4RL0ZMa47BSfMcPSMM4oN91mbVWSWaspCQe0TjbeIR9jl18Y1jcvHloiX8rVC5YKWPPYG8YuGcKq8U0Hp2lkeCnXqKfvUGoH/e6ufkwBCqJZle2S+wmRHKFlEuMHxs1sUEgleZcnQQ6lXYuwpoIXKB6NxMrSTPWM+QHWVnU0tL0X3MYIvCxT6olYV1H9Rfrm3p9lP1vJME7H0sudypXlsUzddMQtqLAjpS7Sgl1RJ7CwnYQa/nfrMYokaWhXdHeT0XpdANyiRdlklrHE19Jlb4Z/wpK+P4zYfrx/8Mj6J+ktxJuyHQVj1wVwH9qmsWfVvwJ4xPKBQcfS4aJ6iUnGwY1HuywETGgx4eAp4vsVjaR7VCE/JPA4kwLCKAcXAT2BwNMC3rCG+4XouyZuZjYLGGTuRkqpXQ1mTBKXSg6t9iUsc25V9k4jS1d+y7qumDT6jqsLavvvwkBKpu1ONgew9Pqbc9GLXBmXSHIhUdFiFF9d3cvWv5m3QhRKdCW0jQ8xUAlxgZW27a+09YppVwvex6/8fmhx9nldpC1I24EyyrBXWgIABAvxv0gAo0CzPTLIOh1c8oOapMaie2aAR3Epfna+q/Z/h5ofrx9HmP+xAxhKHOHrRWo+EybceoWh/mmMRjnqmm1G4DrHsW90Z56qZWdX4QGMXpP9ZhVvxqFj1IxWkzOHk5XAOq44UQq2hFT46bAbe+s5JSOGfvMzzagFC5LuuAeelFTUfRR7wFClM5kQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

        public static string updateUrl = null;

        /// <summary>
        ///  Fetching version information is currently in progress.
        /// </summary>
        public static bool inProgress { get; private set; } = false;
        /// <summary>
        ///  Resulting version string - fetched from ixian.io
        /// </summary>
        public static string serverVersion { get; private set; } = "";
        /// <summary>
        ///  Version string is ready in `serverVersion`.
        /// </summary>
        public static bool ready { get; private set; } = false;
        /// <summary>
        ///  There was an error while fetching version information, or it was signed incorrectly.
        /// </summary>
        public static bool error { get; private set; } = false;

        /// <summary>
        ///  Init updater
        /// </summary>
        public static void init(string url, int check_interval, string sign_pub_key = null)
        {
            updateUrl = url;
            checkInterval = check_interval;
            lastVersionCheck = DateTime.Now.AddSeconds(-(checkInterval + 10));
            if(sign_pub_key != null)
            {
                signPubKey = sign_pub_key;
            }
        }

        /// <summary>
        ///  Initiate version check asynchronously.
        /// </summary>
        public static void checkVersion()
        {
            if(updateUrl == null)
            {
                Logging.error("Cannot check version, URL is null");
                return;
            }

            lock (threadLock)
            {
                if((DateTime.Now - lastVersionCheck).TotalSeconds > checkInterval)
                {
                    if (inProgress) return;
                    lastVersionCheck = DateTime.Now;
                    fetchUpdateThread = new Thread(fetchUpdateVersion);
                    inProgress = true;
                    ready = false;
                    error = false;
                    serverVersion = "";
                    fetchUpdateThread.Start();
                }
            }
        }

        private static void fetchUpdateVersion()
        {
            System.Net.Http.HttpClient http_client = new System.Net.Http.HttpClient();
            try
            {
                var http_get_task = http_client.GetStringAsync(updateUrl);
                http_get_task.Wait();
                string[] update_strings = http_get_task.Result.Split(';');
                string version_text = update_strings[0];
                string signature = update_strings[1];
                if (!checkSignature(version_text, signature))
                {
                    throw new Exception("Incorrect signature for the retrieved version text!");
                }
                serverVersion = version_text;
            }
            catch (Exception ex)
            {
                Logging.warn(String.Format("Error while checking {0} for version update: {1}", updateUrl, ex.Message));
                error = true;
            }
            finally
            {
                inProgress = false;
                ready = true;
            }
        }


        private static bool checkSignature(string version, string base64Sig)
        {
            byte[] signature_bytes = Convert.FromBase64String(base64Sig);
            byte[] version_bytes = ASCIIEncoding.ASCII.GetBytes(version);
            RSACryptoServiceProvider r = new RSACryptoServiceProvider();
            r.FromXmlString(signPubKey);
            return r.VerifyData(version_bytes, signature_bytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        }
    }
}
