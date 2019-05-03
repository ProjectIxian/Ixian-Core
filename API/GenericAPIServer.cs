using DLT.Meta;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;

namespace IXICore
{
    class JsonError
    {
        public int code = 0;
        public string message = null;
    }

    class JsonResponse
    {
        public object result = null;
        public JsonError error = null;
        public string id = null;
    }

    class GenericAPIServer
    {
        protected HttpListener listener;
        protected Thread apiControllerThread;
        protected bool continueRunning;
        protected string listenURL;
        protected ThreadLiveCheck TLC;

        protected Dictionary<string, string> authorizedUsers;

        // Start the API server
        public void start(string listen_url, Dictionary<string, string> authorizedUsers = null)
        {
            continueRunning = true;

            listenURL = listen_url;

            this.authorizedUsers = authorizedUsers;

            apiControllerThread = new Thread(apiLoop);
            apiControllerThread.Name = "API_Controller_Thread";
            TLC = new ThreadLiveCheck();
            apiControllerThread.Start();
        }

        // Stop the API server
        public void stop()
        {
            continueRunning = false;
            try
            {
                // Stop the listener
                listener.Stop();
            }
            catch (Exception)
            {
                Logging.info("API server already stopped.");
            }
        }

        // Override the onUpdate handler
        protected virtual void onUpdate(HttpListenerContext context)
        {

        }

        protected bool isAuthorized(HttpListenerContext context)
        {
            if(authorizedUsers == null)
            {
                return true;
            }

            // No authorized users provided, allow access to everyone
            if(authorizedUsers.Count < 1)
            {
                return true;
            }

            if(context.User == null)
            {
                return false;
            }

            HttpListenerBasicIdentity identity = (HttpListenerBasicIdentity)context.User.Identity;

            if(authorizedUsers.ContainsKey(identity.Name))
            {
                if(authorizedUsers[identity.Name] == identity.Password)
                {
                    return true;
                }
            }

            return false;
        }

        protected void apiLoop()
        {
            // Start a listener on the loopback interface
            listener = new HttpListener();
            try
            {
                listener.Prefixes.Add(listenURL);
                if (authorizedUsers != null && authorizedUsers.Count > 0)
                {
                    listener.AuthenticationSchemes = AuthenticationSchemes.Basic;
                }
                listener.Start();
            }
            catch (Exception ex)
            {
                Logging.error("Cannot initialize API server! The error was: " + ex.Message);
                return;
            }

            while (continueRunning)
            {
                HttpListenerContext context = null;
                try
                {
                    context = listener.GetContext();
                }
                catch(Exception ex)
                {
                    if (continueRunning)
                    {
                        Logging.error("Error in API server! " + ex.Message);
                    }
                    return;
                }

                if(context != null)
                {
                    if(isAuthorized(context))
                    {
                        onUpdate(context);
                    }else
                    {
                        context.Response.StatusCode = 401;
                        context.Response.StatusDescription = "401 Unauthorized";
                    }
                    context.Response.Close();
                }
                TLC.Report();
                Thread.Yield();
            }

        }

        protected void sendError(HttpListenerContext context, string errorString)
        {
            sendResponse(context.Response, errorString);
        }

        protected void sendResponse(HttpListenerResponse responseObject, string responseString)
        {
            byte[] buffer = System.Text.Encoding.UTF8.GetBytes(responseString);

            try
            {
                responseObject.ContentLength64 = buffer.Length;
                System.IO.Stream output = responseObject.OutputStream;
                output.Write(buffer, 0, buffer.Length);
                output.Close();
            }
            catch (Exception e)
            {
                if (continueRunning)
                {
                    Logging.error(String.Format("APIServer: {0}", e));
                }
            }
        }

        public void sendResponse(HttpListenerResponse responseObject, JsonResponse response)
        {
            string responseString = JsonConvert.SerializeObject(response);

            byte[] buffer = Encoding.UTF8.GetBytes(responseString);

            try
            {
                responseObject.ContentLength64 = buffer.Length;
                Stream output = responseObject.OutputStream;
                output.Write(buffer, 0, buffer.Length);
                output.Close();
            }
            catch (Exception e)
            {
                if (continueRunning)
                {
                    Logging.error(String.Format("APIServer: {0}", e));
                }
            }
        }

        public void sendResponse(HttpListenerResponse responseObject, byte[] buffer)
        {
            try
            {
                responseObject.ContentLength64 = buffer.Length;
                Stream output = responseObject.OutputStream;
                output.Write(buffer, 0, buffer.Length);
                output.Close();
            }
            catch (Exception e)
            {
                if (continueRunning)
                {
                    Logging.error(String.Format("APIServer: {0}", e));
                }
            }
        }

        protected void onResources(HttpListenerContext context)
        {
            string name = "";
            for (int i = 2; i < context.Request.Url.Segments.Count(); i++)
            {
                name += context.Request.Url.Segments[i];
            }

            if (name != null && name.Length > 1 && !name.EndsWith("/"))
            {
                name = name.Replace('/', Path.DirectorySeparatorChar);
                if (File.Exists("html" + Path.DirectorySeparatorChar + name))
                {
                    if (name.EndsWith(".css", StringComparison.OrdinalIgnoreCase))
                    {
                        context.Response.ContentType = "text/css";
                    }
                    else if (name.EndsWith(".js", StringComparison.OrdinalIgnoreCase))
                    {
                        context.Response.ContentType = "text/javascript";
                    }
                    else
                    {
                        context.Response.ContentType = "application/octet-stream";
                    }
                    sendResponse(context.Response, File.ReadAllBytes("html" + Path.DirectorySeparatorChar + name));
                    return;
                }
            }
            // 404
            context.Response.ContentType = "text/plain";
            context.Response.StatusCode = 404;
            context.Response.StatusDescription = "404 File not found";
            sendResponse(context.Response, "404 File not found");
        }

        // Send the embedded wallet html file
        protected void sendWallet(HttpListenerContext context)
        {
            // Fetch the wallet html file from the exe
            string wallet_html = File.ReadAllText("html" + Path.DirectorySeparatorChar + "wallet.html");
            // Replace the js API location
            string result = wallet_html.Replace("#IXIAN#NODE#URL#", listenURL);
            // Set the content type to html to show the wallet page
            context.Response.ContentType = "text/html";
            sendResponse(context.Response, result);
        }
    }
}
