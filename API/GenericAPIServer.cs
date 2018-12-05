using DLT.Meta;
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;

namespace IXICore
{
    class GenericAPIServer
    {
        // Public accessible
        public bool forceShutdown = false;


        protected HttpListener listener;
        protected Thread apiControllerThread;
        protected bool continueRunning;
        protected string listenURL;

        protected Dictionary<string, string> authorizedUsers;

        // Start the API server
        public void start(string listen_url, Dictionary<string, string> authorizedUsers = null)
        {
            continueRunning = true;

            listenURL = listen_url;

            this.authorizedUsers = authorizedUsers;

            apiControllerThread = new Thread(apiLoop);
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
                    Logging.error("Error in API server! " + ex.Message);
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
                Logging.error(String.Format("APIServer: {0}", e));
            }
        }
    }
}
