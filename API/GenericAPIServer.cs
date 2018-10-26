using DLT.Meta;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
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

        // Start the API server
        public void start(string listen_url)
        {
            continueRunning = true;

            listenURL = listen_url;
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
        protected virtual void onUpdate()
        {

        }

        protected void apiLoop()
        {
            // Start a listener on the loopback interface
            listener = new HttpListener();
            try
            {
                listener.Prefixes.Add(listenURL);
                listener.Start();
            }
            catch (Exception ex)
            {
                Logging.error("Cannot initialize API server! The error was: " + ex.Message);
                return;
            }

            while (continueRunning)
            {
                onUpdate();
            }

            Thread.Yield();
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
                Logging.error(String.Format("APIServer: {0}", e.ToString()));
            }
        }
    }
}
