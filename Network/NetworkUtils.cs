using IXICore.Meta;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace IXICore.Network
{
    public class NetworkUtils
    {

        public static string resolveHostname(string hostname)
        {
            // Check for IP
            IPAddress address;
            if (IPAddress.TryParse(hostname, out address))
            {
                switch (address.AddressFamily)
                {
                    case System.Net.Sockets.AddressFamily.InterNetwork:
                        return hostname;
                    case System.Net.Sockets.AddressFamily.InterNetworkV6:
                        return hostname;
                    default:
                        break;
                }
            }

            // Check DNS
            try
            {
                IPHostEntry hostEntry;
                hostEntry = Dns.GetHostEntry(hostname);

                // TODO: handle multi-ip hostnames
                foreach (var ip in hostEntry.AddressList)
                {
                    // TODO: handle IPv6 as well
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                    {
                        return ip.ToString();
                    }
                }
            }
            catch (Exception)
            {
                return hostname;
            }

            return "";
        }

        static public bool validateIP(string ip)
        {
            // TODO add local exceptions - 127.0.0.1, ::1, 0.0.0.0 etc...

            IPAddress addr;
            if(IPAddress.TryParse(ip, out addr) && addr.ToString() == ip)
            {
                return true;
            }
            return false;
        }


        static public void configureNetwork(string externalIp, int port)
        {
            // Network configuration
            UPnP upnp = new UPnP();

            if (externalIp != "" && IPAddress.TryParse(externalIp, out _))
            {
                IxianHandler.publicIP = externalIp;
            }
            else
            {
                IxianHandler.publicIP = "";
                List<IPAndMask> local_ips = CoreNetworkUtils.GetAllLocalIPAddressesAndMasks();
                foreach (IPAndMask local_ip in local_ips)
                {
                    if (IPv4Subnet.IsPublicIP(local_ip.Address))
                    {
                        Logging.info(String.Format("Public IP detected: {0}, mask {1}.", local_ip.Address.ToString(), local_ip.SubnetMask.ToString()));
                        IxianHandler.publicIP = local_ip.Address.ToString();
                    }
                }
                if (IxianHandler.publicIP == "")
                {
                    IPAddress primary_local = CoreNetworkUtils.GetPrimaryIPAddress();
                    if (primary_local == null)
                    {
                        Logging.warn("Unable to determine primary IP address.");
                    }
                    else
                    {
                        Logging.warn(String.Format("None of the locally configured IP addresses are public. Attempting UPnP..."));
                        Task<IPAddress> public_ip = upnp.GetExternalIPAddress();
                        if (public_ip.Wait(1000))
                        {
                            if (public_ip.Result != null)
                            {
                                Logging.info(String.Format("UPNP-determined public IP: {0}. Attempting to configure a port-forwarding rule.", public_ip.Result.ToString()));
                                if (upnp.MapPublicPort(port, primary_local))
                                {
                                    IxianHandler.publicIP = public_ip.Result.ToString(); //upnp.getMappedIP();
                                    Logging.info(string.Format("Network configured. Public IP is: {0}", IxianHandler.publicIP));
                                }else
                                {
                                    Logging.warn("UPnP configuration failed, please set port forwarding for port {0} manually.", port);
                                }
                            }
                            else
                            {
                                Logging.warn("UPnP configuration failed, please set port forwarding for port {0} manually.", port);
                            }
                        }

                    }
                }
            }
        }

    }
}
