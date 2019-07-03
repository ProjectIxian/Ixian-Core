using DLT.Meta;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace DLT
{
    namespace Network
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


            static public void configureNetwork()
            {
                // Network configuration
                UPnP upnp = new UPnP();

                if (Config.externalIp != "" && IPAddress.TryParse(Config.externalIp, out _))
                {
                    NetworkClientManager.publicIP = Config.externalIp;
                }
                else
                {
                    NetworkClientManager.publicIP = "";
                    List<IPAndMask> local_ips = CoreNetworkUtils.GetAllLocalIPAddressesAndMasks();
                    foreach (IPAndMask local_ip in local_ips)
                    {
                        if (IPv4Subnet.IsPublicIP(local_ip.Address))
                        {
                            Logging.info(String.Format("Public IP detected: {0}, mask {1}.", local_ip.Address.ToString(), local_ip.SubnetMask.ToString()));
                            NetworkClientManager.publicIP = local_ip.Address.ToString();
                        }
                    }
                    if (NetworkClientManager.publicIP == "")
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
                                    if (upnp.MapPublicPort(NetworkServer.listeningPort, primary_local))
                                    {
                                        NetworkClientManager.publicIP = public_ip.Result.ToString(); //upnp.getMappedIP();
                                        Logging.info(string.Format("Network configured. Public IP is: {0}", NetworkClientManager.publicIP));
                                    }
                                }
                                else
                                {
                                    Logging.warn("UPnP configuration failed.");
                                }
                            }

                        }
                    }
                }
            }

        }
    }
}
