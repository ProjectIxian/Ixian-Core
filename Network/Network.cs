using DLT.Meta;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using IXICore;

namespace DLT
{
    namespace Network
    {
        // Message codes are for the most part pairs (send/receive)
        public enum ProtocolMessageCode
        {
            hello,
            helloData,
            bye,
            getBlock,
            blockData,
            getMeta,
            metaData,
            getWallet,
            walletData,
            getTransaction,
            transactionData,
            syncPoolState,
            poolState,
            syncWalletState,
            walletState,
            newWallet,
            newTransaction,
            newBlock,
            getNeighbors,
            neighborData,
            getWalletStateChunk,
            walletStateChunk,
            syncPresenceList,
            presenceList,
            updatePresence,
            removePresence,
            s2data,
            s2failed,
            s2signature,
            s2keys,
            ping,
            pong,
            getBalance,
            balance,
            keepAlivePresence,
            getPresence,
            getBlockTransactions,
            transactionsChunk,
            getUnappliedTransactions,
            extend,
            attachEvent,
            detachEvent,
            newBlockSignature,
            getBlockSignatures,
            blockSignatureChunk
        }

        public enum RemoteEndpointState
        {
            Initial,
            Established,
            Closed
        }

        public class IPv4Subnet
        {
            private IPAddress subnet;
            private IPAddress mask;

            // Well known subnets:
            public static readonly IPv4Subnet PrivateClassA = IPv4Subnet.FromCIDR("10.0.0.0/8");
            public static readonly IPv4Subnet SharedAddress = IPv4Subnet.FromCIDR("100.64.0.0/10");
            public static readonly IPv4Subnet Loopback = IPv4Subnet.FromCIDR("127.0.0.0/8");
            public static readonly IPv4Subnet LinkLocal = IPv4Subnet.FromCIDR("169.254.0.0/16");
            public static readonly IPv4Subnet PrivateClassB = IPv4Subnet.FromCIDR("172.16.0.0/12");
            public static readonly IPv4Subnet IETF = IPv4Subnet.FromCIDR("192.0.0.0/24");
            public static readonly IPv4Subnet Dummy = IPv4Subnet.FromCIDR("192.0.0.8/32");
            public static readonly IPv4Subnet PortControlAnycast = IPv4Subnet.FromCIDR("192.0.0.9/32");
            public static readonly IPv4Subnet NatAnycastTraversal = IPv4Subnet.FromCIDR("192.0.0.10/32");
            public static readonly IPv4Subnet Nat64Discovery = IPv4Subnet.FromCIDR("192.0.0.170/32");
            public static readonly IPv4Subnet DNS64Discovery = IPv4Subnet.FromCIDR("192.0.0.171/32");
            public static readonly IPv4Subnet TestNet1Documentation = IPv4Subnet.FromCIDR("192.0.2.0/24");
            public static readonly IPv4Subnet AS112 = IPv4Subnet.FromCIDR("192.31.196.0/24");
            public static readonly IPv4Subnet AMT = IPv4Subnet.FromCIDR("192.52.193.0/24");
            public static readonly IPv4Subnet Relay6to4 = IPv4Subnet.FromCIDR("192.88.99.0/24");
            public static readonly IPv4Subnet PrivateClassC = IPv4Subnet.FromCIDR("192.168.0.0/16");
            public static readonly IPv4Subnet AS112DirectDelegation = IPv4Subnet.FromCIDR("192.175.48.0/24");
            public static readonly IPv4Subnet Benchmarking = IPv4Subnet.FromCIDR("198.18.0.0/15");
            public static readonly IPv4Subnet TestNet2Documentation = IPv4Subnet.FromCIDR("198.51.100.0/24");
            public static readonly IPv4Subnet TestNet3Documentation = IPv4Subnet.FromCIDR("203.0.113.0/24");
            public static readonly IPv4Subnet Reserved = IPv4Subnet.FromCIDR("240.0.0.0/4");
            public static readonly IPv4Subnet Broadcast = IPv4Subnet.FromCIDR("255.255.255.255/32");

            private IPv4Subnet(IPAddress s, IPAddress m)
            {
                subnet = s;
                mask = m;
            }

            public static IPv4Subnet FromCIDR(String cidr)
            {
                int delim = cidr.IndexOf('/');
                if(delim == -1)
                {
                    throw new ArgumentException(String.Format("Invalid CIDR notation: {0}", cidr));
                }
                string subnet = cidr.Substring(0, delim);
                string mask = cidr.Substring(delim + 1);
                IPAddress s;
                if(IPAddress.TryParse(subnet, out s) == false)
                {
                    throw new ArgumentException(String.Format("Invalid IP address: {0}", subnet));
                }
                if(s.AddressFamily != AddressFamily.InterNetwork)
                {
                    throw new ArgumentException(String.Format("IPv4 address required: {0}", subnet));
                }
                int maskBits;
                if(int.TryParse(mask, out maskBits) == false)
                {
                    throw new ArgumentException(String.Format("Mask bits is not a number: {0}", mask));
                }
                if (maskBits < 0 || maskBits > 32)
                {
                    throw new ArgumentException(String.Format("Invalid mask bits: {0}", mask));
                }
                uint mask_ip = 0xFFFFFFFF << (32 - maskBits);
                byte[] maskBytes = new byte[]
                {
                    (byte)((mask_ip & 0xFF000000) >> 24),
                    (byte)((mask_ip & 0x00FF0000) >> 16),
                    (byte)((mask_ip & 0x0000FF00) >> 8),
                    (byte)((mask_ip & 0x000000FF))
                };
                return new IPv4Subnet(s, new IPAddress(maskBytes));
            }

            public static IPv4Subnet FromSubnet(String subnet, String mask)
            {
                IPAddress s, m;
                if(IPAddress.TryParse(subnet, out s) == false)
                {
                    throw new ArgumentException(String.Format("Invalid IP address: {0}", subnet));
                }
                if (IPAddress.TryParse(mask, out m) == false)
                {
                    throw new ArgumentException(String.Format("Invalid subnet mask: {0}", mask));
                }
                if(s.AddressFamily != AddressFamily.InterNetwork)
                {
                    throw new ArgumentException(String.Format("IPv4 address required: {0}", subnet));
                }
                if(m.AddressFamily != AddressFamily.InterNetwork)
                {
                    throw new ArgumentException(String.Format("IPv4 subnet mask required: {0}", mask));
                }
                return new IPv4Subnet(s, m);
            }

            public static IPv4Subnet FromSubnet(IPAddress subnet, IPAddress mask)
            {
                if (subnet.AddressFamily != AddressFamily.InterNetwork)
                {
                    throw new ArgumentException(String.Format("IPv4 address required: {0}", subnet));
                }
                if (mask.AddressFamily != AddressFamily.InterNetwork)
                {
                    throw new ArgumentException(String.Format("IPv4 subnet mask required: {0}", mask));
                }
                return new IPv4Subnet(subnet, mask);
            }

            public static bool IsPublicIP(IPAddress addr)
            {
                if(addr.AddressFamily != AddressFamily.InterNetwork)
                {
                    throw new ArgumentException(String.Format("IPv4 address is required: {0}", addr.ToString()));
                }
                bool unroutable = PrivateClassA.IsIPInSubnet(addr) ||
                PrivateClassB.IsIPInSubnet(addr) ||
                PrivateClassC.IsIPInSubnet(addr) ||
                Loopback.IsIPInSubnet(addr) ||
                LinkLocal.IsIPInSubnet(addr) ||
                SharedAddress.IsIPInSubnet(addr) ||
                IETF.IsIPInSubnet(addr) ||
                Dummy.IsIPInSubnet(addr) ||
                PortControlAnycast.IsIPInSubnet(addr) ||
                NatAnycastTraversal.IsIPInSubnet(addr) ||
                Nat64Discovery.IsIPInSubnet(addr) ||
                DNS64Discovery.IsIPInSubnet(addr) ||
                TestNet1Documentation.IsIPInSubnet(addr) ||
                AS112.IsIPInSubnet(addr) ||
                AMT.IsIPInSubnet(addr) ||
                Relay6to4.IsIPInSubnet(addr) ||
                AS112DirectDelegation.IsIPInSubnet(addr) ||
                Benchmarking.IsIPInSubnet(addr) ||
                TestNet2Documentation.IsIPInSubnet(addr) ||
                TestNet3Documentation.IsIPInSubnet(addr) ||
                Reserved.IsIPInSubnet(addr) ||
                Broadcast.IsIPInSubnet(addr);
                return !unroutable;
        }

            public bool IsIPInSubnet(IPAddress addr)
            {
                if(addr.AddressFamily != AddressFamily.InterNetwork)
                {
                    throw new ArgumentException(String.Format("IPv4 address required: {0}", addr.ToString()));
                }
                byte[] addressBytes = addr.GetAddressBytes();
                byte[] subnetBytes = subnet.GetAddressBytes();
                byte[] maskBytes = mask.GetAddressBytes();
                for(int i=0;i<addressBytes.Length;i++)
                {
                    if((addressBytes[i] & maskBytes[i]) != (subnetBytes[i] & maskBytes[i]))
                    {
                        return false;
                    }
                }
                return true;
            }

            public bool IsIPInSubnet(String ipaddr)
            {
                if(IPAddress.TryParse(ipaddr, out IPAddress a))
                {
                    return IsIPInSubnet(a);
                } else
                {
                    throw new ArgumentException(String.Format("IPv4 address required: {0}", ipaddr));
                }
            }
        }

        public struct IPAndMask
        {
            public IPAddress Address;
            public IPAddress SubnetMask;
        }



        public class CoreNetworkUtils
        {
            // The list of seed nodes to connect to first. 
            // Domain/IP seperated by : from the port
            public static List<string> seedNodes = new List<string>
                    {
                        "seed1.ixian.io:10234",
                        "seed2.ixian.io:10234",
                        "seed3.ixian.io:10234",
                        "seed4.ixian.io:10234",
                        "seed5.ixian.io:10234"
                    };

            public static List<string> seedTestNetNodes = new List<string>
                    {
                        "seedtest1.ixian.io:11234",
                        "seedtest2.ixian.io:11234",
                        "seedtest3.ixian.io:11234"
                    };

            // Returns the list of seed nodes or test seed nodes if testnet
            public static string[] getSeedNodes(bool isTestNet)
            {
                if(isTestNet)
                {
                    return seedTestNetNodes.ToArray();
                }
                return seedNodes.ToArray();
            }

            // Get the local accessible IP address of this node
            public static string GetLocalIPAddress()
            {
                NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
                foreach(NetworkInterface nic in nics)
                {
                    if(nic.OperationalStatus == OperationalStatus.Up && nic.Supports(NetworkInterfaceComponent.IPv4))
                    {
                        IPInterfaceProperties properties = nic.GetIPProperties();
                        UnicastIPAddressInformationCollection unicast = properties.UnicastAddresses;
                        foreach(UnicastIPAddressInformation unicastIP in unicast)
                        {
                            if(unicastIP.Address.AddressFamily == AddressFamily.InterNetwork)
                            {
                                return unicastIP.Address.ToString();
                            }
                        }
                    }
                }
                throw new Exception("No network adapters with an IPv4 address in the system!");
            }

            // Get a list of all accessible local IP addresses of this node
            public static List<string> GetAllLocalIPAddresses()
            {
                List<String> ips = new List<string>();
                NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
                foreach (NetworkInterface nic in nics)
                {
                    if (nic.OperationalStatus == OperationalStatus.Up && nic.Supports(NetworkInterfaceComponent.IPv4))
                    {
                        IPInterfaceProperties properties = nic.GetIPProperties();
                        UnicastIPAddressInformationCollection unicast = properties.UnicastAddresses;
                        foreach (UnicastIPAddressInformation unicastIP in unicast)
                        {
                            if (unicastIP.Address.AddressFamily == AddressFamily.InterNetwork)
                            {
                                ips.Add(unicastIP.Address.ToString());
                            }
                        }
                    }
                }
                return ips;
            }

            public static IPAddress GetPrimaryIPAddress()
            {
                // This is impossible to find, but we return the first IP which has a gateway configured
                List<IPAndMask> ips = new List<IPAndMask>();
                NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
                foreach (NetworkInterface nic in nics)
                {
                    if (nic.OperationalStatus == OperationalStatus.Up && nic.Supports(NetworkInterfaceComponent.IPv4))
                    {
                        IPInterfaceProperties properties = nic.GetIPProperties();
                        if(properties.GatewayAddresses.Count  == 0)
                        {
                            continue;
                        }
                        UnicastIPAddressInformationCollection unicast = properties.UnicastAddresses;
                        foreach (UnicastIPAddressInformation unicastIP in unicast)
                        {
                            if (unicastIP.Address.AddressFamily == AddressFamily.InterNetwork)
                            {
                                IPv4Subnet subnet = IPv4Subnet.FromSubnet(unicastIP.Address, unicastIP.IPv4Mask);
                                foreach(GatewayIPAddressInformation gw_addr in properties.GatewayAddresses)
                                {
                                    if(gw_addr.Address.AddressFamily == AddressFamily.InterNetwork)
                                    {
                                        if(subnet.IsIPInSubnet(gw_addr.Address))
                                        {
                                            return unicastIP.Address;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                return null;
            }

            public static List<IPAndMask> GetAllLocalIPAddressesAndMasks()
            {
                List<IPAndMask> ips = new List<IPAndMask>();
                NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
                foreach (NetworkInterface nic in nics)
                {
                    if (nic.OperationalStatus == OperationalStatus.Up && nic.Supports(NetworkInterfaceComponent.IPv4))
                    {
                        IPInterfaceProperties properties = nic.GetIPProperties();
                        UnicastIPAddressInformationCollection unicast = properties.UnicastAddresses;
                        foreach (UnicastIPAddressInformation unicastIP in unicast)
                        {
                            if (unicastIP.Address.AddressFamily == AddressFamily.InterNetwork)
                            {
                                ips.Add(new IPAndMask { Address = unicastIP.Address, SubnetMask = unicastIP.IPv4Mask });
                            }
                        }
                    }
                }
                return ips;
            }

            public static bool PingAddressReachable(String full_hostname)
            {
                String[] hn_port = full_hostname.Split(':');
                if(hn_port.Length != 2)
                {
                    return false;
                }
                String hostname = hn_port[0];
                int port;
                if(int.TryParse(hn_port[1], out port) == false)
                {
                    return false;
                }
                TcpClient temp = new TcpClient();
                bool connected = false;
                try
                {
                    Logging.info(String.Format("Testing client connectivity for {0}. Local endpoint: {1}.", full_hostname, temp.Client.LocalEndPoint.ToString()));
                    if (!temp.ConnectAsync(hostname, port).Wait(1000))
                    {
                        return false;
                    }
                    temp.Client.SendTimeout = 500;
                    temp.Client.ReceiveTimeout = 500;
                    temp.Client.Blocking = false;
                    temp.Client.Send(new byte[1], 0, 0);
                    connected = temp.Client.Connected;
                    temp.Client.Send(CoreProtocolMessage.prepareProtocolMessage(ProtocolMessageCode.bye, new byte[1]));
                    temp.Client.Shutdown(SocketShutdown.Both);
                    temp.Close();
                }
                catch (SocketException) { connected = false; }
                return connected;
            }
        }

    }
}