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
using Open.Nat;
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace IXICore
{
    public class UPnP
    {
        private NatDiscoverer natDiscoverer;
        private NatDevice routerDevice;
        private IPAddress mappedLocalIP;
        private int mappedPublicPort;

        public UPnP()
        {
            natDiscoverer = new NatDiscoverer();
        }

        private bool acquireRouterDevice()
        {
            if (routerDevice != null)
            {
                return true;
            }
            try
            {
                CancellationTokenSource cts = new CancellationTokenSource();
                cts.CancelAfter(4500);
                Task<NatDevice> devicesDiscoveryTask = natDiscoverer.DiscoverDeviceAsync(PortMapper.Upnp, cts);
                if (devicesDiscoveryTask.Wait(5000) == true)
                {
                    NatDevice device = devicesDiscoveryTask.Result;
                    Logging.info(String.Format("Found UPnP device: {0}", device.ToString()));
                    routerDevice = device;
                    return true;
                }
            }
            catch (AggregateException) { }
            return false;
        }

        private Mapping GetPublicPortMappingInternal(int public_port)
        {
            if (acquireRouterDevice() == true)
            {
                try
                {
                    Task<IEnumerable<Mapping>> mappings = routerDevice.GetAllMappingsAsync();
                    if (mappings.Wait(5000) == true)
                    {
                        foreach (Mapping m in mappings.Result)
                        {
                            if (m.PublicPort == public_port)
                            {
                                return m;
                            }
                        }
                    }
                }
                catch (MappingException ex)
                {
                    Logging.warn(String.Format("Error while obtaining current port mapping: {0}", ex.Message));
                }
            }
            return null;
        }

        public async Task<IPAddress> GetExternalIPAddress()
        {
            Logging.info("Attempting to discover external address. This is automatic, if the router supports UPnP.");
            Logging.info("This may take up to 10 seconds...");
            if (acquireRouterDevice() == true)
            {
                Logging.info(String.Format("Found UPnP device: {0}", routerDevice.ToString()));
                try
                {
                    IPAddress externalIP = await routerDevice.GetExternalIPAsync();
                    Logging.info(String.Format("Found external IP address: {0}", externalIP.ToString()));
                    return externalIP;
                }
                catch (Exception ex)
                {
                    Logging.warn(String.Format("Error while retrieving the external IP: {0}", ex));
                }
            }
            //
            Logging.info("UPnP router is not present or is using an incompatible version of the UPnP protocol.");
            return null;
        }

        public IPAddress GetPublicPortMapping(int public_port)
        {
            if (public_port <= 0 || public_port > 65535)
            {
                Logging.error(String.Format("Invalid port number: {0}", public_port));
                return null;
            }
            Logging.info(String.Format("Attempting to discover existing NAT port mapping for port {0}.", public_port));
            if (acquireRouterDevice() == true)
            {
                Mapping m = GetPublicPortMappingInternal(public_port);
                return m.PrivateIP;
            }
            Logging.info("UPnP router is not present or is using an incompatible version of the UPnP protocol.");
            return null;
        }

        public bool MapPublicPort(int public_port, IPAddress local_ip)
        {
            if (public_port <= 0 || public_port > 65535)
            {
                Logging.error(String.Format("Invalid port number: {0}", public_port));
                return false;
            }

            Logging.info(String.Format("Attempting to map external port {0} to local IP {1}", public_port, local_ip.ToString()));
            if (acquireRouterDevice() == true)
            {
                try
                {
                    Mapping m = new Mapping(Protocol.Tcp, local_ip, public_port, public_port, 0, "Ixian DLT automatic port mapping");
                    Task mapPortTask = routerDevice.CreatePortMapAsync(m);
                    if (mapPortTask.Wait(5000) == true)
                    {
                        Logging.info(String.Format("External port successfully {0} mapped to {1}:{2} via UPnP", public_port, local_ip.ToString(), public_port));
                        mappedLocalIP = local_ip;
                        mappedPublicPort = public_port;
                        return true;
                    }
                }
                catch (MappingException ex)
                {
                    Logging.error(String.Format("Error while mapping public port {0} to {1}:{2}: {3}", public_port, local_ip.ToString(), public_port, ex.Message));
                }
                catch (Exception e)
                {
                    Logging.error(String.Format("Inner exception for uPnP: {0}", e.Message));
                }
            }
            Logging.info("UPnP router is not present or is using an incompatible version of the UPnP protocol.");
            return false;
        }

        // Returns the local mapped IP
        public string getMappedIP()
        {
            return string.Format("{0}", mappedLocalIP);
        }

        public void RemoveMapping()
        {
            if (routerDevice != null)
            {
                if (mappedLocalIP != null)
                {
                    Logging.info(String.Format("Removing previously mapped: {0} -> {1}:{2}", mappedPublicPort, mappedLocalIP.ToString(), mappedPublicPort));
                    try
                    {
                        Mapping m = GetPublicPortMappingInternal(mappedPublicPort);
                        if (m != null)
                        {
                            Task deleteMapTask = routerDevice.DeletePortMapAsync(m);
                            deleteMapTask.Wait(5000);
                            mappedPublicPort = 0;
                            mappedLocalIP = null;
                        }
                    }
                    catch (MappingException ex)
                    {
                        Logging.error(String.Format("Unable to remove port mapping for public port {0} to {1}:{2}: {3}",
                            mappedPublicPort,
                            mappedLocalIP.ToString(), mappedPublicPort,
                            ex.Message));
                    }
                }
            }
        }
    }
}
