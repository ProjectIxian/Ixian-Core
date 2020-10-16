using IXICore.Network;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.Linq;

namespace IXICore.Inventory
{
    class PendingInventoryItem
    {
        public InventoryItem item;
        public bool processed;
        public long lastRequested;
        public int retryCount;
        public List<RemoteEndpoint> endpoints;

        public PendingInventoryItem(InventoryItem item)
        {
            this.item = item;
            processed = false;
            retryCount = 0;
            lastRequested = Clock.getTimestamp();
            endpoints = new List<RemoteEndpoint>();
        }
    }

    abstract class InventoryCache
    {
        protected int maxInventoryItems = 600000;
        protected int maxRetryCount = 10;
        protected int pendingTimeOut = 5;
        protected Dictionary<InventoryItemTypes, Dictionary<byte[], PendingInventoryItem>> inventory = null;

        public InventoryCache()
        {
            inventory = new Dictionary<InventoryItemTypes, Dictionary<byte[], PendingInventoryItem>>();
            inventory.Add(InventoryItemTypes.block, new Dictionary<byte[], PendingInventoryItem>(new ByteArrayComparer()));
            inventory.Add(InventoryItemTypes.blockSignature, new Dictionary<byte[], PendingInventoryItem>(new ByteArrayComparer()));
            inventory.Add(InventoryItemTypes.keepAlive, new Dictionary<byte[], PendingInventoryItem>(new ByteArrayComparer()));
            inventory.Add(InventoryItemTypes.transaction, new Dictionary<byte[], PendingInventoryItem>(new ByteArrayComparer()));
        }

        public PendingInventoryItem get(InventoryItemTypes type, byte[] hash)
        {
            lock (inventory)
            {
                var inventory_types = inventory[type];
                if (!inventory_types.ContainsKey(hash))
                {
                    return null;
                }
                return inventory_types[hash];
            }
        }

        public PendingInventoryItem add(InventoryItem item, RemoteEndpoint endpoint)
        {
            lock (inventory)
            {
                var inventory_types = inventory[item.type];
                if (!inventory_types.ContainsKey(item.hash))
                {
                    PendingInventoryItem pii = new PendingInventoryItem(item);
                    pii.endpoints.Add(endpoint);
                    inventory_types.Add(item.hash, pii);
                    if(inventory_types.Count() > maxInventoryItems)
                    {
                        inventory_types.Remove(inventory_types.Keys.First());
                    }
                    return pii;
                }
                else
                {
                    PendingInventoryItem pii = inventory_types[item.hash];
                    if (!pii.endpoints.Contains(endpoint))
                    {
                        pii.endpoints.Add(endpoint);
                    }
                    return pii;
                }
            }
        }

        private bool remove(InventoryItemTypes type, byte[] hash)
        {
            lock (inventory)
            {
                return inventory[type].Remove(hash);
            }
        }

        public static InventoryItem decodeInventoryItem(byte[] bytes)
        {
            InventoryItemTypes type = (InventoryItemTypes)bytes.GetVarInt(0);
            InventoryItem item = null;
            switch (type)
            {
                case InventoryItemTypes.block:
                    item = new InventoryItemBlock(bytes);
                    break;
                case InventoryItemTypes.transaction:
                    item = new InventoryItem(bytes);
                    break;
                case InventoryItemTypes.keepAlive:
                    item = new InventoryItemKeepAlive(bytes);
                    break;
                case InventoryItemTypes.blockSignature:
                    item = new InventoryItemSignature(bytes);
                    break;
            }
            return item;
        }

        public bool processInventoryItem(InventoryItemTypes type, byte[] hash)
        {
            lock(inventory)
            {
                var pii = get(type, hash);
                return processInventoryItem(pii);
            }
        }

        public bool processInventoryItem(PendingInventoryItem pii)
        {
            Random rnd = new Random();
            var endpoints = pii.endpoints.OrderBy(x => rnd.Next());
            foreach (var endpoint in endpoints)
            {
                if (endpoint.isConnected() && endpoint.helloReceived)
                {
                    if(sendInventoryRequest(pii.item, endpoint))
                    {
                        pii.lastRequested = Clock.getTimestamp();
                        if(pii.retryCount > maxRetryCount)
                        {
                            pii.processed = true;
                        }
                        pii.retryCount++;
                        return true;
                    }else
                    {
                        pii.processed = true;
                    }
                    return false;
                }
            }
            return false;
        }

        public void processCache()
        {
            lock(inventory)
            {
                long expiration_time = Clock.getTimestamp() - pendingTimeOut;
                foreach(var types in inventory)
                {
                    foreach(var item in types.Value)
                    {
                        if (item.Value.processed)
                        {
                            continue;
                        }
                        if (item.Value.lastRequested > expiration_time)
                        {
                            continue;
                        }
                        processInventoryItem(item.Value);
                    }
                }
            }
        }

        virtual public bool setProcessedFlag(InventoryItemTypes type, byte[] hash, bool processed)
        {
            lock(inventory)
            {
                if (!inventory[type].ContainsKey(hash))
                {
                    if(processed)
                    {
                        inventory[type].Add(hash, new PendingInventoryItem(new InventoryItem(type, hash)) { processed = processed });
                    }
                }else
                {
                    inventory[type][hash].processed = processed;
                    return true;
                }
            }
            return false;
        }

        abstract protected bool sendInventoryRequest(InventoryItem item, RemoteEndpoint endpoint);
    }
}