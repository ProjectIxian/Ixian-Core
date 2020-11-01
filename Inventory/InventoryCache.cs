using IXICore.Meta;
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
            lastRequested = 0;
            endpoints = new List<RemoteEndpoint>();
        }
    }

    abstract class InventoryCache
    {
        protected int maxRetryCount = 5;
        protected int pendingTimeOut = 200;
        protected Dictionary<InventoryItemTypes, Dictionary<byte[], PendingInventoryItem>> inventory = null;

        Random rnd = new Random();

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
                var inventory_list = inventory[item.type];
                if (!inventory_list.ContainsKey(item.hash))
                {
                    PendingInventoryItem pii = new PendingInventoryItem(item);
                    pii.endpoints.Add(endpoint);
                    inventory_list.Add(item.hash, pii);
                    truncateInventory(item.type);
                    return pii;
                }
                else
                {
                    PendingInventoryItem pii = inventory_list[item.hash];
                    pii.item = item;
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
            InventoryItemTypes type = (InventoryItemTypes)bytes.GetIxiVarInt(0);
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
            var pii = get(type, hash);
            return processInventoryItem(pii);
        }

        public bool processInventoryItem(PendingInventoryItem pii)
        {
            if(pii.processed)
            {
                return false;
            }
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
                }else
                {
                    pii.endpoints.Remove(endpoint);
                }
            }
            return false;
        }

        public void processCache()
        {
            List<PendingInventoryItem> items_to_process = new List<PendingInventoryItem>();
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
                        Logging.trace("Processing inventory cache " + types.Key + ": " + item.Value.lastRequested);
                        items_to_process.Add(item.Value);
                    }
                }
            }
            foreach(var item in items_to_process)
            {
                processInventoryItem(item);
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
                        var inventory_list = inventory[type];
                        inventory_list.Add(hash, new PendingInventoryItem(new InventoryItem(type, hash)) { processed = processed });
                        truncateInventory(type);
                    }
                }
                else
                {
                    inventory[type][hash].processed = processed;
                    return true;
                }
            }
            return false;
        }

        abstract protected bool sendInventoryRequest(InventoryItem item, RemoteEndpoint endpoint);

        public long getItemCount()
        {
            long count = 0;
            foreach (var type in inventory)
            {
                count += type.Value.Count();
            }
            return count;
        }

        protected void truncateInventory(InventoryItemTypes type)
        {
            var inventory_list = inventory[type];
            int max_items = 100000;
            switch(type)
            {
                case InventoryItemTypes.block:
                    max_items = 100;
                    break;

                case InventoryItemTypes.blockSignature:
                    max_items = 200000;
                    break;

                case InventoryItemTypes.transaction:
                case InventoryItemTypes.keepAlive:
                    max_items = 600000;
                    break;
            }
            if (inventory_list.Count() > max_items)
            {
                inventory_list.Remove(inventory_list.Keys.First());
            }
        }
    }
}