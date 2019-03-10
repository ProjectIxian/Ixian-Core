using DLT.Meta;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace DLT
{
    public class NetworkEvents
    {
        // Message codes are for the most part pairs (send/receive)
        public enum Type
        {
            keepAlive,
            transactionFrom,
            transactionTo
        }


        // Prepares an event message data with a provided type and address
        public static byte[] prepareEventMessageData(int type, byte[] address)
        {
            if (address == null)
                return null;

            byte[] data = null;
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(type);
                    writer.Write(address.Length);
                    writer.Write(address);
                    data = m.ToArray();
                }
            }

            return data;
        }

        // Handles a received attach event message and adds event subscriptions for the provided endpoint
        public static void handleAttachEventMessage(byte[] data, RemoteEndpoint endpoint)
        {
            if (data == null || endpoint == null)
            {
                Logging.warn(string.Format("Invalid protocol message event data"));
                return;
            }

            using (MemoryStream m = new MemoryStream(data))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    int type = reader.ReadInt32();
                    int addrLen = reader.ReadInt32();
                    byte[] address = reader.ReadBytes(addrLen);

                    endpoint.attachEvent((NetworkEvents.Type)type, address);
                }
            }
        }

        // Handles a received detach event message and removes event subscriptions for the provided endpoint
        public static void handleDetachEventMessage(byte[] data, RemoteEndpoint endpoint)
        {
            if (data == null || endpoint == null)
            {
                Logging.warn(string.Format("Invalid protocol message event data"));
                return;
            }

            using (MemoryStream m = new MemoryStream(data))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    int type = reader.ReadInt32();
                    int addrLen = reader.ReadInt32();
                    byte[] address = reader.ReadBytes(addrLen);

                    endpoint.detachEvent((NetworkEvents.Type)type, address);
                }
            }
        }

    }
}
