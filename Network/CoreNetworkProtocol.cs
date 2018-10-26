using DLT;
using DLT.Meta;
using DLT.Network;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace IXICore
{
    public class CoreProtocolMessage
    {
        // Returns a specified header checksum
        public static byte getHeaderChecksum(byte[] header)
        {
            byte sum = 0x7F;
            for (int i = 0; i < header.Length; i++)
            {
                sum ^= header[i];
            }
            return sum;
        }

        // Prepare a network protocol message. Works for both client-side and server-side
        public static byte[] prepareProtocolMessage(ProtocolMessageCode code, byte[] data, byte[] checksum = null)
        {
            byte[] result = null;

            // Prepare the protocol sections
            int data_length = data.Length;

            if (data_length > CoreConfig.maxMessageSize)
            {
                Logging.error(String.Format("Tried to send data bigger than max allowed message size - {0} with code {1}.", data_length, code));
                return null;
            }

            byte[] data_checksum = checksum;

            if (checksum == null)
            {
                data_checksum = Crypto.sha512sqTrunc(data);
            }

            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    // Protocol sections are code, length, checksum, data
                    // Write each section in binary, in that specific order
                    writer.Write((byte)'X');
                    writer.Write((int)code);
                    writer.Write(data_length);
                    writer.Write(data_checksum);

                    writer.Flush();
                    m.Flush();

                    byte header_checksum = getHeaderChecksum(m.ToArray());
                    writer.Write(header_checksum);

                    writer.Write((byte)'I');
                    writer.Write(data);
                }
                result = m.ToArray();
            }

            return result;
        }
    }
}
