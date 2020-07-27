using IXICore.Meta;
using System;
using System.IO;

namespace IXICore
{
    public enum SpixiMessageCode
    {
        chat,
        getNick,
        nick,
        requestAdd,
        acceptAdd,
        sentFunds,
        requestFunds,
        keys,
        msgRead,
        msgReceived,
        fileData,
        requestFileData,
        fileHeader,
        acceptFile,
        requestCall,
        acceptCall,
        rejectCall,
        callData,
        requestFundsResponse,
        acceptAddBot,
        botGetMessages,
        appData,
        appRequest,
        fileFullyReceived,
        avatar,
        getAvatar,
        getPubKey,
        pubKey,
        appRequestAccept,
        appRequestReject,
        appRequestError,
        appEndSession,
        botAction,
        msgDelete,
        msgReaction,
        msgTyping,
        msgError,
        leave,
        leaveConfirmed
    }

    // TODO TODO TODO add checksum from StreamMessage/parent message to SpixiMessage when encrypted and when StreamMessage isn't signed and compare the checksums, to make sure StreamMessage hasn't been tampered with

    class SpixiMessage
    {
        public SpixiMessageCode type;          // Spixi Message type
        public byte[] data = null;             // Actual message data
        public int channel = 0;

        public SpixiMessage()
        {
            type = SpixiMessageCode.chat;
            data = null;
        }

        public SpixiMessage(SpixiMessageCode in_type, byte[] in_data, int in_channel = 0)
        {
            type = in_type;
            data = in_data;
            channel = in_channel;
        }

        public SpixiMessage(byte[] bytes)
        {
            try
            {
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        int message_type = reader.ReadInt32();
                        type = (SpixiMessageCode)message_type;

                        int data_length = reader.ReadInt32();
                        if (data_length > 0)
                            data = reader.ReadBytes(data_length);

                        if(reader.BaseStream.Length - reader.BaseStream.Position > 0)
                        {
                            channel = reader.ReadInt32();
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Logging.error("Exception occured while trying to construct SpixiMessage from bytes: " + e);
                type = 0;
                data = null;
                channel = 0;
            }
        }

        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    // Write the type
                    writer.Write((int)type);

                    // Write the data
                    if (data != null)
                    {
                        writer.Write(data.Length);
                        writer.Write(data);
                    }else
                    {
                        writer.Write(0);
                    }

                    if (channel != 0)
                    {
                        writer.Write(channel);
                    }
                }
                return m.ToArray();
            }
        }

    }
}
