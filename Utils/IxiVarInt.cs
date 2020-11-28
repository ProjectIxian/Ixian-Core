using System;
using System.IO;

namespace IXICore.Utils
{
	// VarInt functions convert long/ulong to variable length bytes and vice-versa and was designed to save space.
	// Our variation of VarInt supports signed and unsigned integers.
	// Negative integers or integers bigger than 0xf7 (247) have an additional byte at the beginning of the byte
	// sequence, which specifies length and type of the number represented.
	//
	// Codes for the initial byte are:
	// 0xf8 - negative short (2 bytes)
	// 0xf9 - negative int (4 bytes)
	// 0xfa - negative long (8 bytes)
	// 0xfb - negative reserved for potential future use (x bytes)
	// 0xfc - short (2 bytes)
	// 0xfd - int (4 bytes)
	// 0xfe - long (8 bytes)
	// 0xff - reserved for potential future use (x bytes)
	//
	// VarInt class extends:
	// - ulong/long with GetVarIntBytes
	// - byte[] with GetVarInt/GetVarUint
	// - BinaryWriter with WriteVarInt
	// - BinaryReader with ReadVarInt/ReadVarUInt
	public static class IxiVarInt
    {
		// long extension
		public static byte[] GetIxiVarIntBytes(this long value)
		{
			bool negative = false;
			if (value < 0)
			{
				negative = true;
				value = -value;
			}

			if (!negative && value < 0xf8)
			{
				return new byte[1] { (byte)value };
			}
			else if (value <= 0xffff)
			{
				byte[] bytes = new byte[3];
				if (negative)
				{
					bytes[0] = 0xf8;
				}
				else
				{
					bytes[0] = 0xfc;
				}
				Array.Copy(BitConverter.GetBytes((ushort)value), 0, bytes, 1, 2);
				return bytes;
			}
			else if (value <= 0xffffffff)
			{
				byte[] bytes = new byte[5];
				if (negative)
				{
					bytes[0] = 0xf9;
				}
				else
				{
					bytes[0] = 0xfd;
				}
				Array.Copy(BitConverter.GetBytes((uint)value), 0, bytes, 1, 4);
				return bytes;
			}
			else
			{
				byte[] bytes = new byte[9];
				if (negative)
				{
					bytes[0] = 0xfa;
				}
				else
				{
					bytes[0] = 0xfe;
				}
				Array.Copy(BitConverter.GetBytes((ulong)value), 0, bytes, 1, 8);
				return bytes;
			}
		}

		// ulong extension
		public static byte[] GetIxiVarIntBytes(this ulong value)
		{
			if (value < 0xf8)
			{
				return new byte[1] { (byte)value };
			}
			else if (value <= 0xffff)
			{
				byte[] bytes = new byte[3];
				bytes[0] = 0xfc;
				Array.Copy(BitConverter.GetBytes((ushort)value), 0, bytes, 1, 2);
				return bytes;
			}
			else if (value <= 0xffffffff)
			{
				byte[] bytes = new byte[5];
				bytes[0] = 0xfd;
				Array.Copy(BitConverter.GetBytes((uint)value), 0, bytes, 1, 4);
				return bytes;
			}
			else
			{
				byte[] bytes = new byte[9];
				bytes[0] = 0xfe;
				Array.Copy(BitConverter.GetBytes(value), 0, bytes, 1, 8);
				return bytes;
			}
		}

		// byte[] extensions
		public static (long num, int bytesRead) GetIxiVarInt(this byte[] data, int offset)
		{
			byte type = data[offset];
			if (type < 0xf8)
			{
				return (data[offset], 1);
			}
			else if (type == 0xf8)
			{
				return (-BitConverter.ToUInt16(data, offset + 1), 3);
			}
			else if (type == 0xf9)
			{
				return (-BitConverter.ToUInt32(data, offset + 1), 5);
			}
			else if (type == 0xfa)
			{
				return (-(long)BitConverter.ToUInt64(data, offset + 1), 9);
			}
			else if (type == 0xfc)
			{
				return (BitConverter.ToUInt16(data, offset + 1), 3);
			}
			else if (type == 0xfd)
			{
				return (BitConverter.ToUInt32(data, offset + 1), 5);
			}
			else if (type == 0xfe)
			{
				return (-(long)BitConverter.ToUInt64(data, offset + 1), 9);
			}
			throw new Exception("Cannot decode VarInt from bytes, unknown type " + type.ToString());
		}

		public static (ulong num, int bytesRead) GetIxiVarUInt(this byte[] data, int offset)
		{
			byte type = data[offset];
			if (type < 0xf8)
			{
				return (data[offset], 1);
			}
			else if (type == 0xfc)
			{
				return (BitConverter.ToUInt16(data, offset + 1), 3);
			}
			else if (type == 0xfd)
			{
				return (BitConverter.ToUInt32(data, offset + 1), 5);
			}
			else if (type == 0xfe)
			{
				return (BitConverter.ToUInt64(data, offset + 1), 9);
			}
			else if(type < 0xfc)
            {
				throw new Exception("Cannot decode VarInt from bytes, signed type was used " + type.ToString());
			}
			throw new Exception("Cannot decode VarInt from bytes, unknown type " + type.ToString());
		}

		// BinaryWriter extensions
		public static void WriteIxiVarInt(this BinaryWriter writer, long value)
		{
			writer.Write(GetIxiVarIntBytes(value));

		}

		public static void WriteIxiVarInt(this BinaryWriter writer, ulong value)
		{
			writer.Write(GetIxiVarIntBytes(value));
		}

		// BinaryReader extensions
		public static ulong ReadIxiVarUInt(this BinaryReader reader)
		{
			byte type = reader.ReadByte();
			if (type < 0xf8)
			{
				return type;
			}
			else if (type == 0xfc)
			{
				return reader.ReadUInt16();
			}
			else if (type == 0xfd)
			{
				return reader.ReadUInt32();
			}
			else if (type == 0xfe)
			{
				return reader.ReadUInt64();
			}
			else if (type < 0xfc)
			{
				throw new Exception("Cannot decode VarInt from bytes, signed type was used " + type.ToString());
			}
			throw new Exception("Cannot decode VarInt from bytes, unknown type " + type.ToString());
		}

		public static long ReadIxiVarInt(this BinaryReader reader)
		{
			byte type = reader.ReadByte();
			if (type < 0xf8)
			{
				return type;
			}
			else if (type == 0xf8)
			{
				return -reader.ReadUInt16();
			}
			else if (type == 0xf9)
			{
				return -reader.ReadUInt32();
			}
			else if (type == 0xfa)
			{
				return -(long)reader.ReadUInt64();
			}
			else if (type == 0xfc)
			{
				return reader.ReadUInt16();
			}
			else if (type == 0xfd)
			{
				return reader.ReadUInt32();
			}
			else if (type == 0xfe)
			{
				return (long)reader.ReadUInt64();
			}
			throw new Exception("Cannot decode VarInt from bytes, unknown type " + type.ToString());
		}
	}
}
