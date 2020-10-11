using System;

namespace IXICore.Utils
{
	// VarInt class extends ulong and byte[] with GetVarIntBytes and GetVarInt/GetVarUInt respectively.
	// VarInt functions convert long/ulong to var int bytes and vice-versa and was designed to save space.
	// Our variation of VarInt supports signed and unsigned integers.
	// byte codes for larger than value 247 are:
	// 0xf8 - negative short (2 bytes)
	// 0xf9 - negative int (4 bytes)
	// 0xfa - negative long (8 bytes)
	// 0xfb - negative reserved for potential future use (x bytes)
	// 0xfc - short (2 bytes)
	// 0xfd - int (4 bytes)
	// 0xfe - long (8 bytes)
	// 0xff - reserved for potential future use (x bytes)
	public static class VarInt
    {
		public static byte[] GetVarIntBytes(this long value)
		{
			bool negative = false;
			if (value < 0)
			{
				negative = true;
				value = -value;
			}

			if (value < 0xf8)
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
				Array.Copy(BitConverter.GetBytes(value), 0, bytes, 1, 8);
				return bytes;
			}
		}

		public static byte[] GetVarIntBytes(this ulong value)
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

		public static long GetVarInt(this byte[] data, int offset)
		{
			byte type = data[offset];
			if (type < 0xf8)
			{
				return data[offset];
			}
			else if (type == 0xf8)
			{
				return -BitConverter.ToUInt16(data, offset + 1);
			}
			else if (type == 0xf9)
			{
				return -BitConverter.ToUInt32(data, offset + 1);
			}
			else if (type == 0xfa)
			{
				return -BitConverter.ToInt64(data, offset + 1);
			}
			else if (type == 0xfc)
			{
				return BitConverter.ToUInt16(data, offset + 1);
			}
			else if (type == 0xfd)
			{
				return BitConverter.ToUInt32(data, offset + 1);
			}
			else if (type == 0xfe)
			{
				return BitConverter.ToInt64(data, offset + 1);
			}
			throw new Exception("Cannot decode VarInt from bytes, unknown type " + type.ToString());
		}

		public static ulong GetVarUInt(this byte[] data, int offset)
		{
			byte type = data[offset];
			if (type < 0xf8)
			{
				return data[offset];
			}
			else if (type == 0xfc)
			{
				return BitConverter.ToUInt16(data, offset + 1);
			}
			else if (type == 0xfd)
			{
				return BitConverter.ToUInt32(data, offset + 1);
			}
			else if (type == 0xfe)
			{
				return BitConverter.ToUInt64(data, offset + 1);
			}else if(type < 0xfc)
            {
				throw new Exception("Cannot decode VarInt from bytes, signed type was used " + type.ToString());
			}
			throw new Exception("Cannot decode VarInt from bytes, unknown type " + type.ToString());
		}
	}
}
