using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IXICore.Utils
{
    class _ByteArrayComparer
    {
        public static int Compare(byte[] x, byte[] y)
        {
            var len = Math.Min(x.Length, y.Length);
            for (var i = 0; i < len; i++)
            {
                var c = x[i].CompareTo(y[i]);
                if (c != 0)
                {
                    return c;
                }
            }

            return x.Length.CompareTo(y.Length);
        }
    }

    class ByteArrayComparer : IComparer<byte[]>, IEqualityComparer<byte[]>
    {
        public int Compare(byte[] x, byte[] y)
        {
            return _ByteArrayComparer.Compare(x, y);
        }
        public bool Equals(byte[] left, byte[] right)
        {
            if (left == null || right == null)
            {
                return left == right;
            }
            return left.SequenceEqual(right);
        }
        public int GetHashCode(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException("key");
            return key.Sum(b => b);
        }
    }
}
