using System;
using System.Text;

namespace DllInjectorCS
{
    public static class ByteArrayExtension
    {
        public static int IndexOf(this byte[] data, byte value, int index = 0)
        {
            for (int i = index; i < data.Length; i++)
            {
                if (data[i] == value)
                    return i;
            }

            return -1;
        }

        public static int IndexOf(this byte[] data, byte[] value, int index = 0)
        {
            for (int x = index; x < data.Length; x++)
            {
                if (data[x] == value[0])
                {
                    bool found = true;
                    for (int y = 1; y < value.Length; y++)
                    {
                        if (data[x + y] != value[y])
                        {
                            found = false;
                            break;
                        }
                    }

                    if (found)
                        return x;
                }
            }

            return -1;
        }

        public static int IndexOf(this byte[] data, byte[] value, byte wildCardByte, int index = 0)
        {
            for (int x = index; x < data.Length; x++)
            {
                if (data[x] == value[0])
                {
                    bool found = true;
                    for (int y = 1; y < value.Length; y++)
                    {
                        int index2 = x + y;
                        if (index2 < data.Length && data[index2] != value[y] && value[y] != wildCardByte)
                        {
                            found = false;
                            break;
                        }
                    }

                    if (found)
                        return x;
                }
            }

            return -1;
        }

        public static string ToHexString(this byte[] data)
        {
            var hexString = new StringBuilder(data.Length * 2);
            for (int x = 0; x < data.Length; x++)
                hexString.Append(Convert.ToString(data[x], 16).PadLeft(2, '0'));
            return hexString.ToString();
        }
    }
}