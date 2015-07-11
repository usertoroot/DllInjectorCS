using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace DllInjectorCS
{
    public static class BinaryWriterExtension
    {
        public static void WriteCString(this BinaryWriter binaryWriter, string text)
        {
            binaryWriter.Write(Encoding.ASCII.GetBytes(text));
            binaryWriter.Write((byte)0);
        }
    }
}
