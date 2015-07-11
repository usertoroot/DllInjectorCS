using System.Runtime.InteropServices;

namespace DllInjectorCS
{
    public static class Msvcrt
    {
        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int memcmp(byte[] b1, byte[] b2, int count);
    }
}
