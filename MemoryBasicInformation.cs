using System;
using System.Runtime.InteropServices;

namespace DllInjectorCS
{
    [StructLayout(LayoutKind.Sequential)]
    public struct MemoryBasicInformation
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public MemoryProtection AllocationProtect;
        public int RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }
}
