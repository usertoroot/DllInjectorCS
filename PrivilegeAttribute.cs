using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DllInjectorCS
{
    public enum PrivilegeAttribute : uint
    {
        EnabledByDefault = 0x00000001,
        Enabled = 0x00000002,
        Removed = 0X00000004,
        UsedForAccess = 0x80000000,
    }
}
