using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace DllInjectorCS
{
    public class Module
    {
        public ProcessModule ProcessModule
        {
            get;
            private set;
        }

        public Module(ProcessModule processModule)
        {
            ProcessModule = processModule;
        }

        public IntPtr FindExportFunction(string exportName)
        {
            return Kernel32.GetProcAddress(ProcessModule.BaseAddress, exportName);
        }
    }
}
