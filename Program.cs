using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace DllInjectorCS
{
    class Program
    {
        static void Main(string[] args)
        {
            Process[] processes;

            do
            {
                processes = Process.GetProcessesByName("lawl.exe");
                if (processes.Length > 0)
                {
                    Win32Process process = new Win32Process(processes[0]);
                    process.Inject("dllName.dll", "Initialize");
                }
            } while (processes.Length <= 0);
        }
    }
}
