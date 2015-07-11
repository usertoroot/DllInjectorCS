using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace DllInjectorCS
{
    public class Win32Process : IDisposable
    {
        private const UInt32 INFINITE = 0xFFFFFFFF;

        public static readonly string[] PrivilegeStrings = new[]
        {
            "SeCreateTokenPrivilege",
            "SeAssignPrimaryTokenPrivilege",
            "SeLockMemoryPrivilege",
            "SeIncreaseQuotaPrivilege",
            "SeUnsolicitedInputPrivilege",
            "SeMachineAccountPrivilege",
            "SeTcbPrivilege",
            "SeSecurityPrivilege",
            "SeTakeOwnershipPrivilege",
            "SeLoadDriverPrivilege",
            "SeSystemProfilePrivilege",
            "SeSystemtimePrivilege",
            "SeProfileSingleProcessPrivilege",
            "SeIncreaseBasePriorityPrivilege",
            "SeCreatePagefilePrivilege",
            "SeCreatePermanentPrivilege",
            "SeBackupPrivilege",
            "SeRestorePrivilege",
            "SeShutdownPrivilege",
            "SeDebugPrivilege",
            "SeAuditPrivilege",
            "SeSystemEnvironmentPrivilege",
            "SeChangeNotifyPrivilege",
            "SeRemoteShutdownPrivilege",
            "SeUndockPrivilege",
            "SeSyncAgentPrivilege",
            "SeEnableDelegationPrivilege",
            "SeManageVolumePrivilege",
            "SeImpersonatePrivilege",
            "SeCreateGlobalPrivilege",
            "SeTrustedCredManAccessPrivilege",
            "SeRelabelPrivilege",
            "SeIncreaseWorkingSetPrivilege",
            "SeTimeZonePrivilege",
            "SeCreateSymbolicLinkPrivilege",
        };

        public void Refresh()
        {
            m_process.Refresh();
        }

        public ProcessModuleCollection Modules
        {
            get
            {
                return m_process.Modules;
            }
        }

        private readonly IntPtr m_hProcess;
        private readonly Process m_process = null;
        private IntPtr[] m_pausedThreads = null;

        public Win32Process(int pid)
        {
            m_hProcess = Kernel32.OpenProcess(ProcessAccessFlags.All, false, pid);
            if (m_hProcess == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            if (m_process == null)
                m_process = Process.GetProcessById(pid);
        }

        public Win32Process(Process process)
            : this(process.Id)
        {
            m_process = process;
        }

        public void Dispose()
        {
            if (m_hProcess != IntPtr.Zero)
                Kernel32.CloseHandle(m_hProcess);
        }

        public Module GetModule(string moduleName)
        {
            foreach (ProcessModule processModule in Modules)
            {
                if (moduleName == processModule.ModuleName)
                    return new Module(processModule);
            }

            return null;
        }

        public unsafe void Read(IntPtr address, byte* buffer, int offset, int size)
        {
            int bytesRead;

            if (!Kernel32.ReadProcessMemory(m_hProcess, address, buffer + offset, size, out bytesRead))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        public unsafe void Read(IntPtr address, byte[] buffer, int offset, int size)
        {
            fixed (byte* b = buffer)
                Read(address, b, offset, size);
        }

        public byte[] ReadBytes(IntPtr address, int size)
        {
            int bytesRead;
            var buffer = new byte[size];
            if (!Kernel32.ReadProcessMemory(m_hProcess, address, buffer, size, out bytesRead))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return buffer;
        }

        public sbyte ReadSByte(IntPtr address)
        {
            return (sbyte)ReadBytes(address, 1)[0];
        }

        public short ReadInt16(IntPtr address)
        {
            return BitConverter.ToInt16(ReadBytes(address, sizeof(short)), 0);
        }

        public int ReadInt32(IntPtr address)
        {
            return BitConverter.ToInt32(ReadBytes(address, sizeof(int)), 0);
        }

        public long ReadInt64(IntPtr address)
        {
            return BitConverter.ToInt64(ReadBytes(address, sizeof(long)), 0);
        }

        public byte ReadByte(IntPtr address)
        {
            return ReadBytes(address, 1)[0];
        }

        public ushort ReadUInt16(IntPtr address)
        {
            return BitConverter.ToUInt16(ReadBytes(address, sizeof(ushort)), 0);
        }

        public uint ReadUInt32(IntPtr address)
        {
            return BitConverter.ToUInt32(ReadBytes(address, sizeof(uint)), 0);
        }

        public ulong ReadUInt64(IntPtr address)
        {
            return BitConverter.ToUInt64(ReadBytes(address, sizeof(ulong)), 0);
        }

        public float ReadSingle(IntPtr address)
        {
            return BitConverter.ToSingle(ReadBytes(address, sizeof(float)), 0);
        }

        public double ReadDouble(IntPtr address)
        {
            return BitConverter.ToDouble(ReadBytes(address, sizeof(double)), 0);
        }

        public unsafe T ReadStructure<T>(IntPtr address) where T : struct
        {
            var data = new byte[Marshal.SizeOf(typeof(T))];
            fixed (byte* d = data)
            {
                Read(address, data, 0, data.Length);

                T value = (T)Marshal.PtrToStructure(new IntPtr(d), typeof(T));
                return value;
            }
        }

        public string ReadString(IntPtr address, int maxLen)
        {
            return Encoding.ASCII.GetString(ReadBytes(address, maxLen));
        }

        public unsafe void Write(IntPtr address, byte* data, int offset, int size)
        {
            int bytesWritten;
            var buffer = new byte[size];

            if (!Kernel32.WriteProcessMemory(m_hProcess, address, data + offset, size, out bytesWritten))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        public void Write(IntPtr address, byte[] value)
        {
            int bytesWritten;
            if (!Kernel32.WriteProcessMemory(m_hProcess, address, value, value.Length, out bytesWritten))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        public unsafe void Write(IntPtr address, byte[] data, int offset, int size)
        {
            fixed (byte* d = data)
                Write(address, d, offset, size);
        }

        public void Write(IntPtr address, sbyte value)
        {
            Write(address, (byte)value);
        }

        public void Write(IntPtr address, short value)
        {
            Write(address, BitConverter.GetBytes(value));
        }

        public void Write(IntPtr address, int value)
        {
            Write(address, BitConverter.GetBytes(value));
        }

        public void Write(IntPtr address, long value)
        {
            Write(address, BitConverter.GetBytes(value));
        }

        public void Write(IntPtr address, byte value)
        {
            Write(address, new byte[] { value });
        }

        public void Write(IntPtr address, ushort value)
        {
            Write(address, BitConverter.GetBytes(value));
        }

        public void Write(IntPtr address, uint value)
        {
            Write(address, BitConverter.GetBytes(value));
        }

        public void Write(IntPtr address, ulong value)
        {
            Write(address, BitConverter.GetBytes(value));
        }

        public void Write(IntPtr address, float value)
        {
            Write(address, BitConverter.GetBytes(value));
        }

        public void Write(IntPtr address, double value)
        {
            Write(address, BitConverter.GetBytes(value));
        }

        public unsafe void Write<T>(IntPtr address, T value)
        {
            var data = new byte[Marshal.SizeOf(typeof(T))];
            fixed (byte* d = data)
            {
                Marshal.StructureToPtr(value, new IntPtr(d), false);
                Write(address, data, 0, data.Length);
            }
        }

        public IntPtr Allocate(int size)
        {
            IntPtr address = Kernel32.VirtualAllocEx(m_hProcess, IntPtr.Zero, size, AllocationType.Reserve | AllocationType.Commit, MemoryProtection.ExecuteReadWrite);
            if (address == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return address;
        }

        public void Free(IntPtr address)
        {
            if (Kernel32.VirtualFreeEx(m_hProcess, address, 0, FreeType.Release))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        public MemoryProtection Protect(IntPtr address, int size, MemoryProtection newMemoryProtection)
        {
            MemoryProtection oldMemoryProtection;
            if (!Kernel32.VirtualProtectEx(m_hProcess, address, size, newMemoryProtection, out oldMemoryProtection))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return oldMemoryProtection;
        }

        public IntPtr Scan(byte[] data, byte? wildcard = null)
        {
            bool writeable;
            return Scan(data, out writeable, wildcard);
        }

        public IntPtr Scan(byte[] data, out bool writeable, byte? wildcard = null)
        {
            IntPtr address = IntPtr.Zero;
            int result;

            do
            {
                MemoryBasicInformation memoryBasicInformation;

                result = Kernel32.VirtualQueryEx(m_hProcess, address, out memoryBasicInformation, (uint)Marshal.SizeOf(typeof(MemoryBasicInformation)));
                if (result > 0)
                {
                    if ((memoryBasicInformation.State & 0x1000) == 0x1000 && (memoryBasicInformation.Protect & 0x100) == 0x0)
                    {
                        if (memoryBasicInformation.AllocationProtect.HasFlag(MemoryProtection.ExecuteRead) || 
                            memoryBasicInformation.AllocationProtect.HasFlag(MemoryProtection.ExecuteReadWrite) || 
                            memoryBasicInformation.AllocationProtect.HasFlag(MemoryProtection.ReadOnly) || 
                            memoryBasicInformation.AllocationProtect.HasFlag(MemoryProtection.ReadWrite) || 
                            memoryBasicInformation.AllocationProtect.HasFlag(MemoryProtection.ExecuteWriteCopy))
                            
                        {
                            byte[] block = ReadBytes(memoryBasicInformation.BaseAddress, memoryBasicInformation.RegionSize);
                            int index;

                            if (wildcard.HasValue)
                                index = ByteArrayExtension.IndexOf(block, data, wildcard.Value);
                            else
                                index = ByteArrayExtension.IndexOf(block, data);

                            if (index > 0)
                            {
                                if (memoryBasicInformation.AllocationProtect == MemoryProtection.ExecuteRead || memoryBasicInformation.AllocationProtect == MemoryProtection.ReadOnly)
                                    writeable = false;
                                else
                                    writeable = true;

                                return (IntPtr)memoryBasicInformation.BaseAddress + index;
                            }
                        }
                    }

                    address = memoryBasicInformation.BaseAddress + memoryBasicInformation.RegionSize;
                }
            } while (result > 0);
            writeable = false;
            return (IntPtr)0;
        }

        public int Scan(byte[] data, Stream resultOutputStream, byte wildcard)
        {
            int count = 0;
            using (BinaryWriter binaryWriter = new BinaryWriter(resultOutputStream))
            {
                IntPtr address = IntPtr.Zero;
                int result;

                do
                {
                    MemoryBasicInformation memoryBasicInformation;
                    result = Kernel32.VirtualQueryEx(m_hProcess, address, out memoryBasicInformation, (uint)Marshal.SizeOf(typeof(MemoryBasicInformation)));
                    if (result > 0)
                    {
                        if (memoryBasicInformation.Protect == 0 || memoryBasicInformation.AllocationProtect == MemoryProtection.NoAccess)
                            continue;

                        if (memoryBasicInformation.AllocationProtect == MemoryProtection.ExecuteRead || memoryBasicInformation.AllocationProtect == MemoryProtection.ExecuteReadWrite || memoryBasicInformation.AllocationProtect == MemoryProtection.ReadOnly || memoryBasicInformation.AllocationProtect == MemoryProtection.ReadWrite)
                        {
                            byte[] block = ReadBytes(memoryBasicInformation.BaseAddress, memoryBasicInformation.RegionSize);
                            int index = ByteArrayExtension.IndexOf(block, data, wildcard);

                            if (index > 0)
                            {
                                if (memoryBasicInformation.AllocationProtect == MemoryProtection.ExecuteRead || memoryBasicInformation.AllocationProtect == MemoryProtection.ReadOnly)
                                    binaryWriter.Write(1);
                                else
                                    binaryWriter.Write(0);

                                binaryWriter.Write((int)memoryBasicInformation.BaseAddress + index);
                                binaryWriter.Write(block);
                                count++;
                            }
                        }

                        address = memoryBasicInformation.BaseAddress + memoryBasicInformation.RegionSize;
                    }
                } while (result > 0);
            }

            return count;
        }

        public int Scan(byte[] data, Stream resultOutputStream)
        {
            int count = 0;
            using (BinaryWriter binaryWriter = new BinaryWriter(resultOutputStream))
            {
                IntPtr address = IntPtr.Zero;
                int result;

                do
                {
                    MemoryBasicInformation memoryBasicInformation;
                    result = Kernel32.VirtualQueryEx(m_hProcess, address, out memoryBasicInformation, (uint)Marshal.SizeOf(typeof(MemoryBasicInformation)));
                    if (result > 0)
                    {
                        if (memoryBasicInformation.Protect == 0 || memoryBasicInformation.AllocationProtect == MemoryProtection.NoAccess)
                            continue;

                        if (memoryBasicInformation.AllocationProtect == MemoryProtection.ExecuteRead || memoryBasicInformation.AllocationProtect == MemoryProtection.ExecuteReadWrite || memoryBasicInformation.AllocationProtect == MemoryProtection.ReadOnly || memoryBasicInformation.AllocationProtect == MemoryProtection.ReadWrite)
                        {
                            byte[] block = ReadBytes(memoryBasicInformation.BaseAddress, memoryBasicInformation.RegionSize);
                            int index = block.IndexOf(data);

                            if (index > 0)
                            {
                                if (memoryBasicInformation.AllocationProtect == MemoryProtection.ExecuteRead || memoryBasicInformation.AllocationProtect == MemoryProtection.ReadOnly)
                                    binaryWriter.Write(1);
                                else
                                    binaryWriter.Write(0);

                                binaryWriter.Write((int)memoryBasicInformation.BaseAddress + index);
                                binaryWriter.Write(block);
                                count++;
                            }
                        }

                        address = memoryBasicInformation.BaseAddress + memoryBasicInformation.RegionSize;
                    }
                } while (result > 0);
            }

            return count;
        }

        public int Rescan(byte[] data, Stream resultInputStream, int count, Stream resultOutputStream)
        {
            int newCount = 0;
            using (BinaryWriter binaryWriter = new BinaryWriter(resultOutputStream))
            using (BinaryReader binaryReader = new BinaryReader(resultInputStream))
            {
                for (int i = 0; i < count; i++)
                {
                    bool readOnly = binaryReader.ReadByte() == 1;
                    IntPtr address = new IntPtr(binaryReader.ReadInt32());
                    byte[] previousData = binaryReader.ReadBytes(data.Length);
                    byte[] newData = ReadBytes(address, data.Length);

                    if (Msvcrt.memcmp(newData, previousData, newData.Length) == 0)
                    {
                        binaryWriter.Write(readOnly);
                        binaryWriter.Write((int)address);
                        binaryWriter.Write(newData);
                        newCount++;
                    }
                }
            }

            return newCount;
        }

        public void Pause()
        {
            if (m_pausedThreads != null)
                return;

            m_process.Refresh();

            m_pausedThreads = new IntPtr[m_process.Threads.Count];

            lock (m_pausedThreads)
            {
                for (int i = 0; i < m_pausedThreads.Length; i++)
                {
                    IntPtr hThread = Kernel32.OpenThread(ThreadAccess.SuspendResume, false, m_process.Threads[i].Id);
                    if (hThread == IntPtr.Zero)
                        throw new Win32Exception(Marshal.GetLastWin32Error());

                    m_pausedThreads[i] = hThread;
                }

                foreach (IntPtr hThread in m_pausedThreads)
                {
                    if (Kernel32.SuspendThread(hThread) == -1)
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }
        }

        public void Resume()
        {
            if (m_pausedThreads == null)
                return;

            lock (m_pausedThreads)
            {
                foreach (IntPtr hThread in m_pausedThreads)
                {
                    if (Kernel32.ResumeThread(hThread) == -1)
                        throw new Win32Exception(Marshal.GetLastWin32Error());

                    if (!Kernel32.CloseHandle(hThread))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }

            m_pausedThreads = null;
        }

        public void SetPrivilege(PrivilegeName privilegeName, PrivilegeAttribute privilegeAttribute)
        {
            TokPriv1Luid tokenPrivilege;
            IntPtr hCurrentProcess = Kernel32.GetCurrentProcess();
            IntPtr hProcessToken = IntPtr.Zero;

            if (!AdvApi32.OpenProcessToken(hCurrentProcess, AdvApi32.TOKEN_ADJUST_PRIVILEGES | AdvApi32.TOKEN_QUERY, ref hProcessToken))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            tokenPrivilege.Count = 1;
            tokenPrivilege.Luid = 0;
            tokenPrivilege.Attr = (int)privilegeAttribute;

            if (!AdvApi32.LookupPrivilegeValue(null, PrivilegeStrings[(int)privilegeName], ref tokenPrivilege.Luid))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            if (!AdvApi32.AdjustTokenPrivileges(hProcessToken, false, ref tokenPrivilege, 0, IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        public IntPtr CreateThread(IntPtr address, uint parameter = 0)
        {
            IntPtr hThread = Kernel32.CreateRemoteThread(m_hProcess, IntPtr.Zero, 0, address, new IntPtr(parameter), 0, IntPtr.Zero);
            if (hThread == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return hThread;
        }

        public void FlushInstructionCache(IntPtr address, int size)
        {
            if (!Kernel32.FlushInstructionCache(m_hProcess, address, size))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        public void Inject(string dllName, string functionName, uint parameter = 0)
        {
            byte[] workspace = new byte[1024];
            IntPtr address = Allocate(workspace.Length);
            IntPtr codeAddress;

            Module kernel32 = GetModule("kernel32.dll");
            IntPtr loadLibraryAddress = kernel32.FindExportFunction("LoadLibraryA");
            IntPtr getProcAddressAddress = kernel32.FindExportFunction("GetProcAddress");
            IntPtr exitProcessAddress = kernel32.FindExportFunction("ExitProcess");
            IntPtr exitThreadAddress = kernel32.FindExportFunction("ExitThread");
            IntPtr freeLibraryAndExitThreadAddress = kernel32.FindExportFunction("FreeLibraryAndExitThread");

            using (MemoryStream memoryStream = new MemoryStream(workspace))
            using (BinaryWriter binaryWriter = new BinaryWriter(memoryStream))
            {
                IntPtr dllNameAddress = address + (int)memoryStream.Position;
                binaryWriter.WriteCString(dllName);

                IntPtr functionNameAddress = address + (int)memoryStream.Position;
                binaryWriter.WriteCString(functionName);

                IntPtr user32Address = address + (int)memoryStream.Position;
                binaryWriter.WriteCString("user32.dll");

                IntPtr msgBoxNameAddress = address + (int)memoryStream.Position;
                binaryWriter.WriteCString("MessageBoxA");

                IntPtr errorAddress = address + (int)memoryStream.Position;
                binaryWriter.WriteCString("Error");

                IntPtr couldNotLoadDllAddress = address + (int)memoryStream.Position;
                binaryWriter.WriteCString("Could not load the dll: " + dllName);

                IntPtr couldNotLoadFunctionAddress = address + (int)memoryStream.Position;
                binaryWriter.WriteCString("Could not load the function: " + functionName);

                IntPtr messageBoxAddress = address + (int)memoryStream.Position;
                binaryWriter.Write((uint)0);

                IntPtr dllAddress = address + (int)memoryStream.Position;
                binaryWriter.Write((uint)0);

                codeAddress = address + (int)memoryStream.Position;


                //LOAD USER32.DLL
                //push dllNameAddress
                binaryWriter.Write((byte)0x68);
                binaryWriter.Write((uint)user32Address);

                //mov eax, LoadLibraryA
                binaryWriter.Write((byte)0xB8);
                binaryWriter.Write((uint)loadLibraryAddress);

                //call eax
                binaryWriter.Write((byte)0xFF);
                binaryWriter.Write((byte)0xD0);

                //LOAD MessageBoxA
                //push msgBoxName
                binaryWriter.Write((byte)0x68);
                binaryWriter.Write((uint)msgBoxNameAddress);

                //push eax
                binaryWriter.Write((byte)0x50);

                //mov eax, GetProcAddress
                binaryWriter.Write((byte)0xB8);
                binaryWriter.Write((uint)getProcAddressAddress);

                //call eax
                binaryWriter.Write((byte)0xFF);
                binaryWriter.Write((byte)0xD0);

                //mov [messageBoxAddress], eax
                binaryWriter.Write((byte)0xA3);
                binaryWriter.Write((uint)messageBoxAddress);

                //LOAD DLL
                //push dllNameAddress
                binaryWriter.Write((byte)0x68);
                binaryWriter.Write((uint)dllNameAddress);

                //mov eax, LoadLibraryA
                binaryWriter.Write((byte)0xB8);
                binaryWriter.Write((uint)loadLibraryAddress);

                //call eax
                binaryWriter.Write((byte)0xFF);
                binaryWriter.Write((byte)0xD0);

                //cmp eax, 0
                binaryWriter.Write((byte)0x83);
                binaryWriter.Write((byte)0xF8);
                binaryWriter.Write((byte)0x00);

                //jnz eip + 0x1E to skip over error
                binaryWriter.Write((byte)0x75);
                binaryWriter.Write((byte)0x1E);

                //Error Code 1
                //MessageBox
                //push 0x10 (MB_ICONHAND)
                binaryWriter.Write((byte)0x6A);
                binaryWriter.Write((byte)0x10);

                //push errorAddress
                binaryWriter.Write((byte)0x68);
                binaryWriter.Write((uint)errorAddress);

                //push couldNotLoadDllAddress
                binaryWriter.Write((byte)0x68);
                binaryWriter.Write((uint)couldNotLoadDllAddress);

                //push 0
                binaryWriter.Write((byte)0x6A);
                binaryWriter.Write((byte)0x00);

                //mov eax, [msgBoxAddr]
                binaryWriter.Write((byte)0xA1);
                binaryWriter.Write((uint)msgBoxNameAddress);

                //call eax
                binaryWriter.Write((byte)0xFF);
                binaryWriter.Write((byte)0xD0);

                //Exit Process
                //push 0
                binaryWriter.Write((byte)0x6A);
                binaryWriter.Write((byte)0x00);

                //mov eax, exitProcessAddress
                binaryWriter.Write((byte)0xB8);
                binaryWriter.Write((uint)exitProcessAddress);

                //call eax
                binaryWriter.Write((byte)0xFF);
                binaryWriter.Write((byte)0xD0);

                //After error 1
                //mov [dllAddress], eax
                binaryWriter.Write((byte)0xA3);
                binaryWriter.Write((uint)dllAddress);

                //push functionNameAddress
                binaryWriter.Write((byte)0x68);
                binaryWriter.Write((uint)functionNameAddress);

                //push eax
                binaryWriter.Write((byte)0x50);

                //mov eax, getProcAddressAddress
                binaryWriter.Write((byte)0xB8);
                binaryWriter.Write((uint)getProcAddressAddress);

                //call eax
                binaryWriter.Write((byte)0xFF);
                binaryWriter.Write((byte)0xD0);

                //cmp eax, 0
                binaryWriter.Write((byte)0x83);
                binaryWriter.Write((byte)0xF8);
                binaryWriter.Write((byte)0x00);

                //jnz eip + 0x1C to skip over error
                binaryWriter.Write((byte)0x75);
                binaryWriter.Write((byte)0x1C);

                //Error Code 2
                //MessageBox
                //push 0x10 (MB_ICONHAND)
                binaryWriter.Write((byte)0x6A);
                binaryWriter.Write((byte)0x10);

                //push errorAddress
                binaryWriter.Write((byte)0x68);
                binaryWriter.Write((uint)errorAddress);

                //push couldNotLoadFunctionAddress
                binaryWriter.Write((byte)0x68);
                binaryWriter.Write((uint)couldNotLoadFunctionAddress);

                //push 0
                binaryWriter.Write((byte)0x6A);
                binaryWriter.Write((byte)0x00);

                //mov eax, [msgBoxAddr]
                binaryWriter.Write((byte)0xA1);
                binaryWriter.Write((uint)msgBoxNameAddress);

                //call eax (either messagebox or the function gets invoked)
                binaryWriter.Write((byte)0xFF);
                binaryWriter.Write((byte)0xD0);

                //Exit Process
                //push 0
                binaryWriter.Write((byte)0x6A);
                binaryWriter.Write((byte)0x00);

                //mov eax, exitProcessAddress
                binaryWriter.Write((byte)0xB8);
                binaryWriter.Write((uint)exitProcessAddress);

                //call eax
                binaryWriter.Write((byte)0xFF);
                binaryWriter.Write((byte)0xD0);
            }

            MemoryProtection oldProtection = Protect(address, workspace.Length, MemoryProtection.ExecuteReadWrite);
            Write(address, workspace);
            Protect(address, workspace.Length, oldProtection);
            FlushInstructionCache(address, workspace.Length);

            IntPtr hThread = CreateThread(codeAddress, parameter);
            Kernel32.WaitForSingleObject(hThread, INFINITE);

            Free(address);
        }
    }
}