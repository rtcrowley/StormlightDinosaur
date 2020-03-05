
using System;
using System.Linq;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Security.Principal;
using Microsoft.Win32;
using TaskScheduler;
using System.Security.Cryptography;
using System.ServiceProcess;

namespace StormlightDinosaur
{
    class Program
    {
        public static void Header()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(@"         _____ __                       ___       __    __ ");
            Console.WriteLine(@"        / ___// /_____  _________ ___  / (_)___ _/ /_  / /_");
            Console.WriteLine(@"        \__ \/ __/ __ \/ ___/ __ `__ \/ / / __ `/ __ \/ __/ ");
            Console.WriteLine(@"       ___/ / /_/ /_/ / /  / / / / / / / / /_/ / / / / /_");
            Console.WriteLine(@"      /____/\__/\____/_/  /_/ /_/ /_/_/_/\__, /_/ /_/\__/ ");
            Console.WriteLine(@"                                        /____/     ");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine(@"( ~ ( \ ' \   )_ -' / __ _  /  (_--__'_                     )__");
            Console.WriteLine(@" _\ _\ ` _ ___-)  / )     '-      (( __( _      ) -__'___)");
            Console.WriteLine(@"   `(__\  \  `/                          (-_'-_______)-----'");
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.WriteLine(@"       `\ \           _..--+~/@-~--.         /  _/ ");
            Console.WriteLine(@"        _\_\      _-=~      (  .  ''}      _/  / ");
            Console.WriteLine(@"        `\\    _-~     _.--=.\ \""""""""      / __/");
            Console.WriteLine(@"          \\ _ ~      _-      \ \_\     _/ /");
            Console.WriteLine(@"           \ =      _=        '--'     /__/");
            Console.WriteLine(@"            '      =                  //        .");
            Console.WriteLine(@"_          :      :       ____       /'         '=_. ___");
            Console.WriteLine(@"      ___  |      ;                            ____ '~--.~.");
            Console.WriteLine(@"____       ;      ;                               _____  } |");
            Console.WriteLine(@"        ___=       \ ___ __     __..-...__           ___/__/__");
            Console.WriteLine(@" creosote  :        =_     _.-~~          ~~--.__");
            Console.WriteLine(@"      _____ \         ~-+-~                   ___~=_______");
            Console.WriteLine(@"__         ~'#~~ == ...______ __ ___ _--~~--_             ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(@"           ____  _");
            Console.WriteLine(@"          / __ \(_)___  ____  _________ ___  _______");
            Console.WriteLine(@"         / / / / / __ \/ __ \/ ___/ __ `/ / / / ___/");
            Console.WriteLine(@"        / /_/ / / / / / /_/ (__  ) /_/ / /_/ / / ");
            Console.WriteLine(@"       /_____/_/_/ /_/\____/____/\__,_/\__,_/_/   v1.1  ");
            Console.WriteLine(" ");
            Console.ResetColor();

        }

        /// //////////////////////////////////////////////////
        /// //////////////////////////////////////////////////
        /// ////   Run Keys   ////////////////////////////////
        /// //////////////////////////////////////////////////
        /// //////////////////////////////////////////////////
        public static void RunKeys()
        {
            string[] runKeys = new string[] {
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunService",
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceService",
            };

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("   [+] Checking HKey Local Machine " + "\n");
            foreach (string LMrkey in runKeys)
            {
                RegistryKey key = Registry.LocalMachine.OpenSubKey(LMrkey);
                if (key == null)
                {
                    Console.ForegroundColor = ConsoleColor.DarkCyan;
                    Console.WriteLine("      [+] HKLM\\" + LMrkey + " does not exist");
                }
                else
                {
                    try
                    {
                        Console.ForegroundColor = ConsoleColor.DarkCyan;
                        Console.WriteLine("      [+] Checking HKLM\\" + LMrkey);
                        foreach (var xkey in key.GetValueNames())
                        {
                            Console.ForegroundColor = ConsoleColor.DarkCyan;
                            Console.WriteLine("          --------------------------------------------------------------------");
                            Console.ForegroundColor = ConsoleColor.White;
                            Console.WriteLine("          Registry Key:  " + xkey);
                            using (RegistryKey keyValue = Registry.LocalMachine.OpenSubKey(xkey))
                            {
                                if (xkey != null)
                                {
                                    Object o = key.GetValue(xkey);
                                    if (o != null)
                                    {
                                        Console.ForegroundColor = ConsoleColor.White;
                                        Console.WriteLine("          Value:        " + o);
                                        Console.ForegroundColor = ConsoleColor.DarkCyan;
                                        Console.WriteLine("          --------------------------------------------------------------------");
                                    }
                                }
                                else { Console.WriteLine("          Value:     Empty" + "\n"); }
                            }
                        }
                    }
                    catch (Exception ex) { }
                }
            }
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("   [+] Checking HKey Current User " + "\n");
            foreach (string CUrkey in runKeys)
            {
                RegistryKey key = Registry.CurrentUser.OpenSubKey(CUrkey);
                if (key == null)
                {
                    Console.ForegroundColor = ConsoleColor.DarkCyan;
                    Console.WriteLine("      [+] HKCU\\" + CUrkey + " does not exist");
                }
                else
                {
                    try
                    {
                        Console.ForegroundColor = ConsoleColor.DarkCyan;
                        Console.WriteLine("      [+] Checking HKCU\\" + CUrkey);
                        foreach (var xkey in key.GetValueNames())
                        {
                            Console.ForegroundColor = ConsoleColor.DarkCyan;
                            Console.WriteLine("          --------------------------------------------------------------------");
                            Console.ForegroundColor = ConsoleColor.White;
                            Console.WriteLine("          Registry Key:  " + xkey);
                            using (RegistryKey keyValue = Registry.LocalMachine.OpenSubKey(xkey))
                            {
                                if (xkey != null)
                                {
                                    Object o = key.GetValue(xkey);
                                    if (o != null)
                                    {
                                        Console.ForegroundColor = ConsoleColor.White;
                                        Console.WriteLine("          Value:        " + o);
                                        Console.ForegroundColor = ConsoleColor.DarkCyan;
                                        Console.WriteLine("          --------------------------------------------------------------------");
                                    }
                                }
                                else { Console.WriteLine("          Value:     Empty" + "\n"); }
                            }
                        }
                    }
                    catch (Exception ex) { }
                }
            }

        }
        /// //////////////////////////////////////////////////
        /// //////////////////////////////////////////////////
        /// ////   Scheduled Tasks   /////////////////////////
        /// //////////////////////////////////////////////////
        /// //////////////////////////////////////////////////

        public static void ProcessTaskFoler(ITaskFolder taskFolder)
        {
            int idx;
            string name, path;
            string ePs, schXm, msTaskPath;
            _TASK_STATE state;

            IRegisteredTaskCollection taskCol = taskFolder.GetTasks((int)_TASK_ENUM_FLAGS.TASK_ENUM_HIDDEN);
            for (idx = 1; idx <= taskCol.Count; idx++)
            {
                IRegisteredTask runTask = taskCol[idx];

                // Some lolbins..remove common ones if a lot of noise is created
                string[] interestingTasks = new string[] {
                    "certutil.exe","cmstp.exe","control.exe","csc.exe","cscript.exe","bitsadmin","installutil.exe","jsc.exe","makecab.exe","msbuild.exe",
                        "dfsvc.exe","diskshadow.exe","dnscmd.exe","esentutl.exe","eventvwr.exe","expand.exe","extexport.exe","extrac32.exe",
                        "findstr.exe","forfiles.exe","ftp.exe","ie4uinit.exe","ieexec.exe","infdefaultinstall.exe",
                        "msconfig.exe","msdt.exe","mshta.exe","msiexec.exe","odbcconf.exe","pcalua.exe","pcwrun.exe","presentationhost.exe",
                        "print.exe","regasm.exe","regedit.exe","reg.exe","runonce.exe","runscripthelper.exe","schtasks.exe","scriptrunner.exe",
                        "syncappvpublishingserver.exe","verclsid.exe","wab.exe","wmic.exe","wscript.exe"
                    };

                name = runTask.Name;
                path = runTask.Path;
                state = runTask.State;
                schXm = runTask.Xml;

                string schXml = schXm.ToLower();

                msTaskPath = "\\Microsoft\\";
                ePs = "powershell.exe";

                string sched_out = "          Name: " + name + "\n" + "          Path: " + path + "\n" + "          State: " + state + "\n";

                bool mspath = path.Contains(msTaskPath);
                bool bPs = schXml.Contains(ePs);

                /////////////////////
                // Based off array //
                /////////////////////
                foreach (string itasks in interestingTasks)
                {
                    bool chkItasks = schXml.Contains(itasks);
                    if (chkItasks == true)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("      [-] Detected interesting String in task: ");
                        Console.ForegroundColor = ConsoleColor.DarkRed;
                        Console.WriteLine(sched_out);
                    }
                }
                ////////////////
                // Powershell //
                ////////////////
                if (bPs == true)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("      [-] PowerShell Detected - task info: ");
                    Console.WriteLine(sched_out);
                    //Console.WriteLine(schXm);
                }
                ////////////////////////////
                // Outside Microsoft folder
                ////////////////////////////
                if (mspath == false)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("      [-] Detected Task outside of Microsoft folder - task info: ");
                    Console.ForegroundColor = ConsoleColor.DarkRed;
                    Console.WriteLine(sched_out);

                }

            }

            ITaskFolderCollection taskFolderCol = taskFolder.GetFolders(0);
            for (idx = 1; idx <= taskFolderCol.Count; idx++)
                ProcessTaskFoler(taskFolderCol[idx]);
        }

        public static void ParseScheduleTasks()
        {
            ITaskService taskService = new TaskScheduler.TaskScheduler();
            taskService.Connect();

            ProcessTaskFoler(taskService.GetFolder("\\"));
        }

        /// ////////////////////////////////////////////
        /// ////   Hash Calc   /////////////////////////
        /// ////////////////////////////////////////////
        public static string CalculateMD5(string filename)
        {
            using (var md5 = MD5.Create())
            {
                using (var stream = File.OpenRead(filename))
                {
                    var hash = md5.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
        }

        /// ////////////////////////////////////////////
        /// ////////////////////////////////////////////
        /// ////   Netsh Helpers   /////////////////////
        /// ////////////////////////////////////////////
        /// ////////////////////////////////////////////
        public static void NethshHelpers()
        {
            string[] netshKeys = new string[] {
                "SOFTWARE\\Microsoft\\NetSh"
            };

            // Default x64 Netsh dll's v14393
            string[] realNetshNames = new string[] {
                "ifmon.dll","rasmontr.dll","authfwcfg.dll","dhcpcmonitor.dll","dot3cfg.dll",
                "fwcfg.dll","hnetmon.dll","netiohlp.dll","nettrace.dll","nshhttp.dll","nshipsec.dll",
                "nshwfp.dll","p2pnetsh.dll","rpcnsh.dll","WcnNetsh.dll","whhelper.dll","wlancfg.dll",
                "wshelper.dll","wwancfg.dll","peerdistsh.dll",
            };

            // Valid Win Enterprise DLL 64-bit hashes v14393
            // NOTE: These hashes change often! Not reliable as intrusion detection method
            /*string[] realNetshHashes = new string[] {
            "6516b277fddf621ca229bc83e42d37b1","60ced926123c2302151672f9da7d7af2","ea7d47bd2d258a559b252cad9443cedd",
            "668a386775b2aa36cc7f1e7db96deff4","ff4c066dcba425aa9079f8f5031657c2","4c0eadc150facd63625a1cfc70ef63a5",
            "4a0ad58e4f8b963b05b466cf903347a4","ee26dd15d15b17f6fb172f1b3b9ef69f","edb17de73c6b77e6621eb1c931d2fc6e",
            "90ce7e9f0ec74e31e2a1527c784e71ed","0c83a44dcd312485e1abe30caeca0588","980d774495aa11fc776970f8c81ce867",
            "0899fc19072fa27de8edcfec4575c4a3","9680bccd0e8e98c94b782fbf7d7190f5","1807b9121dad338e1fb45fb9f43549ae",
            "93ecae56f56cac45efe1e7d1b60a3658","e63dd2879f98a7f28b954235e31b42c5","8eb4f3b56439370088a32f6e064fa162",
            "a41806e419220b18b90fbdc391317438","90dc77e5d7fa9e80434e95bcb9a6861a","801dcb0a415284c4655a6591028e9a8b",
            };*/


            // Starting Netsh key check
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("   [+] Validating Default DLL Names" + "\n");

            foreach (string LMrkey in netshKeys)
            {
                RegistryKey key = Registry.LocalMachine.OpenSubKey(LMrkey);
                try
                {
                    foreach (var v in key.GetValueNames())
                    {
                        using (RegistryKey keyValue = Registry.LocalMachine.OpenSubKey(v))
                        {
                            if (key != null)
                            {
                                Object o = key.GetValue(v);
                                var val = o.ToString();

                                //Validate DLL names
                                if (realNetshNames.Any(val.Contains))
                                {
                                    Console.ForegroundColor = ConsoleColor.DarkCyan;
                                    Console.WriteLine("      [+] Sucess: " + val);
                                }
                                else
                                {
                                    Console.ForegroundColor = ConsoleColor.Red;
                                    Console.WriteLine("      [-] Non-Default DLL Found!: " + val);
                                    Console.ForegroundColor = ConsoleColor.DarkRed;
                                    Console.WriteLine("          Investigate HKLM\\SOFTWARE\\Microsoft\\NetSh\\" + v + " and DLL in System32");
                                }
                            }
                            else
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine("      [-] Empty Entry Found: " + v);
                            }
                        }
                    }
                }
                catch (Exception ex) { }
            }
        }

        /// ////////////////////////////////////////////
        /// ////////////////////////////////////////////
        /// ////   BITS Jobs   /////////////////////////
        /// ////////////////////////////////////////////
        /// ////////////////////////////////////////////
        public static void BitsJobs()
        {
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine("------------------------------------------------------------------------------");
            Console.ForegroundColor = ConsoleColor.Gray;
            var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "bitsadmin",
                    Arguments = "/list /allusers /verbose",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }
            };
            proc.Start();
            while (!proc.StandardOutput.EndOfStream)
            {
                string line = proc.StandardOutput.ReadLine();
                Console.WriteLine(line);
            }
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine("------------------------------------------------------------------------------");
            Console.ForegroundColor = ConsoleColor.DarkCyan;
        }


        /// ////////////////////////////////////////////
        /// ////////////////////////////////////////////
        /// ////   WMI Subscriptions   /////////////////
        /// ////////////////////////////////////////////
        /// ////////////////////////////////////////////

        public static void WmiSubs()
        {
            // WMI EventFilter
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("   [+] Querying Non-Default WMI Event Filters");
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine("------------------------------------------------------------------------------");
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = "-c Get-WMIObject -Namespace root\\Subscription -Class __EventFilter | Select-String -Pattern '\\bSCM Event Log Filter\\b' -NotMatch -CaseSensitive",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }
            };
            proc.Start();
            while (!proc.StandardOutput.EndOfStream)
            {
                Console.ForegroundColor = ConsoleColor.White;
                string line = proc.StandardOutput.ReadLine();
                Console.WriteLine(line);
            }
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine("------------------------------------------------------------------------------");
            Console.ForegroundColor = ConsoleColor.DarkCyan;

            // WMI EventConsumer
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("   [+] Querying Non-Default WMI Event Consumers");
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine("------------------------------------------------------------------------------");
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            var procCons = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = "-c Get-WMIObject -Namespace root\\Subscription -Class __EventConsumer | Select-String -Pattern '\\bSCM Event Log Consumer\\b' -NotMatch -CaseSensitive",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }
            };
            procCons.Start();
            while (!procCons.StandardOutput.EndOfStream)
            {
                Console.ForegroundColor = ConsoleColor.White;
                string line = procCons.StandardOutput.ReadLine();
                Console.WriteLine(line);
            }
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine("------------------------------------------------------------------------------");
            Console.ForegroundColor = ConsoleColor.DarkCyan;
        }


        /// ////////////////////////////////////////////
        /// ////////////////////////////////////////////
        /// ////   Startup Folder      /////////////////
        /// ////////////////////////////////////////////
        /// //////////////////////////////////////////// 

        public static void StartFolder()
        {
            // Get %APPDATA% env. var
            string mlem = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string fullFolP = mlem + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
            string[] stFolder = Directory.GetFiles(fullFolP);

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("   [+] Looking in " + fullFolP + "\\");

            if (stFolder == null)
            {
                Console.ForegroundColor = ConsoleColor.DarkGreen;
                Console.WriteLine("   [+] Looks like your Users Startup Folder is Empty");
            }
            else
            {
                foreach (string thingy in stFolder)
                {
                    // List all files in the Startup folder
                    string stName = thingy.Substring(thingy.LastIndexOf('\\') + 1);
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine("      [+] Found: " + stName);
                }
            }

        }

        /// ////////////////////////////////////////////
        /// ////////////////////////////////////////////
        /// ////   Services            /////////////////
        /// ////////////////////////////////////////////
        /// ////////////////////////////////////////////
        public static void EvilServices()
        {
            string[] safeSvc = new string[] {
                "system32","SYSTEM32","System32",
            };

            string[] safeSvcPro = new string[] {
                "C:\\Program Files\\", "C:\\Program Files (x86)\\", "C:\\Windows\\", "C:\\WINDOWS\\", "c:\\Program Files\\"
            };

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("   [-] Checking if Service Descriptions are Empty");
            ServiceController[] services = ServiceController.GetServices();
            foreach (ServiceController service in services)
            {
                var xsvc = new ManagementObject(new ManagementPath(string.Format("Win32_Service.Name='{0}'", service.ServiceName)));
                var zsvc = xsvc["Description"];
                if (zsvc != null)
                { }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("      [-] Empty Description Found! Verify it's a legitimate Service");
                    Console.ForegroundColor = ConsoleColor.DarkRed;
                    Console.WriteLine("          Service: " + service.DisplayName);
                }
            }

            String registryKey = @"SYSTEM\CurrentControlSet\Services";
            using (Microsoft.Win32.RegistryKey key = Registry.LocalMachine.OpenSubKey(registryKey))
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("   [+] Checking Services Image Paths outside of Protected Directories");
                foreach (String subkeyName in key.GetSubKeyNames())
                {
                    var imgPath = key.OpenSubKey(subkeyName).GetValue("ImagePath");
                    var keyD = key.OpenSubKey(subkeyName).GetValue("Description");

                    // Search for service exe's outside of protected folders
                    if (imgPath != null)
                    {
                        var ipa = imgPath.ToString();
                        //if (safeSvc.Any(ipa.Contains))
                        if(safeSvc.Any(ipa.Contains))
                        { /*Console.WriteLine("      [+] Sucess: " + subkeyName);*/
                        }
                        else
                        {
                            if (safeSvcPro.Any(ipa.Contains))
                            { }
                            else
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine("      [-] Found Image Path outside of a Protected Directory: ");
                                Console.ForegroundColor = ConsoleColor.DarkRed;
                                Console.WriteLine("          Service: " + subkeyName);
                                Console.WriteLine("          Path: " + ipa);
                            }

                        }
                    }
                }
            }
        }

        /// ////////////////////////////////////////////
        /// ////   Admin Check         /////////////////
        /// ////////////////////////////////////////////       
        public static bool IsAdministrator()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        /// ////////////////////////////////////////////
        /// ////////////////////////////////////////////
        /// ////   svchost.exe Check   /////////////////
        /// ////////////////////////////////////////////
        /// ////////////////////////////////////////////
        public static void EnumSvchost()
        {
            Process[] localByName = Process.GetProcessesByName("svchost");
            foreach (Process svch in localByName)
            {
                var myId = svch.Id;

                ///////////////////////////////////////////////
                /// Get ppids of each svchost instance
                /// TODO: make this a separate method to call
                var query = string.Format("SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {0}", myId);
                var search = new ManagementObjectSearcher("root\\CIMV2", query);
                var results = search.Get().GetEnumerator();
                results.MoveNext();
                var queryObj = results.Current;
                var parentId = (uint)queryObj["ParentProcessId"];
                var parent = Process.GetProcessById((int)parentId);
                var parentName = parent.ProcessName;
                /////////////////////////////////////////////// 

                if (parentName != "services")
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("   [-] svchost.exe Process NOT start by services.exe!");
                    Console.WriteLine("       PID           : " + myId);
                    Console.WriteLine("       PPID          : " + parent);
                    Console.WriteLine("       Parent Name   : " + parentName);
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.DarkCyan;
                    Console.WriteLine("   [+] Sucess - svchost PID of: " + myId);
                }
            }
        }

        /// ////////////////////////////////////////////
        /// ////////////////////////////////////////////
        /// ////   lsass.exe Check   /////////////////
        /// ////////////////////////////////////////////
        /// ////////////////////////////////////////////
        public static void EnumLsass()
        {
            Process[] localByName = Process.GetProcessesByName("lsass");
            int i = 0;
            foreach (Process lsas in localByName)
            {
                var myId = lsas.Id;
                i++;

                // Look for lsass parent
                var query = string.Format("SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {0}", myId);
                var search = new ManagementObjectSearcher("root\\CIMV2", query);
                var results = search.Get().GetEnumerator();
                results.MoveNext();
                var queryObj = results.Current;
                var parentId = (uint)queryObj["ParentProcessId"];
                var parent = Process.GetProcessById((int)parentId);

                var parentName = parent.ProcessName;

                if (parentName != "wininit")
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("   [-] lsass.exe Process NOT start by blah!");
                    Console.WriteLine("       PID           : " + myId);
                    Console.WriteLine("       PPID          : " + parent);
                    Console.WriteLine("       Parent Name   : " + parentName);
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("   [+] Sucess - Parent of lsass.exe is wininit.exe");
                }

                ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    "SELECT * " +
                    "FROM Win32_Process " +
                    "WHERE ParentProcessId=" + myId);
                ManagementObjectCollection collection = searcher.Get();
                if (collection.Count > 0)
                {
                    foreach (var item in collection)
                    {
                        UInt32 childProcessId = (UInt32)item["ProcessId"];
                        if ((int)childProcessId != Process.GetCurrentProcess().Id)
                        {
                            Process childProcess = Process.GetProcessById((int)childProcessId);
                        }
                    }
                }
                else
                {
                    Console.Write("   [+] Sucess - lsass.exe has " + collection.Count + " child processes \n");
                }

            }
            if (i != 1)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("   [-] Found: " + i + " lsass.exe processes running!");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("   [+] Sucess - Only 1 lsass.exe found running");
            }
        }



        /// ////////////////////////////////////////////
        /// ////////////////////////////////////////////
        /// ////   IFEO Check          /////////////////
        /// ////////////////////////////////////////////
        /// ////////////////////////////////////////////
        public static void IFEO()
        {
            String registryKey = @"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
            
            using (Microsoft.Win32.RegistryKey key = Registry.LocalMachine.OpenSubKey(registryKey))
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("   [+] Checking IFEO SubKeys");
                var dnum = 0;
                var gnum = 0;
                // Store each IFEO subkey NAME in subkeyName
                foreach (String subkeyName in key.GetSubKeyNames())
                {
                    String ikey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\" + subkeyName;
                    //Get the values of each subkey and store in vkey
                    using (Microsoft.Win32.RegistryKey vkey = Registry.LocalMachine.OpenSubKey(ikey))
                    {
                        Console.ForegroundColor = ConsoleColor.Cyan;
                        //Look in each subkey value for 'debugger' and 'globalflag'
                        foreach (var subVals in vkey.GetValueNames())
                        {
                            if (subVals == "Debugger")
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine("      [-] 'Debugger' Value found in:");
                                Console.ForegroundColor = ConsoleColor.DarkRed;
                                Console.WriteLine("          " + vkey);
                                dnum = dnum + 1;
                            }

                            if (subVals == "GlobalFlag")
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine("      [-] 'GlobalFlag' Value found in:");
                                Console.ForegroundColor = ConsoleColor.DarkRed;
                                Console.WriteLine("          " + vkey);
                                gnum = gnum + 1;
                            }
                        }                       
                    }
                }

                if (dnum == 0)
                {
                    Console.ForegroundColor = ConsoleColor.DarkCyan;
                    Console.WriteLine("      [+] Success - 'Debugger' Value not found");
                }
                if (gnum == 0)
                {
                    Console.ForegroundColor = ConsoleColor.DarkCyan;
                    Console.WriteLine("      [+] Success - 'GlobalFlag' Value not found");
                }

            }

            String registryKeyWOW = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
            using (Microsoft.Win32.RegistryKey keyWOW = Registry.LocalMachine.OpenSubKey(registryKeyWOW))
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("   [+] Checking Wow6432Node IFEO SubKeys");
                var dnumWOW = 0;
                var gnumWOW = 0;
                // Store each IFEO subkey NAME in subkeyName
                foreach (String subkeyNameWOW in keyWOW.GetSubKeyNames())
                {
                    String ikeyWOW = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\" + subkeyNameWOW;
                    //Get the values of each subkey and store in vkey
                    using (Microsoft.Win32.RegistryKey vkeyWOW = Registry.LocalMachine.OpenSubKey(ikeyWOW))
                    {
                        Console.ForegroundColor = ConsoleColor.Cyan;
                        //Look in each subkey value for 'debugger' and 'globalflag'
                        foreach (var subValsWOW in vkeyWOW.GetValueNames())
                        {
                            if (subValsWOW == "Debugger")
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine("      [-] 'Debugger' Value found in:");
                                Console.ForegroundColor = ConsoleColor.DarkRed;
                                Console.WriteLine("          " + vkeyWOW);
                                dnumWOW = dnumWOW + 1;
                            }

                            if (subValsWOW == "GlobalFlag")
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine("      [-] 'GlobalFlag' Value found in:");
                                Console.ForegroundColor = ConsoleColor.DarkRed;
                                Console.WriteLine("          " + vkeyWOW);
                                gnumWOW = gnumWOW + 1;
                            }
                        }
                    }
                }

                if (dnumWOW == 0)
                {
                    Console.ForegroundColor = ConsoleColor.DarkCyan;
                    Console.WriteLine("      [+] Success - Wow6432Node 'Debugger' Value not found");
                }
                if (gnumWOW == 0)
                {
                    Console.ForegroundColor = ConsoleColor.DarkCyan;
                    Console.WriteLine("      [+] Success - Wow6432Node 'GlobalFlag' Value not found");
                }

            }

            String silentKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("   [+] Checking for SilentProcessExit Key");
            using (Microsoft.Win32.RegistryKey skey = Registry.LocalMachine.OpenSubKey(silentKey))
            {
                if (skey == null)
                {
                    Console.ForegroundColor = ConsoleColor.DarkCyan;
                    Console.WriteLine("      [+] Success - SilentProcessExit SubKey does not exist");
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("      [-] SilentProcessExit SubKey Found!");
                    foreach (String skeyName in skey.GetSubKeyNames())
                    {
                        Console.ForegroundColor = ConsoleColor.DarkRed;
                        Console.WriteLine("         " + skey);
                    }
                }

            }
            String silentKeyWOW = @"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("   [+] Checking for Wow6432Node SilentProcessExit Key");
            using (Microsoft.Win32.RegistryKey skeyWOW = Registry.LocalMachine.OpenSubKey(silentKeyWOW))
            {
                if (skeyWOW == null)
                {
                    Console.ForegroundColor = ConsoleColor.DarkCyan;
                    Console.WriteLine("      [+] Success - Wow6432Node SilentProcessExit SubKey does not exist");
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("      [-] Wow6432Node SilentProcessExit SubKey Found!");
                    foreach (String skeyNameWOW in skeyWOW.GetSubKeyNames())
                    {
                        Console.ForegroundColor = ConsoleColor.DarkRed;
                        Console.WriteLine("         " + skeyWOW);
                    }
                }

            }
        }


        /// ////////////////////////////////////////////
        /// ////////////////////////////////////////////
        /// ////   App Shimming        /////////////////
        /// ////////////////////////////////////////////
        /// ////////////////////////////////////////////
        public static void AppShims()
        {
            String appKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom";
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("   [+] Checking 'Custom' SubKey entries");
            using (Microsoft.Win32.RegistryKey skey = Registry.LocalMachine.OpenSubKey(appKey))
            {
                if (skey == null)
                {
                    Console.ForegroundColor = ConsoleColor.DarkCyan;
                    Console.WriteLine("      [+] Success - 'Custom' SubKey does not exist");
                }
                else
                {
                    var aSubKey = 0;
                    foreach (String skeyName in skey.GetSubKeyNames())
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("      [-] Custom SubKey Found! ");
                        Console.ForegroundColor = ConsoleColor.DarkRed;
                        Console.WriteLine("          " + skey + "\\" + skeyName);
                        aSubKey = aSubKey + 1;
                    }
                    if (aSubKey == 0)
                    {
                        Console.ForegroundColor = ConsoleColor.DarkCyan;
                        Console.WriteLine("      [+] Sucess - No SubKeys detected");
                    }
                }
            }

            String sdbKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB";
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("   [+] Checking 'InstalledSDB' SubKey entries");
            using (Microsoft.Win32.RegistryKey ukey = Registry.LocalMachine.OpenSubKey(sdbKey))
            {
                if (ukey == null)
                {
                    Console.ForegroundColor = ConsoleColor.DarkCyan;
                    Console.WriteLine("      [+] Success - 'InstalledSDB' SubKey does not exist");
                }
                else
                {
                    var uSubKey = 0;
                    foreach (String ukeyName in ukey.GetSubKeyNames())
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("      [-] InstalledSDB SubKey Found! ");
                        Console.ForegroundColor = ConsoleColor.DarkRed;
                        Console.WriteLine("          " + ukey + "\\" + ukeyName);
                        uSubKey = uSubKey + 1;
                    }
                    if (uSubKey == 0)
                    {
                        Console.ForegroundColor = ConsoleColor.DarkCyan;
                        Console.WriteLine("      [+] Sucess - No SubKeys detected");
                    }
                }
            }
        }


            /// ////////////////////////////////////////////
            /// ////////////////////////////////////////////     
            /// ////    Codename: StormlightDinosaur    ////
            /// ////////////////////////////////////////////
            /// ////////////////////////////////////////////
            static void Main(string[] args)
            {
            Header();
            Console.ForegroundColor = ConsoleColor.Magenta;
            if (IsAdministrator() != true)
            { Console.Write("[!] NOT Running as Administrator! Results will be skewed!" + "\n"); }


            // LSASS
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("[+] Verifying basic lsass.exe integrity - T1177" + "\n");
            EnumLsass();
            Console.Write("\n");

            // Run Keys
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("[+] Checking RunKeys - T1060" + "\n");
            RunKeys();
            Console.Write("\n");

            // Startup Folder
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("[+] Checking Startup Folder - T1060" + "\n");
            StartFolder();
            Console.Write("\n");

            // Services
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("[+] Checking Services - T1050" + "\n");
            EvilServices();
            Console.Write("\n");

            // Scheduled Tasks
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("[+] Checking Scheduled Tasks - T1053" + "\n");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("   [+] Searching Tasks that are utilizing unusual Binaries or Locations ");
            ParseScheduleTasks();
            Console.Write("\n");

            // SVCHOST
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("[+] Verifying Parent Process of running svchost.exe's is services.exe" + "\n");
            EnumSvchost();
            Console.Write("\n");

            // BITS
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("[+] Checking BITS Jobs - T1197" + "\n");
            BitsJobs();
            Console.Write("\n");

            // WMI Event Subscriptions
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("[+] Checking WMI Event Subscriptions - T1084" + "\n");
            WmiSubs();
            Console.Write("\n");

            // IFEO
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("[+] Checking Accessibility Abuse (IFEO) - T1183" + "\n");
            IFEO();
            Console.Write("\n");

            // Application Shimming
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("[+] Checking Application Shims - T1138" + "\n");
            AppShims();
            Console.Write("\n");

            // NetSh DLL Helpers
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("[+] Checking Netsh DLL Helpers - T1128" + "\n");
            NethshHelpers();
            Console.Write("\n");

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("------------------------------------------------------------------------------");
            Console.WriteLine("----------------------          COMPLETE          ----------------------------");
            Console.WriteLine("------------------------------------------------------------------------------");
            Console.ResetColor();
            //Console.ReadLine();

            }

    }
}
