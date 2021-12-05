using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;

namespace DllExportExport
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("DllExportExport - Copyright (C) 2020-" + DateTime.Now.Year + " Simon Mourier. All rights reserved.");
            Console.WriteLine();

            var path = CommandLine.GetNullifiedArgument(0);
            if (CommandLine.HelpRequested || args.Length < 1 || path == null)
            {
                Help();
                return;
            }

            path = Path.Combine(Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName), path);
            Console.WriteLine("Path: " + path);

            if (Directory.Exists(path))
            {
                var recursive = CommandLine.GetArgument("s", false);
                Console.WriteLine("Recursive: " + recursive);

                var options = new EnumerationOptions();
                options.RecurseSubdirectories = recursive;

                var dirExports = DllExport.FromDirectory(path, null, options);
                foreach (var dirExport in dirExports)
                {
                    Console.WriteLine(dirExport);
                    foreach (var name in dirExport.Names)
                    {
                        Console.WriteLine(" " + name);
                    }
                }
                return;
            }

            var fileExport = DllExport.FromFile(path);
            if (fileExport == null)
            {
                Console.WriteLine("File is not valid.");
                return;
            }

            Console.WriteLine(fileExport);
            foreach (var name in fileExport.Names)
            {
                Console.WriteLine(" " + name);
            }
        }

        static void Help()
        {
            Console.WriteLine(Assembly.GetEntryAssembly().GetName().Name.ToUpperInvariant() + " <directory path> or <file path>");
            Console.WriteLine();
            Console.WriteLine("Description:");
            Console.WriteLine("    This tool is used to dump all DLL exports from a directory or a file.");
            Console.WriteLine();
            Console.WriteLine("Example:");
            Console.WriteLine();
            Console.WriteLine("    " + Assembly.GetEntryAssembly().GetName().Name.ToUpperInvariant() + " c:\\windows\\system32");
            Console.WriteLine();
            Console.WriteLine("    Dumps all DLL exports for all DLL files in the c:\\windows\\system32 directory.");
            Console.WriteLine();
        }
    }
}
