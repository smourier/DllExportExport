using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace DllExportExport
{
    public class DllExport
    {
        private readonly List<string> _names = new List<string>();

        private DllExport(string filePath, PEFormat format)
        {
            FilePath = filePath;
            Format = format;
        }

        public string FilePath { get; }
        public IReadOnlyList<string> Names => _names.AsReadOnly();
        public PEFormat Format { get; }

        public override string ToString() => Format + " " + FilePath;

        public static DllExport FromFile(string filePath)
        {
            if (filePath == null)
                throw new ArgumentNullException(nameof(filePath));

            try
            {
                using (var file = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    if (file.Length <= 60)
                        return null;

                    var br = new BinaryReader(file);
                    if (br.ReadByte() != 'M' || br.ReadByte() != 'Z')
                        return null;

                    file.Seek(60, SeekOrigin.Begin);
                    var e_lfanew = br.ReadInt32();

                    file.Seek(e_lfanew, SeekOrigin.Begin);
                    if (br.ReadInt32() != 0x4550) // PE
                        return null;

                    file.Seek(e_lfanew + 4 + 2, SeekOrigin.Begin);
                    var numberOfSections = br.ReadInt16();
                    if (numberOfSections == 0)
                        return null;

                    file.Seek(e_lfanew + 16 + 2, SeekOrigin.Begin);
                    var sizeOfOptionalHeader = br.ReadInt16();

                    file.Seek(e_lfanew + 24, SeekOrigin.Begin); // max size of PE32
                    var optionalHeader = file.Position;
                    var format = (PEFormat)br.ReadInt16();
                    if (format != PEFormat.PE32 && format != PEFormat.PE32Plus)
                        return null;

                    var export = new DllExport(filePath, format);
                    file.Seek(optionalHeader + (format == PEFormat.PE32 ? 92 : 108), SeekOrigin.Begin);
                    var numberOfRvaAndSizes = br.ReadInt32();
                    if (numberOfRvaAndSizes != 16)
                        return null;

                    var exportVirtualAddress = br.ReadUInt32();
                    var exportSize = br.ReadUInt32();
                    if (exportVirtualAddress == 0 || exportSize == 0)
                        return export;

                    file.Seek(numberOfRvaAndSizes * 8 - 8, SeekOrigin.Current);
                    var sections = new List<Section>();
                    for (var i = 0; i < numberOfSections; i++)
                    {
                        var section = new Section();
                        sections.Add(section);

                        section.Name = Encoding.ASCII.GetString(br.ReadBytes(8)).Replace("\0", string.Empty);
                        section.VirtualSize = br.ReadUInt32();
                        section.VirtualAddress = br.ReadUInt32();
                        section.SizeOfRawData = br.ReadUInt32();
                        section.PointerToRawData = br.ReadUInt32();
                        section.PointerToRelocations = br.ReadUInt32();
                        section.PointerToLinenumbers = br.ReadUInt32();
                        section.NumberOfRelocations = br.ReadInt16();
                        section.NumberOfLinenumbers = br.ReadInt16();
                        section.Characteristics = br.ReadUInt32();
                    }

                    var offset = rvaToOffset(exportVirtualAddress);

                    // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#export-directory-table
                    file.Seek(offset + 24, SeekOrigin.Begin);
                    var numberOfNames = br.ReadInt32();
                    var exportAddressTableRva = br.ReadInt32();
                    var namePointerRva = br.ReadUInt32();

                    var namesOffset = rvaToOffset(namePointerRva);
                    file.Seek(namesOffset, SeekOrigin.Begin);

                    for (var i = 0; i < numberOfNames; i++)
                    {
                        var nameRva = br.ReadUInt32();
                        var pos = file.Position;
                        file.Seek(rvaToOffset(nameRva), SeekOrigin.Begin);

                        var sb = new StringBuilder();
                        do
                        {
                            var c = br.ReadByte();
                            if (c == 0)
                                break;

                            sb.Append((char)c);
                        }
                        while (true);

                        export._names.Add(sb.ToString());
                        file.Seek(pos, SeekOrigin.Begin);
                    }

                    uint rvaToOffset(uint rva)
                    {
                        for (var i = 0; i < sections.Count; i++)
                        {
                            var o = sections[i].VirtualAddress + sections[i].SizeOfRawData;
                            if (o >= rva)
                                return sections[i].PointerToRawData + rva + sections[i].SizeOfRawData - o;
                        }
                        return 0xFFFFFFFF;
                    }
                    return export;
                }
            }
            catch (UnauthorizedAccessException)
            {
                return null;
            }
            catch (Exception e)
            {
#if DEBUG
                Console.WriteLine("ERROR " + e.GetType().FullName + ": " + e.Message);
#endif
                return null;
            }
        }

        private class Section
        {
            public string Name;
            public uint VirtualSize;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public uint PointerToRelocations;
            public uint PointerToLinenumbers;
            public short NumberOfRelocations;
            public short NumberOfLinenumbers;
            public uint Characteristics;

            public override string ToString() => Name;
        }

        public static IEnumerable<DllExport> FromDirectory(string directoryPath, string searchPattern = null, SearchOption searchOption = SearchOption.TopDirectoryOnly)
        {
            if (directoryPath == null)
                throw new ArgumentNullException(nameof(directoryPath));

            searchPattern = searchPattern ?? "*.*";
            foreach (var file in Directory.EnumerateFiles(directoryPath, searchPattern, searchOption))
            {
                var export = FromFile(file);
                if (export != null)
                {
                    yield return export;
                }
            }
        }
    }
}
