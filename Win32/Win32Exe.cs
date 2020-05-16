/* ----------------------------------------------------------------------------
Kohoutech Win32 Library
Copyright (C) 1998-2020  George E Greaney

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
----------------------------------------------------------------------------*/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

//win32 exe model
//https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files
//https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format

namespace Kohoutech.Win32
{
    public class Win32Exe
    {
        public String filename;
        public bool isDLL;

        public MsDosHeader dosHeader;

        //coff header fields
        public MachineType machine;
        public uint timeStamp;
        public uint characteristics;

        //optional header fields
        public uint magicNum;
        public uint majorLinkerVersion;
        public uint minorLinkerVersion;
        public uint sizeOfCode;
        public uint sizeOfInitializedData;
        public uint sizeOfUninitializedData;
        public uint addressOfEntryPoint;
        public uint baseOfCode;
        public uint baseOfData;
        public uint imageBase;
        public uint sectionAlignment;
        public uint fileAlignment;
        public uint majorOSVersion;
        public uint minorOSVersion;
        public uint majorImageVersion;
        public uint minorImageVersion;
        public uint majorSubsystemVersion;
        public uint minorSubsystemVersion;
        public uint win32VersionValue;
        public uint sizeOfImage;
        public uint sizeOfHeaders;
        public uint checksum;
        public uint subsystem;
        public uint dLLCharacteristics;
        public uint sizeOfStackReserve;
        public uint sizeOfStackCommit;
        public uint sizeOfHeapReserve;
        public uint sizeOfHeapCommit;
        public uint loaderFlags;
        public uint numberOfRvaAndSizes;

        //dataDirectory entries
        public DataDirectory dExportTable;
        public DataDirectory dImportTable;
        public DataDirectory dResourceTable;
        public DataDirectory exceptionTable;
        public DataDirectory certificatesTable;
        public DataDirectory baseRelocationTable;
        public DataDirectory debugTable;
        public DataDirectory architecture;
        public DataDirectory globalPtr;
        public DataDirectory threadLocalStorageTable;
        public DataDirectory loadConfigurationTable;
        public DataDirectory boundImportTable;
        public DataDirectory importAddressTable;
        public DataDirectory delayImportDescriptor;
        public DataDirectory CLRRuntimeHeader;
        public DataDirectory reserved;

        public List<Section> sections;

        //standard sections
        public ImportTable importTable;
        public ExportTable exportTable;
        public ResourceTable resourceTable;

        public Win32Exe()
        {
            filename = null;
            isDLL = false;

            dosHeader = null;

            //coff header fields
            machine = MachineType.IMAGE_FILE_MACHINE_I386;
            timeStamp = 0;
            characteristics = 0;

            //optional header fields
            magicNum = 0x010b;                  //PE32 executable
            majorLinkerVersion = 0;
            minorLinkerVersion = 1;
            sizeOfCode = 0;
            sizeOfInitializedData = 0;
            sizeOfUninitializedData = 0;
            addressOfEntryPoint = 0;
            baseOfCode = 0;
            baseOfData = 0;
            imageBase = 0x400000;
            sectionAlignment = 0x1000;
            fileAlignment = 0x200;
            majorOSVersion = 5;
            minorOSVersion = 1;
            majorImageVersion = 0;
            minorImageVersion = 0;
            majorSubsystemVersion = 5;
            minorSubsystemVersion = 1;
            win32VersionValue = 0;                   //reserved, must be zero
            sizeOfImage = 0;
            sizeOfHeaders = 0;
            checksum = 0;
            subsystem = 2;
            dLLCharacteristics = 0;
            sizeOfStackReserve = 0x100000;
            sizeOfStackCommit = 0x1000;
            sizeOfHeapReserve = 0x100000;
            sizeOfHeapCommit = 0x1000;
            loaderFlags = 0;                        //reserved, must be zero
            numberOfRvaAndSizes = 0x10;             //"not fixed" but the PE format spec only defines 16 of these

            //data directory
            dExportTable = new DataDirectory();
            dImportTable = new DataDirectory();
            dResourceTable = new DataDirectory();
            exceptionTable = new DataDirectory();
            certificatesTable = new DataDirectory();
            baseRelocationTable = new DataDirectory();
            debugTable = new DataDirectory();
            architecture = new DataDirectory();
            globalPtr = new DataDirectory();
            threadLocalStorageTable = new DataDirectory();
            loadConfigurationTable = new DataDirectory();
            boundImportTable = new DataDirectory();
            importAddressTable = new DataDirectory();
            delayImportDescriptor = new DataDirectory();
            CLRRuntimeHeader = new DataDirectory();
            reserved = new DataDirectory();

            sections = new List<Section>();

            //standard sections
            exportTable = null;
            importTable = null;
            resourceTable = null;
        }

        //- reading in ----------------------------------------------------------------

        //public void readFile(String _filename)
        //{
        //    filename = _filename;

        //    SourceFile source = new SourceFile(filename);

        //    dosHeader = MsDosHeader.readMSDOSHeader(source);
        //    source.seek(dosHeader.e_lfanew);
        //    uint pesig = source.getFour();
        //    if (pesig != 0x00004550)
        //    {
        //        throw new Win32ReadException("this is not a valid win32 executable file");
        //    }

        //    readCoffHeader(source);
        //    readOptionalHeader(source);
        //    loadSections(source);
        //    foreach (Section section in sections)
        //    {
        //        section.imageBase = imageBase;          //sections in exe/dll have an image base
        //    }
        //    //getResourceTable(source);
        //}

        //private void readOptionalHeader(SourceFile source)
        //{
        //    magicNum = source.getTwo();
        //    majorLinkerVersion = source.getOne();
        //    minorLinkerVersion = source.getOne();
        //    sizeOfCode = source.getFour();
        //    sizeOfInitializedData = source.getFour();
        //    sizeOfUninitializedData = source.getFour();
        //    addressOfEntryPoint = source.getFour();
        //    baseOfCode = source.getFour();
        //    baseOfData = source.getFour();
        //    imageBase = source.getFour();
        //    sectionAlignment = source.getFour();
        //    fileAlignment = source.getFour();
        //    majorOSVersion = source.getTwo();
        //    minorOSVersion = source.getTwo();
        //    majorImageVersion = source.getTwo();
        //    minorImageVersion = source.getTwo();
        //    majorSubsystemVersion = source.getTwo();
        //    minorSubsystemVersion = source.getTwo();
        //    win32VersionValue = source.getFour();
        //    sizeOfImage = source.getFour();
        //    sizeOfHeaders = source.getFour();
        //    checksum = source.getFour();
        //    subsystem = source.getTwo();
        //    dLLCharacteristics = source.getTwo();
        //    sizeOfStackReserve = source.getFour();
        //    sizeOfStackCommit = source.getFour();
        //    sizeOfHeapReserve = source.getFour();
        //    sizeOfHeapCommit = source.getFour();
        //    loaderFlags = source.getFour();
        //    numberOfRvaAndSizes = source.getFour();

        //    dExportTable = DataDirectory.readDataDirectory(source);
        //    dImportTable = DataDirectory.readDataDirectory(source);
        //    dResourceTable = DataDirectory.readDataDirectory(source);
        //    exceptionTable = DataDirectory.readDataDirectory(source);
        //    certificatesTable = DataDirectory.readDataDirectory(source);
        //    baseRelocationTable = DataDirectory.readDataDirectory(source);
        //    debugTable = DataDirectory.readDataDirectory(source);
        //    architecture = DataDirectory.readDataDirectory(source);
        //    globalPtr = DataDirectory.readDataDirectory(source);
        //    threadLocalStorageTable = DataDirectory.readDataDirectory(source);
        //    loadConfigurationTable = DataDirectory.readDataDirectory(source);
        //    boundImportTable = DataDirectory.readDataDirectory(source);
        //    importAddressTable = DataDirectory.readDataDirectory(source);
        //    delayImportDescriptor = DataDirectory.readDataDirectory(source);
        //    CLRRuntimeHeader = DataDirectory.readDataDirectory(source);
        //    reserved = DataDirectory.readDataDirectory(source);
        //}

        //private void getResourceTable(SourceFile source)
        //{
        //    if (optHeader.dataDirectory[DataDirectory.IMAGE_DIRECTORY_ENTRY_RESOURCE].size > 0)
        //    {
        //        uint resOfs = optHeader.dataDirectory[DataDirectory.IMAGE_DIRECTORY_ENTRY_RESOURCE].rva;
        //        uint resSize = optHeader.dataDirectory[DataDirectory.IMAGE_DIRECTORY_ENTRY_RESOURCE].size;
        //        Section resSec = findSection(resOfs);
        //        if (resSec != null)
        //        {
        //            SourceFile secData = new SourceFile(resSec.data);
        //            resourceTable = new ResourceTable();
        //            resourceTable.imageBase = imageBase;
        //            resourceTable.resourceRVA = resOfs;
        //            resourceTable.data = secData.getRange(resOfs - resSec.memloc, resSize);
        //        }
        //    }
        //}

        //- writing out ----------------------------------------------------------------

        public void buildSectionTable()
        {
            uint secStart = sizeOfHeaders;
            uint secMem = 0x1000;
            for (int i = 0; i < sections.Count; i++)
            {
                Section sec = sections[i];
                sec.filePos = secStart;
                sec.fileSize = ((((uint)sec.data.Count) + (fileAlignment - 1) / fileAlignment) * fileAlignment);
                secStart += sec.fileSize;

                sec.memPos = secMem;
                sec.memSize = (uint)sec.data.Count;
                secMem += ((((sec.memSize) + sectionAlignment - 1) / sectionAlignment) * sectionAlignment);
            }
        }

        public void writeCoffHeader(OutputFile outfile)
        {
            outfile.putFour(0x00004550);            //PE sig
            outfile.putTwo((uint)machine);
            outfile.putTwo((uint)sections.Count);
            outfile.putFour(timeStamp);
            outfile.putFour(0);                     //no symbol table
            outfile.putFour(0);
            outfile.putTwo(0xe0);                   //optional hdr size
            outfile.putTwo(characteristics);
        }

        public void writeOptionalHeader(OutputFile outfile)
        {
            outfile.putTwo(magicNum);
            outfile.putOne(majorLinkerVersion);
            outfile.putOne(minorLinkerVersion);
            outfile.putFour(sizeOfCode);
            outfile.putFour(sizeOfInitializedData);
            outfile.putFour(sizeOfUninitializedData);
            outfile.putFour(addressOfEntryPoint);
            outfile.putFour(baseOfCode);
            outfile.putFour(baseOfData);
            outfile.putFour(imageBase);
            outfile.putFour(sectionAlignment);
            outfile.putFour(fileAlignment);
            outfile.putTwo(majorOSVersion);
            outfile.putTwo(minorOSVersion);
            outfile.putTwo(majorImageVersion);
            outfile.putTwo(minorImageVersion);
            outfile.putTwo(majorSubsystemVersion);
            outfile.putTwo(minorSubsystemVersion);
            outfile.putFour(win32VersionValue);
            outfile.putFour(sizeOfImage);
            outfile.putFour(sizeOfHeaders);
            outfile.putFour(checksum);
            outfile.putTwo(subsystem);
            outfile.putTwo(dLLCharacteristics);
            outfile.putFour(sizeOfStackReserve);
            outfile.putFour(sizeOfStackCommit);
            outfile.putFour(sizeOfHeapReserve);
            outfile.putFour(sizeOfHeapCommit);
            outfile.putFour(loaderFlags);
            outfile.putFour(numberOfRvaAndSizes);

            dExportTable.writeOut(outfile);
            dImportTable.writeOut(outfile);
            dResourceTable.writeOut(outfile);
            exceptionTable.writeOut(outfile);
            certificatesTable.writeOut(outfile);
            baseRelocationTable.writeOut(outfile);
            debugTable.writeOut(outfile);
            architecture.writeOut(outfile);
            globalPtr.writeOut(outfile);
            threadLocalStorageTable.writeOut(outfile);
            loadConfigurationTable.writeOut(outfile);
            boundImportTable.writeOut(outfile);
            importAddressTable.writeOut(outfile);
            delayImportDescriptor.writeOut(outfile);
            CLRRuntimeHeader.writeOut(outfile);
            reserved.writeOut(outfile);
        }

        public void writeSectionTable(OutputFile outfile)
        {
            for (int i = 0; i < sections.Count; i++)
            {
                sections[i].writeSectionTblEntry(outfile);
            }
        }

        public void writeSectionData(OutputFile outfile)
        {
            for (int i = 0; i < sections.Count; i++)
            {
                sections[i].writeSectionData(outfile);
            }
        }

        public void writeFile(String filename)
        {
            //build standard sections
            int importSecNum = -1;
            if (importTable != null)
            {
                importSecNum = sections.Count;
                Section importSection = importTable.createSection();
                sections.Add(importSection);
            }

            int exportSecNum = -1;
            if (exportTable != null)
            {
                exportSecNum = sections.Count;
                Section exportSection = exportTable.createSection();
                sections.Add(exportSection);
            }

            int resourceSecNum = -1;
            if (resourceTable != null)
            {
                resourceSecNum = sections.Count;
                Section resourceSection = resourceTable.createSection();
                sections.Add(resourceSection);
            }

            //build dos header
            if (dosHeader == null)
            {
                dosHeader = new MsDosHeader();
            }
            uint winHdrPos = (((dosHeader.headerSize + 7) / 8) * 8);
            dosHeader.e_lfanew = winHdrPos;

            //win hdr fields
            characteristics = 0x102;        //IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE
            if (isDLL)
            {
                characteristics |= 0x2000;      //IMAGE_FILE_DLL
            }

            sizeOfHeaders = ((((winHdrPos + 0x18 + 0xe0 + (uint)(sections.Count * 0x28)) + (fileAlignment - 1)) / fileAlignment) * fileAlignment);

            buildSectionTable();

            OutputFile outfile = new OutputFile(filename);
            dosHeader.writeOut(outfile);
            outfile.putZeros(winHdrPos - dosHeader.headerSize);

            writeCoffHeader(outfile);
            writeOptionalHeader(outfile);
            writeSectionTable(outfile);
            writeSectionData(outfile);

            outfile.writeOut();
        }
    }

    //- ms dos header -------------------------------------------------------------

    //the dos header is only used in reading in / writing out win32 exe files
    public class MsDosHeader
    {
        public uint signature;
        public uint lastsize;
        public uint nblocks;
        public uint nreloc;
        public uint hdrsize;
        public uint minalloc;
        public uint maxalloc;
        public uint ss;
        public uint sp;
        public uint checksum;
        public uint ip;
        public uint cs;
        public uint relocpos;
        public uint noverlay;
        public byte[] reserved1;
        public uint oem_id;
        public uint oem_info;
        public byte[] reserved2;
        public uint e_lfanew;         // Offset to the 'PE\0\0' signature relative to the beginning of the file
        public byte[] stub;

        public uint headerSize;      //size of entire header, including the stub bytes

        public MsDosHeader()
        {
            signature = 0x5a4d;     //MZ
            lastsize = 0x90;
            nblocks = 1;
            nreloc = 0;
            hdrsize = 4;            //number of 16 byte paragraphs up to the header (64 bytes total)
            minalloc = 0;
            maxalloc = 0xffff;
            ss = 0;
            sp = 0xb8;
            checksum = 0;
            ip = 0;
            cs = 0;
            relocpos = 0x40;
            noverlay = 0;
            reserved1 = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };
            oem_id = 0;
            oem_info = 0;
            reserved2 = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            e_lfanew = 0;
            stub = new byte[] {0x0e,0x1f,0xba,0x0e,0x00,0xb4,0x09,0xcd,0x21,0xb8,0x01,0x4c,0xcd,0x21,0x44,0x6f,
                               0x6e,0x27,0x74,0x20,0x65,0x76,0x65,0x6e,0x20,0x74,0x68,0x69,0x6e,0x6b,0x20,0x6f,
                               0x66,0x20,0x72,0x75,0x6e,0x6e,0x69,0x4e,0x67,0x20,0x74,0x68,0x6e,0x73,0x20,0x69,
                               0x4e,0x20,0x57,0x49,0x4e,0x20,0x6d,0x6f,0x64,0x65,0x0d,0x0a,0x24};
                            //"Don't even think of running this in DOS mode.\r\n$"
            headerSize = (uint)(0x40 + stub.Length);
        }

        static public MsDosHeader readMSDOSHeader(SourceFile source)
        {
            MsDosHeader dosHeader = new MsDosHeader();

            dosHeader.signature = source.getTwo();
            if (dosHeader.signature != 0x5a4d)
            {
                throw new Win32FormatException("this is not a valid win32 executable file");
            }

            dosHeader.lastsize = source.getTwo();
            dosHeader.nblocks = source.getTwo();
            dosHeader.nreloc = source.getTwo();
            dosHeader.hdrsize = source.getTwo();
            dosHeader.minalloc = source.getTwo();
            dosHeader.maxalloc = source.getTwo();
            dosHeader.ss = source.getTwo();
            dosHeader.sp = source.getTwo();
            dosHeader.checksum = source.getTwo();
            dosHeader.ip = source.getTwo();
            dosHeader.cs = source.getTwo();
            dosHeader.relocpos = source.getTwo();
            dosHeader.noverlay = source.getTwo();
            dosHeader.reserved1 = source.getRange(8);
            dosHeader.oem_id = source.getTwo();
            dosHeader.oem_info = source.getTwo();
            dosHeader.reserved2 = source.getRange(20);
            dosHeader.e_lfanew = source.getFour();

            return dosHeader;
        }

        public void writeOut(OutputFile outfile)
        {

            outfile.putTwo(signature);

            outfile.putTwo(lastsize);
            outfile.putTwo(nblocks);
            outfile.putTwo(nreloc);
            outfile.putTwo(hdrsize);
            outfile.putTwo(minalloc);
            outfile.putTwo(maxalloc);
            outfile.putTwo(ss);
            outfile.putTwo(sp);
            outfile.putTwo(checksum);
            outfile.putTwo(ip);
            outfile.putTwo(cs);
            outfile.putTwo(relocpos);
            outfile.putTwo(noverlay);
            outfile.putZeros(8);
            outfile.putTwo(oem_id);
            outfile.putTwo(oem_info);
            outfile.putZeros(20);
            outfile.putFour(e_lfanew);
            outfile.putRange(stub);
        }
    }


    //- data directory ------------------------------------------------------------

    public class DataDirectory
    {
        public uint rva;
        public uint size;

        public DataDirectory() : this(0, 0)
        {
        }

        public DataDirectory(uint _rva, uint _size)
        {
            rva = _rva;
            size = _size;
        }

        static public DataDirectory readIn(SourceFile source)
        {
            uint rva = source.getFour();
            uint size = source.getFour();
            return new DataDirectory(rva, size);
        }

        public void writeOut(OutputFile outfile)
        {
            outfile.putFour(rva);
            outfile.putFour(size);
        }
    }

    //- error handling ------------------------------------------------------------

    class Win32FormatException : Exception
    {
        public Win32FormatException(string message)
            : base(message)
        {
        }
    }
}

//Console.WriteLine("there's no sun in the shadow of the wizard");