/* ----------------------------------------------------------------------------
Kohoutech OBOE Library
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

using Kohoutech.Binary;

//win32 exe model
//https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files
//https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format

namespace Kohoutech.OBOE
{
    public class Win32Exe : Win32Coff
    {
        public String filename;
        public bool isDLL;

        public uint mempos;
        public uint filepos;

        public MsDosHeader dosHeader;

        //coff header fields
        public MachineType machine;
        public DateTime timeStamp;
        public Characteristics characteristics;

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
        public uint memAlignment;
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

        public List<CoffSection> sections;

        //standard sections
        public CoffSection importSec;
        public List<CoffImportEntry> importList;
        public CoffSection exportSec;
        public List<CoffExportEntry> exportList;
        public CoffSection resourceSec;
        public List<ResourceData> resourceList;
        public CoffSection relocSec;
        public List<CoffRelocationEntry> relocList;

        public Win32Exe()
        {
            filename = null;
            isDLL = false;

            mempos = 0;
            filepos = 0;

            dosHeader = null;

            //coff header fields
            machine = MachineType.IMAGE_FILE_MACHINE_I386;
            timeStamp = DateTime.Now;
            characteristics = new Characteristics();

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
            imageBase = 0x400000;               //exe default image base
            memAlignment = 0x1000;
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
            dLLCharacteristics = 0x140;
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

            sections = new List<CoffSection>();

            //standard sections
            importSec = null;
            importList = new List<CoffImportEntry>();
            exportSec = null;
            exportList = new List<CoffExportEntry>();
            resourceSec = null;
            resourceList = new List<ResourceData>();
            relocSec = null;
            relocList = new List<CoffRelocationEntry>();
            
        }

        internal void addRelocationiList(List<uint> _relocList)
        {
            foreach(uint raddr in _relocList)
            {
                relocList.Add(new CoffRelocationEntry(raddr));
            }
        }

        //- reading in ----------------------------------------------------------------

        public void readFile(String _filename)
        {
            filename = _filename;

            BinaryIn source = new BinaryIn(filename);

            dosHeader = MsDosHeader.readMSDOSHeader(source);
            source.seek(dosHeader.e_lfanew);
            uint pesig = source.getFour();
            if (pesig != 0x00004550)
            {
                throw new Win32ReadException("this is not a valid win32 executable file");
            }

            machine = (MachineType)source.getTwo();
            uint secCount = source.getTwo();
            uint stamp = source.getFour();
            timeStamp = setTimestamp(stamp);
            uint symbolTblAddr = source.getFour();
            uint symbolTblCount = source.getFour();                 //these fields should be zero
            uint optionalHdrSize = source.getTwo();
            if (optionalHdrSize != 0xe0)
            {
                throw new Win32ReadException("this is not a valid win32 executable file");
            }
            uint flags = source.getTwo();
            characteristics = Characteristics.decodeFlags(flags);

            readOptionalHeader(source);
            loadSections(source, secCount);

            //getImportTable(source);
            //getExportTable(source);
            //getResourceTable(source);
        }

        public DateTime setTimestamp(uint stamp)
        {
            DateTime then = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Local);
            DateTime now = then.AddSeconds(stamp);                                      //from 1970/1/1 00:00:00 to now
            return now;
        }

        private void loadSections(BinaryIn source, uint secCount)
        {
            for(int i = 0; i < secCount; i++)
            {
                CoffSection sec = CoffSection.readSection(source);
                sec.owner = this;
                sec.secNum = i + 1;
                sections.Add(sec);
            }
        }

        private void readOptionalHeader(BinaryIn source)
        {
            magicNum = source.getTwo();
            majorLinkerVersion = source.getOne();
            minorLinkerVersion = source.getOne();
            sizeOfCode = source.getFour();
            sizeOfInitializedData = source.getFour();
            sizeOfUninitializedData = source.getFour();
            addressOfEntryPoint = source.getFour();
            baseOfCode = source.getFour();
            baseOfData = source.getFour();
            imageBase = source.getFour();
            memAlignment = source.getFour();
            fileAlignment = source.getFour();
            majorOSVersion = source.getTwo();
            minorOSVersion = source.getTwo();
            majorImageVersion = source.getTwo();
            minorImageVersion = source.getTwo();
            majorSubsystemVersion = source.getTwo();
            minorSubsystemVersion = source.getTwo();
            win32VersionValue = source.getFour();
            sizeOfImage = source.getFour();
            sizeOfHeaders = source.getFour();
            checksum = source.getFour();
            subsystem = source.getTwo();
            dLLCharacteristics = source.getTwo();
            sizeOfStackReserve = source.getFour();
            sizeOfStackCommit = source.getFour();
            sizeOfHeapReserve = source.getFour();
            sizeOfHeapCommit = source.getFour();
            loaderFlags = source.getFour();
            numberOfRvaAndSizes = source.getFour();

            dExportTable = DataDirectory.readIn(source);
            dImportTable = DataDirectory.readIn(source);
            dResourceTable = DataDirectory.readIn(source);
            exceptionTable = DataDirectory.readIn(source);
            certificatesTable = DataDirectory.readIn(source);
            baseRelocationTable = DataDirectory.readIn(source);
            debugTable = DataDirectory.readIn(source);
            architecture = DataDirectory.readIn(source);
            globalPtr = DataDirectory.readIn(source);
            threadLocalStorageTable = DataDirectory.readIn(source);
            loadConfigurationTable = DataDirectory.readIn(source);
            boundImportTable = DataDirectory.readIn(source);
            importAddressTable = DataDirectory.readIn(source);
            delayImportDescriptor = DataDirectory.readIn(source);
            CLRRuntimeHeader = DataDirectory.readIn(source);
            reserved = DataDirectory.readIn(source);
        }

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

        public void writeFile(String _filename)
        {
            filename = _filename;
            mempos = 0x1000;
            filepos = 0;

            //build dos header
            if (dosHeader == null)
            {
                dosHeader = new MsDosHeader();
            }
            uint winHdrPos = (((dosHeader.headerSize + 7) / 8) * 8);
            dosHeader.e_lfanew = winHdrPos;

            //win hdr fields
            characteristics.isExecutable = true;
            characteristics.is32BitMachine = true;
            if (isDLL)
            {
                characteristics.isDLL = true;
                imageBase = 0x10000000;         //dll default image base
            }

            uint sectionCount = (uint)sections.Count;
            if (exportList.Count > 0)
            {
                sectionCount++;
            }
            if (relocList.Count > 0)
            {
                sectionCount++;
            }
            filepos = (winHdrPos + 0x18 + 0xe0 + (uint)(sectionCount * 0x28) + (fileAlignment - 1)) & ~(fileAlignment - 1);
            sizeOfHeaders = filepos;

            buildSectionTable();

            //build standard sections
            //int importSecNum = -1;
            //if (importTable != null)
            //{
            //    importSecNum = sections.Count;
            //    CoffSection importSection = importTable.createSection();
            //    sections.Add(importSection);
            //}

            if (exportList.Count > 0)
            {
                buildExportSection();
            }

            //int resourceSecNum = -1;
            //if (resourceTable != null)
            //{
            //    resourceSecNum = sections.Count;
            //    CoffSection resourceSection = resourceTable.createSection();
            //    sections.Add(resourceSection);
            //}

            if (relocList.Count > 0)
            {
                buildRelocSection();
            }

            sizeOfImage = mempos;     //total image size

            BinaryOut outfile = new BinaryOut(filename);
            dosHeader.writeOut(outfile);
            outfile.putZeros(winHdrPos - dosHeader.headerSize);

            writeCoffHeader(outfile);
            writeOptionalHeader(outfile);
            writeSectionTable(outfile);
            outfile.putZeros(sizeOfHeaders - outfile.getPos());
            writeSectionData(outfile);

            outfile.writeOut();
        }

        public int getTimestamp()
        {
            DateTime then = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Local);
            //DateTime now = DateTime.Now;
            TimeSpan since = timeStamp.Subtract(then);                       //from 1970/1/1 00:00:00 to now
            int seconds = Convert.ToInt32(since.TotalSeconds);
            return seconds;
        }

        public void buildSectionTable()
        {
            //uint secStart = sizeOfHeaders;
            for (int i = 0; i < sections.Count; i++)
            {
                CoffSection sec = sections[i];

                //file pos- if file size != 0, use that instead of data count
                sec.filePos = filepos;
                uint datasize = (uint)sec.data.Count;
                if (sec.fileSize > 0)
                {
                    datasize = sec.fileSize;
                }
                sec.fileSize = (datasize + (fileAlignment - 1)) & ~(fileAlignment - 1);
                filepos += sec.fileSize;

                uint msize = (sec.memSize + fileAlignment - 1) & ~(fileAlignment - 1);
                if (sec.settings.hasCode)
                {
                    sizeOfCode += msize;
                    if (baseOfCode == 0)
                    {
                        baseOfCode = sec.memPos;
                    }
                }
                if (sec.settings.hasInitData) 
                { 
                    sizeOfInitializedData += msize;
                    if (baseOfData == 0)
                    {
                        baseOfData = sec.memPos;
                    }
                }
                if (sec.settings.hasUninitData) 
                { 
                    sizeOfUninitializedData += msize; 
                }

                uint memsize = (sec.memSize + memAlignment - 1) & ~(memAlignment - 1);
                mempos += memsize;
            }
        }

        //standard sections
        public void buildExportSection()
        {
            uint ordinalBase = 1;
            BinaryOut expData = new BinaryOut();
            expData.putFour(0);
            expData.putFour((uint)getTimestamp());
            expData.putTwo(1);
            expData.putTwo(0);
            expData.putFour(0);                             //filename addr
            expData.putFour(ordinalBase);                   
            expData.putFour((uint)exportList.Count);
            expData.putFour((uint)exportList.Count);
            expData.putFour(0x28 + mempos);
            uint expnametbl = 0x28 + 4 * (uint)exportList.Count;
            expData.putFour(expnametbl + mempos);
            uint ordtbl = expnametbl + 4 * (uint)exportList.Count;
            expData.putFour(ordtbl + mempos);

            //export addr tbl 
            foreach(CoffExportEntry exp in exportList)
            {
                expData.putFour(exp.addr);
            }

            //export name tbl 
            expData.skip(4 * (uint)exportList.Count);

            //ordinal number tbl
            foreach (CoffExportEntry exp in exportList)
            {
                expData.putTwo(exp.ord - ordinalBase);
            }

            uint faddr = expData.getPos() + mempos;
            expData.putString(filename);
            List<uint> nameaddrs = new List<uint>();
            foreach (CoffExportEntry exp in exportList)
            {
                nameaddrs.Add(expData.getPos() + mempos);
                expData.putString(exp.name);
            }

            expData.seek(0xc);
            expData.putFour(faddr);
            expData.seek(expnametbl);
            foreach(uint nameaddr in nameaddrs)
            {
                expData.putFour(nameaddr);
            }

            exportSec = new CoffSection(".edata");
            exportSec.data = new List<byte>(expData.getData());
            uint datasize = (uint)exportSec.data.Count;
            exportSec.filePos = filepos;
            exportSec.fileSize = (datasize + (fileAlignment - 1)) & ~(fileAlignment - 1);
            filepos += exportSec.fileSize;

            exportSec.memPos = mempos;
            exportSec.memSize = datasize;
            mempos += (datasize + (memAlignment - 1)) & ~(memAlignment - 1);

            exportSec.settings.canRead = true;
            exportSec.settings.hasInitData = true;

            uint msize = (exportSec.memSize + fileAlignment - 1) & ~(fileAlignment - 1);
            sizeOfInitializedData += msize;

            sections.Add(exportSec);
            dExportTable.rva = exportSec.memPos;
            dExportTable.size = exportSec.memSize;
        }

        public void buildRelocSection()
        {
            relocList.Sort();

            BinaryOut relData = new BinaryOut();
            uint basepage = relocList[0].addr & 0xFFFFF000;
            uint blocksize = 8;
            relData.putFour(basepage);
            uint blockstart = relData.getPos();
            relData.putFour(0);
            foreach (CoffRelocationEntry rel in relocList)
            {
                uint page = rel.addr & 0xFFFFF000;
                if (page != basepage)
                {
                    if (blocksize % 4 != 0)
                    {
                        relData.putTwo(0);
                        blocksize += 2;
                    }
                    uint blockend = relData.getPos();
                    relData.seek(blockstart);
                    relData.putFour(blocksize);
                    relData.seek(blockend);
                    basepage = page;
                    blocksize = 8;
                    relData.putFour(basepage);
                    blockstart = relData.getPos();
                    relData.putFour(0);
                }
                uint ofs = rel.addr % 0x1000;
                ofs += 0x3000;
                relData.putTwo(ofs);
                blocksize += 2;
            }
            if (blocksize % 4 != 0)
            {
                relData.putTwo(0);
                blocksize += 2;
            }
            relData.seek(blockstart);
            relData.putFour(blocksize);

            relocSec = new CoffSection(".reloc");
            relocSec.data = new List<byte>(relData.getData());
            uint datasize = (uint)relocSec.data.Count;
            relocSec.filePos = filepos;
            relocSec.fileSize = (datasize + (fileAlignment - 1)) & ~(fileAlignment - 1);
            filepos += relocSec.fileSize;

            relocSec.memPos = mempos;
            relocSec.memSize = datasize;
            mempos += (datasize + (memAlignment - 1)) & ~(memAlignment - 1);

            relocSec.settings.canRead = true;
            relocSec.settings.hasInitData = true;
            relocSec.settings.canDiscard = true;

            uint msize = (relocSec.memSize + fileAlignment - 1) & ~(fileAlignment - 1);
            sizeOfInitializedData += msize;

            sections.Add(relocSec);
            baseRelocationTable.rva = relocSec.memPos;
            baseRelocationTable.size = relocSec.memSize;
        }

        public void writeCoffHeader(BinaryOut outfile)
        {
            outfile.putFour(0x00004550);            //PE sig
            outfile.putTwo((uint)machine);
            outfile.putTwo((uint)sections.Count);
            outfile.putFour((uint)getTimestamp());
            outfile.putFour(0);                     //no symbol table
            outfile.putFour(0);
            outfile.putTwo(0xe0);                   //optional hdr size
            uint flagval = characteristics.encodeFlags();
            outfile.putTwo(flagval);
        }

        public void writeOptionalHeader(BinaryOut outfile)
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
            outfile.putFour(memAlignment);
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

        public void writeSectionTable(BinaryOut outfile)
        {
            for (int i = 0; i < sections.Count; i++)
            {
                sections[i].writeSectionTblEntry(outfile);
            }
        }

        public void writeSectionData(BinaryOut outfile)
        {
            for (int i = 0; i < sections.Count; i++)
            {
                sections[i].writeSectionData(outfile);
            }
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
            stub = new byte[] {0x0e,0x1f,0xba,0x0e,0x00,0xb4,0x09,0xcd,0x21,0xb8,0x01,0x4c,0xcd,0x21,
                               0x44,0x6f,0x6e,0x27,0x74,0x20,0x65,0x76,0x65,0x6e,0x20,0x74,0x68,0x69,0x6e,0x6b,0x20,
                               0x6f,0x66,0x20,0x72,0x75,0x6e,0x6e,0x69,0x6e,0x67,0x20,0x74,0x68,0x69,0x73,0x20,
                               0x69,0x6e,0x20,0x57,0x49,0x4e,0x20,0x6d,0x6f,0x64,0x65,0x0d,0x0a,0x24};
                            //"Don't even think of running this in WIN mode.\r\n$"
            headerSize = (uint)(0x40 + stub.Length);
        }

        static public MsDosHeader readMSDOSHeader(BinaryIn source)
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

        public void writeOut(BinaryOut outfile)
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

    //-------------------------------------------------------------------------

    public class Characteristics
    {
        public bool relocationsStripped;
        public bool isExecutable;
        public bool lineNumbersStripped;
        public bool symbolsStripped;
        public bool largeAddress;
        public bool is32BitMachine;
        public bool debugStripped;
        public bool removableRunFromSwap;
        public bool networkRunFromSwap;
        public bool isSystemFile;
        public bool isDLL;
        public bool runOnUniprocessor;


        internal static Characteristics decodeFlags(uint flags)
        {
            Characteristics characteristics = new Characteristics();

            characteristics.relocationsStripped = (flags & 0x1) != 0;
            characteristics.isExecutable = (flags & 0x2) != 0;
            characteristics.lineNumbersStripped = (flags & 0x4) != 0;
            characteristics.symbolsStripped = (flags & 0x8) != 0;
            characteristics.largeAddress = (flags & 0x10) != 0;
            characteristics.is32BitMachine = (flags & 0x100) != 0;
            characteristics.debugStripped = (flags & 0x200) != 0;
            characteristics.removableRunFromSwap = (flags & 0x400) != 0; 
            characteristics.networkRunFromSwap = (flags & 0x800) != 0;
            characteristics.isSystemFile = (flags & 0x1000) != 0;
            characteristics.isDLL = (flags & 0x2000) != 0;
            characteristics.runOnUniprocessor = (flags & 0x4000) != 0;

            return characteristics;
        }

        public uint encodeFlags()
        {
            uint flags = 0;
            if (relocationsStripped) { flags |= 0x1; }
            if (isExecutable) { flags |= 0x2; }
            if (lineNumbersStripped) { flags |= 0x4; }
            if (symbolsStripped) { flags |= 0x8; }
            if (largeAddress) { flags |= 0x10; }
            if (is32BitMachine) { flags |= 0x100; }
            if (debugStripped) { flags |= 0x200; }
            if (removableRunFromSwap) { flags |= 0x400; }
            if (networkRunFromSwap) { flags |= 0x800; }
            if (isSystemFile) { flags |= 0x1000; }
            if (isDLL) { flags |= 0x2000; }
            if (runOnUniprocessor) { flags |= 0x4000; }
            return flags;
        }

        public Characteristics()
        {
            relocationsStripped = false;
            isExecutable = false;
            lineNumbersStripped = false;
            symbolsStripped = false;
            largeAddress = false;
            is32BitMachine = false;
            debugStripped = false;
            removableRunFromSwap = false;
            networkRunFromSwap = false;
            isSystemFile = false;
            isDLL = false;
            runOnUniprocessor = false;
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

        static public DataDirectory readIn(BinaryIn source)
        {
            uint rva = source.getFour();
            uint size = source.getFour();
            return new DataDirectory(rva, size);
        }

        public void writeOut(BinaryOut outfile)
        {
            outfile.putFour(rva);
            outfile.putFour(size);
        }
    }

    //-------------------------------------------------------------------------

    public class CoffImportEntry
    {
        public CoffImportEntry ()
        {
            
        }
    }

    //-------------------------------------------------------------------------

    public class CoffExportEntry
    {
        public uint ord;
        public string name;
        public uint addr;

        public CoffExportEntry(uint _ord, string _name, uint _addr)
        {
            ord = _ord;
            name = _name;
            addr = _addr;
        }
    }

    //-------------------------------------------------------------------------

    public class CoffRelocationEntry : IComparable<CoffRelocationEntry>
    {
        public uint addr;

        public CoffRelocationEntry(uint _addr)
        {
            addr = _addr;
        }

        public int CompareTo(CoffRelocationEntry that)
        {
            return this.addr.CompareTo(that.addr);
        }

        public override string ToString()
        {
            return addr.ToString("X4");
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