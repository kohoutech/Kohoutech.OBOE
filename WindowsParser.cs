/* ----------------------------------------------------------------------------
Origami Windows Library
Copyright (C) 1998-2017  George E Greaney

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

//https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files

namespace Origami.Windows
{
    class WindowsParser
    {
        WinDecoder decoder;
        SourceFile source;

        uint imageBase;
        uint sectionCount;
        public Section[] sections;

        public WindowsParser(WinDecoder _decoder)
        {
            decoder = _decoder;
            source = decoder.source;
        }

//-----------------------------------------------------------------------------

        public void skipMSDOSHeader()
        {
            uint e_magic = source.getFour();
            source.seek(0x3c);
            uint e_lfanew = source.getFour();
            Console.Out.WriteLine("PE offset = " + e_lfanew);
            source.seek(e_lfanew);
            
        }


        public void loadSectionTable()
        {
            sections = new Section[sectionCount];
            for (int i = 0; i < sectionCount; i++)
            {
                sections[i] = Section.getSection(source, i + 1, imageBase);
            }
        }

//-----------------------------------------------------------------------------

        public void parse()
        {
            skipMSDOSHeader();
            decoder.peHeader = PEHeader.load(source);
            decoder.optionalHeader = OptionalHeader.load(source);
            loadSectionTable();
        }
    }

    class PEHeader
    {
        uint pesig;
        uint machine;
        uint sectionCount;
        uint timeStamp;
        uint pSymbolTable;
        uint symbolcount;
        uint optionalHeaderSize;
        uint characteristics;

        static public PEHeader load(SourceFile source)
        {
            PEHeader header = new PEHeader();

            header.pesig = source.getFour();
            header.machine = source.getTwo();
            header.sectionCount = source.getTwo();
            header.timeStamp = source.getFour();
            header.pSymbolTable = source.getFour();
            header.symbolcount = source.getFour();
            header.optionalHeaderSize = source.getTwo();
            header.characteristics = source.getTwo();

            return header;
        }

            //Console.Out.WriteLine("machine = " + machine);
            //Console.Out.WriteLine("sectioncount = " + sectionCount);
            //Console.Out.WriteLine("timestamp = " + timeStamp);
            //Console.Out.WriteLine("symbol tbl ptr = " + pSymbolTable);
            //Console.Out.WriteLine("symbol count = " + symbolcount);
            //Console.Out.WriteLine("optional header size = " + optionalHeaderSize);
            //Console.Out.WriteLine("characteristics = " + characteristics);
    }

    class OptionalHeader
    {
        uint signature;
        uint MajorLinkerVersion;
        uint MinorLinkerVersion;
        uint SizeOfCode;
        uint SizeOfInitializedData;
        uint SizeOfUninitializedData;
        uint AddressOfEntryPoint;
        uint BaseOfCode;
        uint BaseOfData;
        uint imageBase;
        uint SectionAlignment;
        uint FileAlignment;
        uint MajorOSVersion;
        uint MinorOSVersion;
        uint MajorImageVersion;
        uint MinorImageVersion;
        uint MajorSubsystemVersion;
        uint MinorSubsystemVersion;
        uint Win32VersionValue;
        uint SizeOfImage;
        uint SizeOfHeaders;
        uint Checksum;
        uint Subsystem;
        uint DLLCharacteristics;
        uint SizeOfStackReserve;
        uint SizeOfStackCommit;
        uint SizeOfHeapReserve;
        uint SizeOfHeapCommit;
        uint LoaderFlags;
        uint NumberOfRvaAndSizes;

        uint[] dataDirectory;

        static public OptionalHeader load(SourceFile source)
        {
            OptionalHeader header = new OptionalHeader();
            header.signature = source.getTwo();
            header.MajorLinkerVersion = source.getOne();
            header.MinorLinkerVersion = source.getOne();
            header.SizeOfCode = source.getFour();
            header.SizeOfInitializedData = source.getFour();
            header.SizeOfUninitializedData = source.getFour();
            header.AddressOfEntryPoint = source.getFour();
            header.BaseOfCode = source.getFour();
            header.BaseOfData = source.getFour();
            header.imageBase = source.getFour();
            header.SectionAlignment = source.getFour();
            header.FileAlignment = source.getFour();
            header.MajorOSVersion = source.getTwo();
            header.MinorOSVersion = source.getTwo();
            header.MajorImageVersion = source.getTwo();
            header.MinorImageVersion = source.getTwo();
            header.MajorSubsystemVersion = source.getTwo();
            header.MinorSubsystemVersion = source.getTwo();
            header.Win32VersionValue = source.getFour();
            header.SizeOfImage = source.getFour();
            header.SizeOfHeaders = source.getFour();
            header.Checksum = source.getFour();
            header.Subsystem = source.getTwo();
            header.DLLCharacteristics = source.getTwo();
            header.SizeOfStackReserve = source.getFour();
            header.SizeOfStackCommit = source.getFour();
            header.SizeOfHeapReserve = source.getFour();
            header.SizeOfHeapCommit = source.getFour();
            header.LoaderFlags = source.getFour();
            header.NumberOfRvaAndSizes = source.getFour();

            header.dataDirectory = new uint[header.NumberOfRvaAndSizes * 2];
            for (int i = 0; i < header.NumberOfRvaAndSizes; i++)
            {
                header.dataDirectory[i * 2] = source.getFour();
                header.dataDirectory[(i * 2) + 1] = source.getFour();
            }

            return header;
        }

        //Console.Out.WriteLine("signature = " + signature);
        //Console.Out.WriteLine("MajorLinkerVersion = " + MajorLinkerVersion);
        //Console.Out.WriteLine("MinorLinkerVersion = " + MinorLinkerVersion);
        //Console.Out.WriteLine("SizeOfCode = " + SizeOfCode);
        //Console.Out.WriteLine("SizeOfInitializedData = " + SizeOfInitializedData);
        //Console.Out.WriteLine("SizeOfUninitializedData = " + SizeOfUninitializedData);
        //Console.Out.WriteLine("AddressOfEntryPoint = " + AddressOfEntryPoint);
        //Console.Out.WriteLine("BaseOfCode = " + BaseOfCode);
        //Console.Out.WriteLine("BaseOfData = " + BaseOfData);
        //Console.Out.WriteLine("ImageBase = " + imageBase.ToString("X"));
        //Console.Out.WriteLine("SectionAlignment = " + SectionAlignment);
        //Console.Out.WriteLine("FileAlignment = " + FileAlignment);
        //Console.Out.WriteLine("MajorOSVersion = " + MajorOSVersion);
        //Console.Out.WriteLine("MinorOSVersion = " + MinorOSVersion);
        //Console.Out.WriteLine("MajorImageVersion = " + MajorImageVersion);
        //Console.Out.WriteLine("MinorImageVersion = " + MinorImageVersion);
        //Console.Out.WriteLine("MajorSubsystemVersion = " + MajorSubsystemVersion);
        //Console.Out.WriteLine("MinorSubsystemVersion = " + MinorSubsystemVersion);
        //Console.Out.WriteLine("Win32VersionValue = " + Win32VersionValue);
        //Console.Out.WriteLine("SizeOfImage = " + SizeOfImage);
        //Console.Out.WriteLine("SizeOfHeaders = " + SizeOfHeaders);
        //Console.Out.WriteLine("Checksum = " + Checksum);
        //Console.Out.WriteLine("Subsystem = " + Subsystem);
        //Console.Out.WriteLine("DLLCharacteristics = " + DLLCharacteristics);
        //Console.Out.WriteLine("SizeOfStackReserve = " + SizeOfStackReserve);
        //Console.Out.WriteLine("SizeOfStackCommit = " + SizeOfStackCommit);
        //Console.Out.WriteLine("SizeOfHeapReserve = " + SizeOfHeapReserve);
        //Console.Out.WriteLine("SizeOfHeapCommit = " + SizeOfHeapCommit);
        //Console.Out.WriteLine("LoaderFlags = " + LoaderFlags);
        //Console.Out.WriteLine("NumberOfRvaAndSizes = " + NumberOfRvaAndSizes);
    }
}
