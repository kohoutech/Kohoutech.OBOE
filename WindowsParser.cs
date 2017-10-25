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

        public void loadPEHeader()
        {
            uint pesig = source.getFour();
            Console.Out.WriteLine("PE sig = " + pesig);
            uint machine = source.getTwo();
            sectionCount = source.getTwo();
            uint timeStamp = source.getFour();
            uint pSymbolTable = source.getFour();
            uint symbolcount = source.getFour();
            uint optionalHeaderSize = source.getTwo();
            uint characteristics = source.getTwo();

            Console.Out.WriteLine("machine = " + machine);
            Console.Out.WriteLine("sectioncount = " + sectionCount);
            Console.Out.WriteLine("timestamp = " + timeStamp);
            Console.Out.WriteLine("symbol tbl ptr = " + pSymbolTable);
            Console.Out.WriteLine("symbol count = " + symbolcount);
            Console.Out.WriteLine("optional header size = " + optionalHeaderSize);
            Console.Out.WriteLine("characteristics = " + characteristics);
            
        }

        public void loadOptionalHeader()
        {
            uint signature = source.getTwo();
            uint MajorLinkerVersion = source.getOne();
            uint MinorLinkerVersion = source.getOne();
            uint SizeOfCode = source.getFour();
            uint SizeOfInitializedData = source.getFour();
            uint SizeOfUninitializedData = source.getFour();
            uint AddressOfEntryPoint = source.getFour();
            uint BaseOfCode = source.getFour();
            uint BaseOfData = source.getFour();
            imageBase = source.getFour();
            uint SectionAlignment = source.getFour();
            uint FileAlignment = source.getFour();
            uint MajorOSVersion = source.getTwo();
            uint MinorOSVersion = source.getTwo();
            uint MajorImageVersion = source.getTwo();
            uint MinorImageVersion = source.getTwo();
            uint MajorSubsystemVersion = source.getTwo();
            uint MinorSubsystemVersion = source.getTwo();
            uint Win32VersionValue = source.getFour();
            uint SizeOfImage = source.getFour();
            uint SizeOfHeaders = source.getFour();
            uint Checksum = source.getFour();
            uint Subsystem = source.getTwo();
            uint DLLCharacteristics = source.getTwo();
            uint SizeOfStackReserve = source.getFour();
            uint SizeOfStackCommit = source.getFour();
            uint SizeOfHeapReserve = source.getFour();
            uint SizeOfHeapCommit = source.getFour();
            uint LoaderFlags = source.getFour();
            uint NumberOfRvaAndSizes = source.getFour();

            Console.Out.WriteLine("signature = " + signature);
            Console.Out.WriteLine("MajorLinkerVersion = " + MajorLinkerVersion);
            Console.Out.WriteLine("MinorLinkerVersion = " + MinorLinkerVersion);
            Console.Out.WriteLine("SizeOfCode = " + SizeOfCode);
            Console.Out.WriteLine("SizeOfInitializedData = " + SizeOfInitializedData);
            Console.Out.WriteLine("SizeOfUninitializedData = " + SizeOfUninitializedData);
            Console.Out.WriteLine("AddressOfEntryPoint = " + AddressOfEntryPoint);
            Console.Out.WriteLine("BaseOfCode = " + BaseOfCode);
            Console.Out.WriteLine("BaseOfData = " + BaseOfData);
            Console.Out.WriteLine("ImageBase = " + imageBase.ToString("X"));
            Console.Out.WriteLine("SectionAlignment = " + SectionAlignment);
            Console.Out.WriteLine("FileAlignment = " + FileAlignment);
            Console.Out.WriteLine("MajorOSVersion = " + MajorOSVersion);
            Console.Out.WriteLine("MinorOSVersion = " + MinorOSVersion);
            Console.Out.WriteLine("MajorImageVersion = " + MajorImageVersion);
            Console.Out.WriteLine("MinorImageVersion = " + MinorImageVersion);
            Console.Out.WriteLine("MajorSubsystemVersion = " + MajorSubsystemVersion);
            Console.Out.WriteLine("MinorSubsystemVersion = " + MinorSubsystemVersion);
            Console.Out.WriteLine("Win32VersionValue = " + Win32VersionValue);
            Console.Out.WriteLine("SizeOfImage = " + SizeOfImage);
            Console.Out.WriteLine("SizeOfHeaders = " + SizeOfHeaders);
            Console.Out.WriteLine("Checksum = " + Checksum);
            Console.Out.WriteLine("Subsystem = " + Subsystem);
            Console.Out.WriteLine("DLLCharacteristics = " + DLLCharacteristics);
            Console.Out.WriteLine("SizeOfStackReserve = " + SizeOfStackReserve);
            Console.Out.WriteLine("SizeOfStackCommit = " + SizeOfStackCommit);
            Console.Out.WriteLine("SizeOfHeapReserve = " + SizeOfHeapReserve);
            Console.Out.WriteLine("SizeOfHeapCommit = " + SizeOfHeapCommit);
            Console.Out.WriteLine("LoaderFlags = " + LoaderFlags);
            Console.Out.WriteLine("NumberOfRvaAndSizes = " + NumberOfRvaAndSizes);

            uint[] dataDirectory = new uint[NumberOfRvaAndSizes * 2];
            for (int i = 0; i < NumberOfRvaAndSizes; i++)
            {
                dataDirectory[i * 2] = source.getFour();
                dataDirectory[(i * 2) + 1] = source.getFour();
            }
        }

        public void loadSectionTable()
        {
            sections = new Section[sectionCount];
            for (int i = 0; i < sectionCount; i++)
            {
                sections[i] = Section.getSection(fluoro, i + 1, imageBase);
            }
        }

//-----------------------------------------------------------------------------

        public void parse()
        {
            skipMSDOSHeader();
            loadPEHeader();
            loadOptionalHeader();
            loadSectionTable();
        }
    }
}
