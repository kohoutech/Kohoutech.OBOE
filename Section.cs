/* ----------------------------------------------------------------------------
Origami Win32 Library
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

//https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files#Section_Table
//https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers

namespace Origami.Win32
{
    public class Section
    {
        //section header fields
        public int secNum;
        public String name;

        public uint memPos;                 //section addr in memory
        public uint memSize;                //section size in memory
        public uint filePos;                //section addr in file
        public uint fileSize;               //section size in file

        public Flags flags;
        public Alignment dataAlignment;

        //flag fields
        [Flags]
        public enum Flags : uint
        {
            IMAGE_SCN_CNT_CODE = 0x00000020,  	            //The section contains executable code.
            IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040, 	//The section contains initialized data.
            IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080,  //The section contains uninitialized data.
            IMAGE_SCN_LNK_INFO = 0x00000200,  	            //The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
            IMAGE_SCN_LNK_REMOVE = 0x00000800,  	        //The section will not become part of the image. This is valid only for object files.
            IMAGE_SCN_LNK_COMDAT = 0x00001000,  	        //The section contains COMDAT data. For more information, see COMDAT Sections (Object Only). This is valid only for object files.
            IMAGE_SCN_GPREL = 0x00008000,  	                //The section contains data referenced through the global pointer (GP).

            IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000,         //The section contains extended relocations.
            IMAGE_SCN_MEM_DISCARDABLE = 0x02000000,         //The section can be discarded as needed.
            IMAGE_SCN_MEM_NOT_CACHED = 0x04000000,          //The section cannot be cached.
            IMAGE_SCN_MEM_NOT_PAGED = 0x08000000,           //The section is not pageable.
            IMAGE_SCN_MEM_SHARED = 0x10000000,              //The section can be shared in memory.
            IMAGE_SCN_MEM_EXECUTE = 0x20000000,             //The section can be executed as code.
            IMAGE_SCN_MEM_READ = 0x40000000,                //The section can be read.
            IMAGE_SCN_MEM_WRITE = 0x80000000                //The section can be written to. 
        }

        public const Flags TEXTFLAGS = Flags.IMAGE_SCN_CNT_CODE | Flags.IMAGE_SCN_MEM_EXECUTE | Flags.IMAGE_SCN_MEM_READ;
        public const Flags DATAFLAGS = Flags.IMAGE_SCN_CNT_INITIALIZED_DATA | Flags.IMAGE_SCN_MEM_READ | Flags.IMAGE_SCN_MEM_WRITE;
        public const Flags BSSFLAGS = Flags.IMAGE_SCN_CNT_UNINITIALIZED_DATA | Flags.IMAGE_SCN_MEM_READ | Flags.IMAGE_SCN_MEM_WRITE;

        //Align data on a nnn-byte boundary. Valid only for object files.
        public enum Alignment
        {
            IMAGE_SCN_ALIGN_1BYTES = 1,
            IMAGE_SCN_ALIGN_2BYTES,
            IMAGE_SCN_ALIGN_4BYTES,
            IMAGE_SCN_ALIGN_8BYTES,
            IMAGE_SCN_ALIGN_16BYTES,
            IMAGE_SCN_ALIGN_32BYTES,
            IMAGE_SCN_ALIGN_64BYTES,
            IMAGE_SCN_ALIGN_128BYTES,
            IMAGE_SCN_ALIGN_256BYTES,
            IMAGE_SCN_ALIGN_512BYTES,
            IMAGE_SCN_ALIGN_1024BYTES,
            IMAGE_SCN_ALIGN_2048BYTES,
            IMAGE_SCN_ALIGN_4096BYTES,
            IMAGE_SCN_ALIGN_8192BYTES
        }

        public List<CoffRelocation> relocations;
        public uint relocTblPos;

        public List<CoffLineNumber> linenumbers;                //line num data is deprecated

        public List<Byte> data;

        //new section cons
        public Section(String _name, Flags _flags, Alignment _alignment)
        {
            secNum = 0;
            name = _name;

            memSize = 0;
            memPos = 0;
            fileSize = 0;
            filePos = 0;

            flags = _flags;
            dataAlignment = _alignment;

            relocations = new List<CoffRelocation>();
            linenumbers = new List<CoffLineNumber>();

            data = new List<byte>();            
        }

        public Section(String name)
            : this(name, 0, Alignment.IMAGE_SCN_ALIGN_1BYTES)
        {
        }

        //- reading in ----------------------------------------------------------------

        public void resetData()
        {
            data.Clear();
        }

        public int addData(List<Byte> bytes)
        {
            int addr = data.Count;
            data.AddRange(bytes);
            return addr;
        }

        //- reading in ----------------------------------------------------------------

        //read in both section tbl entry & section data
        public static Section readSection(SourceFile source)
        {
            //if section name is stored in string tbl, we read in index & let caller deref the actual name
            String name = source.getAsciiString(8);
            Section section = new Section(name);

            section.memSize = source.getFour();
            section.memPos = source.getFour();
            section.fileSize = source.getFour();
            section.filePos = source.getFour();

            uint relocPos = source.getFour();
            uint lineNumPos = source.getFour();
            uint relocCount = source.getFour();
            uint lineNumCount = source.getFour();
            section.relocations = CoffRelocation.read(source, relocPos, relocCount);
            section.linenumbers = CoffLineNumber.read(source, lineNumPos, lineNumCount);

            //load flags & extract alignment value
            uint flagval = source.getFour();
            section.dataAlignment = (Alignment)((flagval >> 20) % 0x10);
            flagval &= ~((uint)0x00f00000);
            section.flags = (Flags)flagval;

            //load section data - read in all the bytes that will be loaded into mem (memsize)
            //and skip the remaining section bytes (filesize) to pad out the data to a file boundary
            section.data = new List<Byte>(source.getRange(section.filePos, section.memSize));

            return section;
        }

        //- writing out ---------------------------------------------------------------

        public void writeSectionTblEntry(OutputFile outfile)
        {
            outfile.putFixedString(name, 8);

            outfile.putFour(memSize);
            outfile.putFour(memPos);
            outfile.putFour(fileSize);
            outfile.putFour(filePos);

            //line numbers are deprecated, we don't write them
            outfile.putFour(relocTblPos);
            outfile.putFour(0);
            outfile.putTwo((uint)relocations.Count);
            outfile.putTwo(0);

            uint flagval = (uint)flags;
            flagval = flagval | ((uint)dataAlignment << 20);
            outfile.putFour(flagval);
        }

        public void writeSectionData(OutputFile outfile)
        {
            outfile.putRange(data.ToArray());

            //these get written directly after the section data
            CoffRelocation.write(outfile, relocTblPos);
            CoffLineNumber.write(outfile);
        }
    }

    //-----------------------------------------------------------------------------

    //relocation tbl entry
    public class CoffRelocation
    {
        public enum Reloctype
        {
            ABSOLUTE = 0x00,
            DIR32 = 0x06,
            DIR32NB = 0x07,
            SECTION = 0x0a,
            SECREL = 0x0b,
            TOKEN = 0x0c,
            SECREL7 = 0x0d,
            REL32 = 0x14
        }

        public uint address;
        public uint symTblIdx;
        public Reloctype type;

        public CoffRelocation(uint _addr, uint _idx, Reloctype _type)
        {
            address = _addr;
            symTblIdx = _idx;
            type = _type;
        }

        public void writeToFile(OutputFile outfile)
        {
            outfile.putFour(address);
            outfile.putFour(symTblIdx);
            outfile.putTwo((uint)type);
        }

        public static List<CoffRelocation> read(SourceFile source, uint pos, uint count)
        {
            return null;        //not implemented yet
        }

        public static void write(OutputFile outfile, uint pos)
        {
            //not implemented yet
        }
    }

    //line number tbl entry
    //Microsoft states that these are deprecated
    public class CoffLineNumber
    {
        public static List<CoffLineNumber> read(SourceFile source, uint pos, uint count)
        {
            return null;        //we don't read in line numbers
        }

        public static void write(OutputFile outfile)
        {
            //we don't write out line numbers
        }
    }
}
