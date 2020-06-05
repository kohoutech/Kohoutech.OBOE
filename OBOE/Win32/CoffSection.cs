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

//https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files#Section_Table
//https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers

namespace Kohoutech.OBOE
{
    public class CoffSection
    {
        //section header fields
        public  Win32Coff owner;
        public int secNum;
        public String name;

        SectionSettings settings;

        public uint memPos;                 //section addr in memory
        public uint memSize;                //section size in memory
        public uint filePos;                //section addr in file
        public uint fileSize;               //section size in file

        public List<Byte> data;

        public List<CoffRelocation> relocations;
        public uint relocTblPos;
        public uint relocTblCount;

        //new section cons
        public CoffSection(String _name)
        {
            secNum = 0;
            name = _name;

            memSize = 0;
            memPos = 0;
            fileSize = 0;
            filePos = 0;

            settings = new SectionSettings();

            relocations = new List<CoffRelocation>();

            data = new List<byte>();

            relocTblPos = 0;
            relocTblCount = 0;
        }

        public CoffSection(String _name, SectionSettings _settings)
            : this(_name)
        {
            settings = _settings;
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

            //uint flagval = (uint)flags;
            //flagval = flagval | ((uint)dataAlignment << 20);
            //outfile.putFour(flagval);
        }

        public void writeSectionData(OutputFile outfile)
        {
            uint pos = outfile.getPos();
            outfile.putRange(data.ToArray());

            //these get written directly after the section data
            CoffRelocation.write(outfile, relocTblPos);
            uint padding = fileSize - (outfile.getPos() - pos);
            outfile.putZeros(padding);
        }

        public override string ToString()
        {
            return name;
        }
    }

    //-----------------------------------------------------------------------------

    public class SectionSettings
    {
        static int[] DATAALIGNMENTS = { 0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192 };

        public bool hasCode;
        public bool hasInitData;
        public bool hasUninitData;
        public bool hasInfo;
        public bool willRemove;
        public bool hasComdat;
        public bool hasGPRel;
        public bool hasExtRelocs;
        public bool canDiscard;
        public bool dontCache;
        public bool notPageable;
        public bool canShare;
        public bool canExecute;
        public bool canRead;
        public bool canWrite;

        public int dataAlignment;

        internal static SectionSettings decodeFlags(uint flags)
        {
            SectionSettings settings = new SectionSettings();

            settings.hasCode = (flags & 0x20) != 0;
            settings.hasInitData = (flags & 0x40) != 0;
            settings.hasUninitData = (flags & 0x80) != 0;
            settings.hasInfo = (flags & 0x200) != 0;
            settings.willRemove = (flags & 0x800) != 0;
            settings.hasComdat = (flags & 0x1000) != 0;
            settings.hasGPRel = (flags & 0x8000) != 0;
            settings.hasExtRelocs = (flags & 0x01000000) != 0;
            settings.canDiscard = (flags & 0x02000000) != 0;
            settings.dontCache = (flags & 0x04000000) != 0; 
            settings.notPageable = (flags & 0x08000000) != 0;
            settings.canShare = (flags & 0x10000000) != 0;
            settings.canExecute = (flags & 0x20000000) != 0;
            settings.canRead = (flags & 0x40000000) != 0;
            settings.canWrite = (flags & 0x80000000) != 0;

            settings.dataAlignment = DATAALIGNMENTS[(flags & 0x00F00000) >> 20];

            return settings;
        }

        public SectionSettings()
        {
            hasCode = false;
            hasInitData = false;
            hasUninitData = false;
            hasInfo = false;
            willRemove = false;
            hasComdat = false;
            hasGPRel = false;
            hasExtRelocs = false;
            canDiscard = false;
            dontCache = false;
            notPageable = false;
            canShare = false;
            canExecute = false;
            canRead = false;
            canWrite = false;
            dataAlignment = 1;
        }
    }

    //-----------------------------------------------------------------------------

    //relocation tbl entry
    public class CoffRelocation
    {
        public enum Reloctype
        {
            NONE,
            ABSOLUTE,
            RELATIVE,
            RVA,
            SECREL32
        }

        public uint address;
        public CoffSymbol symbol;
        public Reloctype type;

        public CoffRelocation(uint _addr, CoffSymbol _sym, Reloctype _type)
        {
            address = _addr;
            symbol = _sym;
            type = _type;
        }

        //public void writeToFile(OutputFile outfile)
        //{
        //    outfile.putFour(address);
        //    outfile.putFour(symTblIdx);
        //    outfile.putTwo((uint)type);
        //}

        public static void write(OutputFile outfile, uint pos)
        {
            //not implemented yet
        }

        public override string ToString()
        {
            return address.ToString() + " : " + type.ToString() + " : " + symbol.name;
        }
    }

}
