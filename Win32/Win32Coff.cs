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

//Win32 COFF object file

//https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format

namespace Kohoutech.Win32
{
    public class Win32Coff
    {

        //coff header fields
        public MachineType machine;
        public uint timeStamp;
        public int characteristics;
        uint optionalHdrSize;

        public List<Section> sections;
        public Dictionary<String, Section> secNames;
        uint sectionCount;

        public List<CoffSymbol> symbolTbl;
        public Dictionary<String, CoffSymbol> symNames;
        uint symbolTblAddr;
        uint symbolCount;

        public Dictionary<int, String> stringTbl;
        public int strTblIdx;

        //cons
        public Win32Coff()
        {
            machine = MachineType.IMAGE_FILE_MACHINE_I386;
            timeStamp = 0;
            characteristics = 0;

            sections = new List<Section>();
            secNames = new Dictionary<string, Section>();

            symbolTbl = new List<CoffSymbol>();
            symNames = new Dictionary<string, CoffSymbol>();

            stringTbl = new Dictionary<int, string>();
            strTblIdx = 4;
        }

        //- reading in ----------------------------------------------------------------

        public void readCoffHeader(SourceFile source)
        {
            machine = (MachineType)source.getTwo();
            sectionCount = source.getTwo();
            timeStamp = source.getFour();
            symbolTblAddr = source.getFour();
            symbolCount = source.getFour();
            optionalHdrSize = source.getTwo();
            characteristics = (int)source.getTwo();         
        }

        public void readSections(SourceFile source)
        {
            for (int i = 0; i < sectionCount; i++)
            {
                Section section = Section.readSection(source);
                section.secNum = i + 1;
                sections.Add(section);
            }
        }

        public void loadSymbolTable(SourceFile source)
        {
            source.seek(symbolTblAddr);
            for (int i = 0; i < symbolCount; i++)
            {
                CoffSymbol sym = CoffSymbol.readSymbol(source);
                symbolTbl.Add(sym);
                symNames[sym.name] = sym;
            }
        }

        public void loadStringTable(SourceFile source)
        {
            uint pos = symbolTblAddr + (symbolCount * 0x12);
            source.seek(pos);
            uint len = source.getFour() - 4;
            if (len > 0)
            {
                byte[] data = source.getRange(len);
                String str = "";
                int idx = 4;
                for (int i = 0; i < len; i++)
                {
                    if (data[i] != 0)
                    {
                        str += (char)data[i];
                    }
                    else
                    {
                        stringTbl.Add(idx, str);        //end of str, add it to string tbl
                        str = "";                       
                        idx = i + 5;                    //index of next str
                    }
                }
            }
        }

        public static Win32Coff readFromFile(String filename)
        {
            Win32Coff objfile = new Win32Coff();

            SourceFile source = new SourceFile(filename);
            objfile.readCoffHeader(source);
            objfile.readSections(source);
            objfile.loadSymbolTable(source);
            objfile.loadStringTable(source);

            return objfile;
        }

        //- writing out ---------------------------------------------------------------

        public void writeCoffHeader(OutputFile outfile)
        {
            outfile.putTwo((uint)machine);
            outfile.putTwo((uint)sections.Count);
            outfile.putFour(timeStamp);
            outfile.putFour(symbolTblAddr);
            outfile.putFour((uint)symbolTbl.Count);
            outfile.putTwo((uint)0);                        //no line number entries
            outfile.putTwo((uint)characteristics);
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

        public void writeSymbolTable(OutputFile outfile)
        {
            for (int i = 0; i < symbolTbl.Count; i++)
            {
                symbolTbl[i].writeSymbol(outfile);
            }
        }

        public void writeStringTable(OutputFile outfile)
        {
            uint tblSize = 4;
            for (int i = 0; i < stringTbl.Count; i++)
            {
                tblSize += (uint)(stringTbl[i].Length + 1);
            }
            outfile.putFour(tblSize);
            for (int i = 0; i < stringTbl.Count; i++)
            {
                outfile.putString(stringTbl[i]);
            }
        }

        public void writeToFile(String filename)
        {
            //layout .obj file 
            uint filepos = 0x14;                               //coff hdr size

            //sections
            filepos += (uint)sections.Count * 0x28;            //add sec tbl size
            for (int i = 0; i < sections.Count; i++)           //add section data sizes
            {
                if (sections[i].data.Count > 0)
                {
                    sections[i].filePos = filepos;
                    sections[i].fileSize = (uint)(sections[i].data.Count);
                    filepos += sections[i].fileSize;
                    uint relocsize = (uint)(sections[i].relocations.Count * 0x0a);
                    sections[i].relocTblPos = filepos;
                    filepos += relocsize;
                }
            }

            symbolTblAddr = filepos;
            filepos += (uint)symbolTbl.Count * 0x12;           //add symbol tbl size
            filepos += 0x04;
            for (int i = 0; i < stringTbl.Count; i++)
            {
                filepos += (uint)(stringTbl[i].Length + 1);    //add string tbl size
            }

            //now we have the size of the .obj file, write it out to disk
            OutputFile outfile = new OutputFile(filename, filepos);
            writeCoffHeader(outfile);
            writeSectionTable(outfile);
            writeSectionData(outfile);
            writeSymbolTable(outfile);
            writeStringTable(outfile);

            outfile.writeOut();
        }

        //-----------------------------------------------------------------------------

        public Section findSection(String name)
        {
            Section sec = null;
            if (secNames.ContainsKey(name))
            {
                sec = secNames[name];
            }
            return sec;
        }

        public Section addSection(String name, Section.Flags flags, Section.Alignment align)
        {
            Section sec = new Section(name, flags, align);
            sections.Add(sec);
            sec.secNum = sections.Count;
            secNames[name] = sec;
            return sec;
        }

        public CoffSymbol findSymbol(String name)
        {
            CoffSymbol sym = null;
            if (symNames.ContainsKey(name))
            {
                sym = symNames[name];
            }
            return sym;
        }

        public CoffSymbol addSymbol(String name, uint val, int num, uint type, CoffStorageClass storage, uint aux)
        {
            int namepos = -1;
            if (name.Length > 8)
            {
                namepos = addString(name);
                name = "";
            }
            CoffSymbol sym = new CoffSymbol(name, namepos, val, num, type, storage, aux);
            symbolTbl.Add(sym);
            symNames[name] = sym;
            return sym;
        }

        public String findString(int idx)
        {
            String s = null;
            if (stringTbl.ContainsKey(idx))
            {
                s = stringTbl[idx];
            }
            return s;
        }

        public int addString(string str)
        {
            int strpos = strTblIdx;
            stringTbl[strTblIdx] = str;
            strTblIdx += (str.Length + 1);
            return strpos;
        }
    }

    //- obj sym table ------------------------------------------------------------

    public class CoffSymbol
    {
        public String name;        //the symbol name string if 8 chars or less
        public int namePos;        //or its pos in the string tbl (-1 otherwise)
        public uint value;
        public int sectionNum;
        public uint type;
        public CoffStorageClass storageClass;
        public uint auxSymbolCount;

        public CoffSymbol(String _name, int _namePos, uint _val, int _secnum, uint _type, CoffStorageClass _storage, uint _aux)
        {
            name = _name;
            namePos = _namePos;
            value = _val;
            sectionNum = _secnum;
            type = _type;
            storageClass = _storage;
            auxSymbolCount = _aux;
        }

        public static CoffSymbol readSymbol(SourceFile source)
        {
            //get short name or pos in string tbl
            uint nameloc = source.getPos();
            uint namezeros = source.getFour();
            int namepos = -1;
            String name = "";
            if (namezeros == 0)
            {
                namepos = (int)source.getFour();
            }
            else
            {
                source.seek(nameloc);
                name = source.getAsciiString(8);
            }

            uint val = source.getFour();
            uint secval = source.getTwo();
            int secnum = (secval < 0x8000) ? (int)secval : ((int)secval - 0x10000);
            uint type = source.getTwo();
            CoffStorageClass stoarge = (CoffStorageClass)source.getOne();
            uint aux = source.getOne();

            CoffSymbol sym = new CoffSymbol(name, namepos, val, secnum, type, stoarge, aux);
            return sym;
        }

        public void writeSymbol(OutputFile outfile)
        {
            if (namePos == -1)
            {
                outfile.putFixedString(name, 8);
            }
            else
            {
                outfile.putFour(0);
                outfile.putFour((uint)namePos);
            }
            outfile.putFour(value);
            uint sn = (uint)((sectionNum < 0) ? 0x10000 + sectionNum : sectionNum);
            outfile.putTwo(sn);
            outfile.putTwo(type);
            outfile.putOne((uint)storageClass);
            outfile.putOne(auxSymbolCount);
        }
    }

    //- error handling --------------------------------------------------------

    public class Win32ReadException : Exception
    {
        public Win32ReadException(string message)
            : base(message)
        {
        }
    }

    //-------------------------------------------------------------------------

    public enum MachineType
    {
        IMAGE_FILE_MACHINE_I386 = 0x14c,
        IMAGE_FILE_MACHINE_IA64 = 0x0200,
        IMAGE_FILE_MACHINE_AMD64 = 0x8664
    }

    //there are others, but these are the only ones Microsoft uses currently
    public enum CoffStorageClass
    {
        IMAGE_SYM_CLASS_EXTERNAL = 2,
        IMAGE_SYM_CLASS_STATIC = 3,
        IMAGE_SYM_CLASS_FUNCTION = 101,
        IMAGE_SYM_CLASS_FILE = 103
    }
}
