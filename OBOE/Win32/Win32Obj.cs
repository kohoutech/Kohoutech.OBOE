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

//Win32 COFF object file

//https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format

namespace Kohoutech.OBOE
{
    //base class for both object and executable files
    //this exists so coff sections can point to owner for both obj / exe files
    //in time, common fields _may_ be moved here
    public class Win32Coff
    {
    }

    //-------------------------------------------------------------------------

    public class Win32Obj : Win32Coff
    {
        public const int COFFHDRSIZE = 0x14;

        public String filename;

        //coff header fields
        public MachineType machine;
        public uint timeStamp;
        public int characteristics;

        public List<CoffSection> sections;
        public Dictionary<String, CoffSection> secNames;

        public List<CoffSymbol> symbols;
        public Dictionary<String, CoffSymbol> symNames;

        //cons
        public Win32Obj(String _filename)
        {
            filename = _filename;
            machine = MachineType.IMAGE_FILE_MACHINE_I386;
            timeStamp = 0;
            characteristics = 0;

            sections = new List<CoffSection>();
            secNames = new Dictionary<string, CoffSection>();

            symbols = new List<CoffSymbol>();
            symNames = new Dictionary<string, CoffSymbol>();
        }

        //- reading in ----------------------------------------------------------------

        static String readString(byte[] strtbl, int idx)
        {
            StringBuilder result = new StringBuilder();
            while (idx < strtbl.Length && strtbl[idx] != 0)
            {
                result.Append((char)strtbl[idx++]);
            }
            return result.ToString();
        }

        public static void loadSymbols(BinaryIn source, uint count, byte[] strtbl, Win32Obj objfile)
        {
            for (int i = 0; i < count;)
            {
                //get short name or pos in string tbl
                uint nameloc = source.getPos();
                uint namezeros = source.getFour();
                String name = "";
                if (namezeros == 0)         //if first 4 bytes = 0, 2nd 4 bytes = ofs into str tbl
                {
                    int namepos = (int)source.getFour();
                    name = readString(strtbl, namepos);
                }
                else
                {
                    source.seek(nameloc);
                    name = source.getAsciiString(8);
                }

                //read rest of sym entry
                uint val = source.getFour();
                uint secval = source.getTwo();
                uint type = source.getTwo();
                CoffStorageClass storage = (CoffStorageClass)source.getOne();
                uint aux = source.getOne();

                CoffSymbol sym = null;
                CoffSymbol.SYMBIND bind = CoffSymbol.SYMBIND.EXTERNAL;
                uint size = 0;
                uint addr = 0;
                CoffSection sec = null;

                switch (storage)
                {
                    case CoffStorageClass.IMAGE_SYM_CLASS_EXTERNAL:
                        if (secval == 0)
                        {
                            if (val == 0)
                            {
                                bind = CoffSymbol.SYMBIND.EXTERNAL;
                            }
                            else
                            {
                                bind = CoffSymbol.SYMBIND.COMMON;
                                size = val;
                            }
                        }
                        else
                        {
                            bind = CoffSymbol.SYMBIND.GLOBAL;
                            sec = objfile.sections[(int)secval - 1];
                            if (val >= sec.memPos)
                            {
                                addr = val - sec.memPos;
                            }
                        }
                        sym = new CoffSymbol(name);
                        sym.bind = bind;
                        sym.typ = CoffSymbol.SYMTYPE.FUNCTION;
                        sym.section = sec;
                        sym.ofs = addr;
                        sym.size = size;
                        break;

                    case CoffStorageClass.IMAGE_SYM_CLASS_STATIC:
                    case CoffStorageClass.IMAGE_SYM_CLASS_LABEL:
                        if (secval != 0xffff)
                        {
                            sec = objfile.sections[(int)secval - 1];
                            if (val >= sec.memPos)
                            {
                                addr = val - sec.memPos;
                            }
                            sym = new CoffSymbol(name);
                            sym.bind = CoffSymbol.SYMBIND.LOCAL;
                            sym.typ = CoffSymbol.SYMTYPE.FUNCTION;
                            sym.section = sec;
                            sym.ofs = addr;
                            sym.size = size;
                        }
                        break;

                    case CoffStorageClass.IMAGE_SYM_CLASS_SECTION:
                        sec = objfile.sections[(int)secval - 1];
                        sym = new CoffSymbol(name);
                        sym.bind = CoffSymbol.SYMBIND.LOCAL;
                        sym.typ = CoffSymbol.SYMTYPE.FUNCTION;
                        sym.section = sec;
                        sym.ofs = addr;
                        sym.size = size;
                        break;

                    case CoffStorageClass.IMAGE_SYM_CLASS_FUNCTION:
                    case CoffStorageClass.IMAGE_SYM_CLASS_FILE:
                        break;

                    default:
                        break;
                }
                i++;

                objfile.symbols.Add(sym);
                if (sym != null)
                {
                    objfile.symNames[sym.name] = sym;
                }

                //skip any aux sym entries
                for (int j = 0; j < aux; j++)
                {
                    source.skip(CoffSymbol.SYMTBLENTRYSIZE);
                    objfile.symbols.Add(null);
                    i++;
                }
            }
        }

        public static void loadRelocations(BinaryIn source, CoffSection sec, Win32Obj objfile)
        {            
            source.seek(sec.relocTblPos);
            for (int i = 0; i < sec.relocTblCount; i++)
            {
                uint addr = source.getFour();
                int symidx = (int)source.getFour();
                uint reloctype = source.getTwo();

                CoffRelocation.Reloctype reltype = CoffRelocation.Reloctype.NONE;
                switch(reloctype)
                {
                    case 06:
                        reltype = CoffRelocation.Reloctype.ABSOLUTE;        //IMAGE_REL_I386_DIR32
                        break;

                    case 07:
                        reltype = CoffRelocation.Reloctype.RVA;             //IMAGE_REL_I386_DIR32NB
                        break;

                    case 11:
                        reltype = CoffRelocation.Reloctype.SECREL32;        //IMAGE_REL_I386_SECREL
                        break;

                    case 20:
                        reltype = CoffRelocation.Reloctype.RELATIVE;        //IMAGE_REL_I386_REL32
                        break;

                    default:
                        break;

                }

                CoffSymbol sym = objfile.symbols[symidx];
                CoffRelocation reloc = new CoffRelocation(addr - sec.memPos, sym, reltype);
                sec.relocations.Add(reloc);
            }            
        }

        public static Win32Obj readFromFile(String filename)
        {
            Win32Obj objfile = new Win32Obj(filename);
            BinaryIn source = new BinaryIn(filename);

            //coff header
            objfile.machine = (MachineType)source.getTwo();
            uint sectionCount = source.getTwo();
            objfile.timeStamp = source.getFour();
            uint symbolTblAddr = source.getFour();
            uint symbolCount = source.getFour();
            uint optionalHdrSize = source.getTwo();
            objfile.characteristics = (int)source.getTwo();

            //string tbl - follows symbol tbl
            uint strtblpos = symbolTblAddr + symbolCount * CoffSymbol.SYMTBLENTRYSIZE;
            source.seek(strtblpos);
            byte[] strtbl = null;
            uint len = source.getFour();
            if (len > 4)
            {
                source.seek(strtblpos);
                strtbl = source.getRange(len);
            }

            //section tbl
            source.seek(COFFHDRSIZE);
            for (int i = 0; i < sectionCount; i++)
            {
                //if section name is stored in string tbl, we read in index & let caller deref the actual name
                String secname = source.getAsciiString(8);
                if (secname[0] == '/')
                {
                    int stridx = Int32.Parse(secname.Substring(1));
                    secname = readString(strtbl, stridx);
                }

                //read section hdr field
                uint memSize = source.getFour();        //don't use - 0 in object files
                uint memPos = source.getFour();
                uint fileSize = source.getFour();
                uint filePos = source.getFour();

                uint relocPos = source.getFour();
                uint lineNumPos = source.getFour();     //don't use - deprecated
                uint relocCount = source.getTwo();
                uint lineNumCount = source.getTwo();    //don't use
                uint flagval = source.getFour();

                SectionSettings settings = SectionSettings.decodeFlags(flagval);
                CoffSection section = new CoffSection(secname, settings);
                section.owner = objfile;
                section.secNum = i + 1;
                section.memPos = memPos;
                section.fileSize = fileSize;
                section.filePos = filePos;
                section.relocTblPos = relocPos;
                section.relocTblCount = relocCount;

                objfile.sections.Add(section);
                objfile.secNames[section.name] = section;
            }

            //load symbols
            source.seek(symbolTblAddr);
            loadSymbols(source, symbolCount, strtbl, objfile);

            foreach (CoffSection section in objfile.sections)
            {
                //load section data
                section.data = new List<Byte>(source.getRange(section.filePos, section.fileSize));

                //load sectionrelocs
                loadRelocations(source, section, objfile);
            }

            
            return objfile;
        }

        //- writing out ---------------------------------------------------------------

        public void writeCoffHeader(BinaryOut outfile)
        {
            //outfile.putTwo((uint)machine);
            //outfile.putTwo((uint)sections.Count);
            //outfile.putFour(timeStamp);
            //outfile.putFour(symbolTblAddr);
            //outfile.putFour((uint)symbols.Count);
            //outfile.putTwo((uint)0);                        //no line number entries
            //outfile.putTwo((uint)characteristics);
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

        public void writeSymbolTable(BinaryOut outfile)
        {
            for (int i = 0; i < symbols.Count; i++)
            {
                symbols[i].writeSymbol(outfile);
            }
        }

        public void writeStringTable(BinaryOut outfile)
        {
            //uint tblSize = 4;
            //for (int i = 0; i < stringTbl.Count; i++)
            //{
            //    tblSize += (uint)(stringTbl[i].Length + 1);
            //}
            //outfile.putFour(tblSize);
            //for (int i = 0; i < stringTbl.Count; i++)
            //{
            //    outfile.putString(stringTbl[i]);
            //}
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

            //symbolTblAddr = filepos;
            //filepos += (uint)symbols.Count * 0x12;           //add symbol tbl size
            //filepos += 0x04;
            //for (int i = 0; i < stringTbl.Count; i++)
            //{
            //    filepos += (uint)(stringTbl[i].Length + 1);    //add string tbl size
            //}

            //now we have the size of the .obj file, write it out to disk
            BinaryOut outfile = new BinaryOut(filename, filepos);
            writeCoffHeader(outfile);
            writeSectionTable(outfile);
            writeSectionData(outfile);
            writeSymbolTable(outfile);
            writeStringTable(outfile);

            outfile.writeOut();
        }

        //-----------------------------------------------------------------------------

        public CoffSection findSection(String name)
        {
            CoffSection sec = null;
            if (secNames.ContainsKey(name))
            {
                sec = secNames[name];
            }
            return sec;
        }

        //public Section addSection(String name, Section.Flags flags, Section.Alignment align)
        //{
        //    Section sec = new Section(name, flags, align);
        //    sections.Add(sec);
        //    sec.secNum = sections.Count;
        //    secNames[name] = sec;
        //    return sec;
        //}

        public CoffSymbol findSymbol(String name)
        {
            CoffSymbol sym = null;
            if (symNames.ContainsKey(name))
            {
                sym = symNames[name];
            }
            return sym;
        }

        //public CoffSymbol addSymbol(String name, uint val, int num, uint type, CoffStorageClass storage, uint aux)
        //{
        //    int namepos = -1;
        //    if (name.Length > 8)
        //    {
        //        namepos = addString(name);
        //        name = "";
        //    }
        //    CoffSymbol sym = new CoffSymbol(name, val, num, type, storage, aux);
        //    symbols.Add(sym);
        //    symNames[name] = sym;
        //    return sym;
        //}

        public String findString(int idx)
        {
            //String s = null;
            //if (stringTbl.ContainsKey(idx))
            //{
            //    s = stringTbl[idx];
            //}
            //return s;
            return "";
        }

        public int addString(string str)
        {
            //int strpos = strTblIdx;
            //stringTbl[strTblIdx] = str;
            //strTblIdx += (str.Length + 1);
            //return strpos;
            return 0;
        }

        public override string ToString()
        {
            return filename;
        }
    }

    //- obj file constants ----------------------------------------------------

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
        IMAGE_SYM_CLASS_LABEL = 6,
        IMAGE_SYM_CLASS_FUNCTION = 101,
        IMAGE_SYM_CLASS_FILE = 103,
        IMAGE_SYM_CLASS_SECTION = 104
    }

    //- obj symbols -----------------------------------------------------------

    public class CoffSymbol
    {
        public const int SYMTBLENTRYSIZE = 0x12;

        public enum SYMBIND {NONE, EXTERNAL, COMMON, LOCAL, GLOBAL, WEAK_EXTERNAL, IMPORT };

        public enum SYMTYPE { NONE, FUNCTION, DATA, SECTION, LABEL, ADDR};

        public String name;
        public SYMBIND bind;
        public SYMTYPE typ;
        public CoffSection section;
        public uint ofs;
        public uint size;

        public CoffSymbol(String _name)
        {
            name = _name;
            bind = SYMBIND.NONE;
            typ = SYMTYPE.NONE;
            section = null;
            ofs = 0;
            size = 0;
        }

        public void writeSymbol(BinaryOut outfile)
        {
            //if (namePos == -1)
            //{
            //    outfile.putFixedString(name, 8);
            //}
            //else
            //{
            //    outfile.putFour(0);
            //    outfile.putFour((uint)namePos);
            //}
            //outfile.putFour(value);
            //uint sn = (uint)((sectionNum < 0) ? 0x10000 + sectionNum : sectionNum);
            //outfile.putTwo(sn);
            //outfile.putTwo(type);
            //outfile.putOne((uint)storageClass);
            //outfile.putOne(auxSymbolCount);
        }

        public override string ToString()
        {
            string secnum = (section != null) ? "SEC[" + section.secNum.ToString() + "]" : "UNDEF";
            return name + " : " + bind.ToString() + " : " + typ.ToString() + " : " + secnum + " : " + ofs.ToString() + " : " + size.ToString();
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
}
