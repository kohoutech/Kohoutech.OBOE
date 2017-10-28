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
using System.Text.RegularExpressions;
using System.IO;

namespace Origami.Win32
{
    
    class CodeSection : Section
    {
        const int BYTESFIELDWIDTH = 6;
        i32Disasm disasm;
        List<String> codeList;

        public CodeSection(SourceFile source, int _secnum, String _sectionName, uint _memsize,
                uint _memloc, uint _filesize, uint _fileloc, uint _pRelocations, uint _pLinenums,
            int _relocCount, int _linenumCount, uint _flags, uint _imageBase)
            : base(source, _secnum, _sectionName, _memsize, _memloc, _filesize, _fileloc, _pRelocations, _pLinenums,
            _relocCount, _linenumCount, _flags, _imageBase)
        {
            Console.Out.WriteLine("[" + _secnum + "] is a code section");
        }

//-----------------------------------------------------------------------------

        public void disasmCode()
        {
            
            uint srcpos = 0;
            disasm = new i32Disasm(sourceBuf, srcpos);
            codeList = new List<String>();

            uint instrlen = 0;
            uint codeaddr = imageBase + memloc;         //starting pos of code in mem, used for instr addrs

            while (srcpos < sourceBuf.Length)       
            {
                disasm.getInstr(codeaddr);
                instrlen = disasm.instrLen;

                StringBuilder asmLine = new StringBuilder();
                asmLine.Append("  " + codeaddr.ToString("X") + ": ");   //address

                for (int i = 0; i < BYTESFIELDWIDTH; i++)
                {
                    if (i < instrlen)
                    {
                        asmLine.Append(disasm.instrBytes[i].ToString("X2") + " ");   //bytes
                    }
                    else
                    {
                        asmLine.Append("   ");   //bytes
                    }
                }

                asmLine.Append(" ");
                String spacer = "            ".Substring(0, 12 - disasm.opcode.Length);
                if (disasm.opcount == 0)
                {
                    asmLine.Append(disasm.opcode);
                }
                else if (disasm.opcount == 1)
                {
                    asmLine.Append(disasm.opcode + spacer + disasm.op1);
                }
                else if (disasm.opcount == 2)
                {
                    asmLine.Append(disasm.opcode + spacer + disasm.op1 + "," + disasm.op2);
                }
                else if (disasm.opcount == 3)
                {
                    asmLine.Append(disasm.opcode + spacer + disasm.op1 + "," + disasm.op2 + "," + disasm.op3);
                }

                asmLine.AppendLine();

                if (instrlen > 6)
                {
                    asmLine.Append("            ");                    
                    for (int i = 6; i < (instrlen - 1); i++)
                    {
                        asmLine.Append(disasm.instrBytes[i].ToString("X2") + " ");   //extra bytes
                    }
                    asmLine.Append(disasm.instrBytes[instrlen - 1].ToString("X2"));   //last extra bytes
                    asmLine.AppendLine();
                }

                codeList.Add(asmLine.ToString());

                srcpos += instrlen;
                codeaddr += instrlen;
            }
        }

        public void getAddrList()
        {
            Regex regex = new Regex("[0-9A-F]{8}");
            uint codestart = imageBase + memloc;
            uint codeend = codestart + memsize;
            
            foreach (String line in codeList)
            {
                if (line.Length < 44) continue;
                Match match = regex.Match(line, 32);
                if (match.Success)
                {
                    uint val = Convert.ToUInt32(match.Value, 16);
                    if ((val >= codestart) && (val <= codeend)) {
                    Console.Out.WriteLine(val.ToString("X8"));
                    }
                }
            }
        }

        public void writeCodeFile(String outname)
        {
            StreamWriter outfile = new StreamWriter(outname);

            foreach (String line in codeList)
            {
                outfile.Write(line);
            }
            outfile.Close();
        }
        
    }
}
