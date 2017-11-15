/* ----------------------------------------------------------------------------
Origami Win32 Library
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

namespace Origami.Win32
{
    
    class CodeSection : Section
    {
        const int BYTESFIELDWIDTH = 6;              //in bytes = each byte takes up 3 spaces
        const int OPCODEFIELDWIDTH = 12;            //in actual spaces

        i32Disasm disasm;
        List<String> codeList;

        public CodeSection(Win32Decoder decoder, SourceFile source, int _secnum, String _sectionName, uint _memsize,
                uint _memloc, uint _filesize, uint _fileloc, uint _pRelocations, uint _pLinenums,
            int _relocCount, int _linenumCount, uint _flags)
            : base(decoder, source, _secnum, _sectionName, _memsize, _memloc, _filesize, _fileloc, _pRelocations, _pLinenums,
            _relocCount, _linenumCount, _flags)
        {            
        }

//-----------------------------------------------------------------------------

        //format addr, instruction bytes & asm ops into a list of strings for all bytes in code section
        //code format based on MS dumpbin utility
        public List<String> disasmCode()
        {
            loadSource();

            uint srcpos = 0;
            disasm = new i32Disasm(sourceBuf, srcpos);
            codeList = new List<String>();
            StringBuilder asmLine = new StringBuilder();

            uint instrlen = 0;
            uint codeaddr = memloc;         //starting pos of code in mem, used for instr addrs

            while (srcpos < sourceBuf.Length)       
            {
                disasm.getInstr(codeaddr);          //disasm bytes at cur source pos to next instruction
                instrlen = disasm.instrLen;         //determines how many bytes to format in line

                asmLine.Clear();

                //address field
                asmLine.Append("  " + codeaddr.ToString("X8") + ": ");

                //bytes field
                for (int i = 0; i < BYTESFIELDWIDTH; i++)
                {
                    if (i < instrlen)
                    {
                        asmLine.Append(disasm.instrBytes[i].ToString("X2") + " ");
                    }
                    else
                    {
                        asmLine.Append("   ");          //extra space in field
                    }
                }
                asmLine.Append(" ");

                //opcodes - one op followed by 0 to 3 operands
                String spacer = (disasm.opcode.Length < OPCODEFIELDWIDTH) ?
                    "            ".Substring(0, OPCODEFIELDWIDTH - disasm.opcode.Length) : "";
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

                //if all of instructions bytes were too long for one line, put the extra bytes on the next line
                if (instrlen > 6)
                {
                    asmLine.AppendLine();
                    asmLine.Append("            ");
                    for (int i = 6; i < (instrlen - 1); i++)
                    {
                        asmLine.Append(disasm.instrBytes[i].ToString("X2") + " ");   //extra bytes
                    }
                    asmLine.Append(disasm.instrBytes[instrlen - 1].ToString("X2"));   //last extra byte
                }

                codeList.Add(asmLine.ToString());

                srcpos += instrlen;
                codeaddr += instrlen;
            }

            freeSource();
            return codeList;
        }

        public void getAddrList()
        {
            Regex regex = new Regex("[0-9A-F]{8}");
            uint codestart = memloc;
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
    }
}
