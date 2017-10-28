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

namespace Origami.Win32
{
    class Win32Decoder
    {
        public SourceFile source;
        public Win32Parser parser;
        String outname;

        public PEHeader peHeader;
        public OptionalHeader optionalHeader;
        public List<Section> sections;
        CodeSection codesection;

        public Win32Decoder(SourceFile _source)
        {
            source = _source;
            parser = new Win32Parser(this);
            outname = "out.code.txt";

            peHeader = null;
            optionalHeader = null;
            sections = null;
        }

        public void setSourceFile(SourceFile _source) 
        {
            source = _source;
        }

        public void parse()
        {
            parser.parse();                         //parse win hdr + get section list
        }

        public void decode()
        {
            foreach (Section sec in sections)
            {
                if (sec is CodeSection)
                {
                    codesection = (CodeSection)sec;
                    codesection.loadSource();
                }
                
            }
            codesection.disasmCode();
            codesection.getAddrList();
            codesection.writeCodeFile(outname);
        }
    }
}
