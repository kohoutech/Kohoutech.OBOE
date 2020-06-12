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
using System.Net.Sockets;
using System.Text;
using System.IO;

using Kohoutech.Binary;

namespace Kohoutech.OBOE
{
    //section base class
    public class Section
    {
        public int num;             //section's pos in the section table
        public string name;
        public uint sectype;
        public uint addr;           //for storage & linkage
        public uint size;

        //cons
        public Section(string _name, uint _sectype)
        {
            num = 0;
            name = _name;
            sectype = _sectype;
            addr = 0;
            size = 0;
        }

        public virtual Section readIn(BinaryIn infile, uint secsize)
        {
            return null;
        }

        public virtual void writeOut(BinaryOut outfile)
        {
            outfile.putString(name);            
        }

        public virtual void dumpSection(StreamWriter txtout)
        {
            txtout.WriteLine("SECTION {0}", num);
            txtout.WriteLine("name: {0}", name);
            txtout.WriteLine("section type: {0}", sectype);
            txtout.WriteLine("-------");
        }
    }
}
