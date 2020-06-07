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

namespace Kohoutech.OBOE
{
    public class ImportEntry
    {
        public enum IMPORTTYPE { DIR32, REL32 };

        public string name;
        public uint addr;
        public IMPORTTYPE typ;

        public ImportEntry(string _name, uint _addr, IMPORTTYPE _typ)
        {
            int spidx = _name.IndexOf(' ');
            if (spidx != -1)
            {
                _name = _name.Substring(0, spidx);
            }

            name = _name;
            addr = _addr;
            typ = _typ;
        }

        public static ImportEntry loadFromFile(BinaryIn infile)
        {
            string name = infile.getAsciiZString();
            uint addr = infile.getFour();
            uint b = infile.getOne();
            ImportEntry imp = new ImportEntry(name, addr, (IMPORTTYPE)b);
            return imp;            
        }

        public void writeToFile(BinaryOut outfile)
        {
            outfile.putString(name);
            outfile.putFour((uint)addr);
            //int b = (typ == IMPORTTYPE.DIR32) ? 0 : 1;
            outfile.putOne((uint)typ);
        }

        public override string ToString()
        {
            return String.Format("{0}: {1} [{2}]", addr.ToString("X4"), name, typ.ToString());
        }

    }

}
