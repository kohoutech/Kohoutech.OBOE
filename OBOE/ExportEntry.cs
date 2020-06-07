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
    public class ExportEntry
    {
        public string name;
        public uint addr;

        public ExportEntry(string _name, uint _addr)
        {
            int spidx = _name.IndexOf(' ');
            if (spidx != -1)
            {
                _name = _name.Substring(0, spidx);
            }

            name = _name;
            addr = _addr;
        }

        public static ExportEntry loadFromFile(BinaryIn infile)
        {
            string name = infile.getAsciiZString();
            uint addr = infile.getFour();
            ExportEntry exp = new ExportEntry(name, addr);
            return exp;
        }

        public void writeToFile(BinaryOut modfile)
        {
            modfile.putString(name);
            modfile.putFour((uint)addr);
        }

        public override string ToString()
        {
            return String.Format("{0}: {1}", addr.ToString("X4"), name);
        }

        internal static int sortByAddress(ExportEntry x, ExportEntry y)
        {
            return x.addr.CompareTo(y.addr);
        }
    }

}
