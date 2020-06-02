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
using System.IO;

//OBOE - Origami Binary for Objects and Executables

namespace Kohoutech.OBOE
{
    public class Oboe
    {
        public static int OBOEVERSION = 1;
        public static int OBOEBLOCK = 1000;
        public static int BSSBLOCK = 1001;

        //header vals
        public string sig;
        public int version;
        public List<Section> sections;

        public Oboe(string name)
        {
            sig = "OBOE";
            version = OBOEVERSION;
            sections = new List<Section>();
        }

        //- writing out to file -----------------------------------------------

        public void writeOboeFile(String outname)
        {
            OutputFile outfile = new OutputFile(outname);
            this.writeOboeFile(outfile);
            outfile.writeOut();
        }

        public void writeOboeFile(OutputFile outfile)
        {
            //write header
            outfile.putFixedString(sig, 4);
            outfile.putFour((uint)version);
            outfile.putFour((uint)sections.Count);
            writeExtendedHeader(outfile);

            //write initial section tbl
            uint sectbl = outfile.getPos();
            for (int i = 0; i < sections.Count; i++)
            {
                outfile.putFour(0);     //addr
                outfile.putFour(0);     //size
            }

            //write section data
            uint pos = outfile.getPos();
            foreach (Section sec in sections)
            {
                sec.addr = pos;
                sec.writeOut(outfile);
                pos = outfile.getPos();
                sec.size = pos - sec.addr;
            }

            //adjust section tbl
            outfile.seek(sectbl);
            foreach (Section sec in sections)
            {
                outfile.putFour(sec.addr);
                outfile.putFour(sec.size);
            }
        }

        //for subclasses to add their own specific header fields
        public virtual void writeExtendedHeader(OutputFile outfile)
        {

        }

        public void dumpOboeFile(string dumpname)
        {
            //print out text file report for error checking
            StreamWriter txtout = File.CreateText(dumpname);

            txtout.WriteLine(sig);
            txtout.WriteLine(version.ToString());
            txtout.WriteLine();
            txtout.WriteLine("section count: {0}", sections.Count.ToString());
            foreach (Section sec in sections)
            {
                txtout.WriteLine("-----------------------------------------");
                sec.dumpSection(txtout);
            }
            txtout.Flush();
            txtout.Close();
        }
    }
}
