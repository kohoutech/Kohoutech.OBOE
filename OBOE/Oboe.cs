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

//OBOE - Origami Binary for Objects and Executables

//

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

using Kohoutech.Binary;
using System.ComponentModel.Design.Serialization;
using System.Reflection;

namespace Kohoutech.OBOE
{
    public class Oboe
    {
        public const string OBOESIG = "OBOE";
        public const int SECTIONENTRYSIZE = 12;

        public List<Section> sections;
        public static Dictionary<uint, Section> loaders;

        public Oboe()
        {
            sections = new List<Section>();
        }

        //- section mgmt ------------------------------------------------------

        public static void registerSectionLoader(uint sectype, Section section)
        {
            loaders.Add(sectype, section);
        }

        public void addSection(Section sec)
        {
            sections.Add(sec);
            sec.num = sections.Count;
        }

        //- reading in from file -----------------------------------------------

        public static Oboe loadFromFile(string inname)
        {
            BinaryIn infile = new BinaryIn(inname);
            Oboe oboe = new Oboe();

            try
            {
                string sig = infile.getAsciiString(4);
                if (!sig.Equals(OBOESIG))
                {
                    throw new OboeFormatException("this is not a valid OBOE file");
                }
                uint secCount = infile.getFour();

                for (int i = 0; i < secCount; i++)
                {
                    uint sectype = infile.getFour();
                    uint secaddr = infile.getFour();
                    uint secsize = infile.getFour();
                    uint hdrpos = infile.getPos();

                    //ignore any section types we don't recognize
                    if (loaders.ContainsKey(sectype))
                    {
                        infile.seek(secaddr);
                        Section sec = loaders[sectype].readIn(infile, secsize);
                        oboe.addSection(sec);
                        infile.seek(hdrpos);
                    }
                }
            }
            catch(BinaryReadException)
            {
                throw new OboeFormatException("this is not a valid OBOE file");
            }

            return oboe;
        }

        //- writing out to file -----------------------------------------------

        public void writeOboeFile(String outname)
        {
            BinaryOut outfile = new BinaryOut(outname);
            this.writeOboeFile(outfile);
            outfile.writeOut();
        }

        public void writeOboeFile(BinaryOut outfile)
        {
            //write header
            outfile.putFixedString(OBOESIG, 4);
            outfile.putFour((uint)sections.Count);

            //write initial section tbl
            uint sectblsize = (uint)(sections.Count * SECTIONENTRYSIZE);
            uint sectbl = outfile.getPos();
            outfile.skip(sectblsize);

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
                outfile.putFour(sec.sectype);
                outfile.putFour(sec.addr);
                outfile.putFour(sec.size);
            }
        }

        //- text representation -----------------------------------------------

        public void dumpOboeFile(string dumpname)
        {
            //print out text file report for error checking
            StreamWriter txtout = File.CreateText(dumpname);

            txtout.WriteLine("signature: {0}", OBOESIG);
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

    //- error handling ------------------------------------------------------------

    class OboeFormatException : Exception
    {
        public OboeFormatException(string message)
            : base(message)
        {
        }
    }
}
