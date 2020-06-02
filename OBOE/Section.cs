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

namespace Kohoutech.OBOE
{
    //base class
    public class Section
    {
        public int num;
        public string name;
        public int sectype;
        public uint addr;           //for storage
        public uint size;

        //cons
        public Section(string _name, int _sectype)
        {
            num = 0;
            name = _name;
            sectype = _sectype;
            addr = 0;
            size = 0;
        }

        public virtual void writeOut(OutputFile outfile)
        {
            outfile.putString(name);
            outfile.putFour((uint)sectype);
        }

        public virtual void dumpSection(StreamWriter txtout)
        {
            txtout.WriteLine("SECTION {0}", num);
            txtout.WriteLine("name: {0}", name);
            txtout.WriteLine("section type: {0}", sectype);
            txtout.WriteLine("-------");
        }
    }

    //-------------------------------------------------------------------------

    public class OboeBlock : Section
    {
        //data vals
        public List<byte> blockdata;
        public List<ImportEntry> imports;
        public List<ExportEntry> exports;

        //cons
        public OboeBlock(string name) : base(name, Oboe.OBOEBLOCK)
        {
            blockdata = new List<byte>();
            imports = new List<ImportEntry>();
            exports = new List<ExportEntry>();
        }

        //- writing out -------------------------------------------------------

        public override void writeOut(OutputFile outfile)
        {
            base.writeOut(outfile);

            //initize block header
            uint hdrpos = outfile.getPos();
            outfile.putFour(0);
            outfile.putFour(0);
            outfile.putFour(0);
            outfile.putFour(0);
            outfile.putFour(0);
            outfile.putFour(0);

            //write block data
            uint blockaddr = outfile.getPos();
            uint blocksize = (uint)blockdata.Count;
            outfile.putRange(blockdata.ToArray());

            //write import list
            uint importaddr = outfile.getPos();
            uint importcount = (uint)imports.Count;
            foreach (ImportEntry imp in imports)
            {
                imp.writeToFile(outfile);
            }

            //write export list
            uint exportaddr = outfile.getPos();
            uint exportcount = (uint)exports.Count;
            foreach (ExportEntry exp in exports)
            {
                exp.writeToFile(outfile);
            }
            uint endpos = outfile.getPos();

            //go back and adjust block header
            outfile.seek(hdrpos);
            outfile.putFour(blockaddr);
            outfile.putFour(blocksize);
            outfile.putFour(importaddr);
            outfile.putFour(importcount);
            outfile.putFour(exportaddr);
            outfile.putFour(exportcount);
            outfile.seek(endpos);
        }

        public override void dumpSection(StreamWriter txtout)
        {
            base.dumpSection(txtout);

            int i = 0;
            if (blockdata.Count > 0)
            {
                txtout.Write("{0}: ", i.ToString("X4"));
                while (i < blockdata.Count)
                {
                    txtout.Write("{0} ", blockdata[i].ToString("X2"));
                    i++;
                    if (i % 16 == 0)
                    {
                        txtout.WriteLine();
                        txtout.Write("{0}: ", i.ToString("X4"));
                    }
                }
                txtout.WriteLine();
            }
            else
            {
                txtout.WriteLine("no data");
            }

            txtout.WriteLine();
            txtout.WriteLine("IMPORTS");
            txtout.WriteLine("-------");
            if (imports.Count == 0)
            {
                txtout.WriteLine("none");
            }
            else
            {
                foreach (ImportEntry imp in imports)
                {
                    txtout.WriteLine(imp.ToString());
                }
            }

            txtout.WriteLine();
            txtout.WriteLine("EXPORTS");
            txtout.WriteLine("-------");
            if (exports.Count == 0)
            {
                txtout.WriteLine("none");
            }
            else
            {
                foreach (ExportEntry exp in exports)
                {
                    txtout.WriteLine(exp.ToString());
                }
            }
        }
    }
}
