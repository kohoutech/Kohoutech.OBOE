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
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;

using Kohoutech.Binary;

namespace Kohoutech.OBOE
{
    public class OboeBlock : Section
    {
        public static uint CODEBLOCK = 1000;
        public static uint DATABLOCK = 1001;
        public static uint VARBLOCK = 1002;

        //data vals
        public List<byte> blockdata;
        public List<ImportEntry> imports;
        public List<ExportEntry> exports;

        //cons
        public OboeBlock(string name, uint _type) : base(name, _type)
        {
            blockdata = new List<byte>();
            imports = new List<ImportEntry>();
            exports = new List<ExportEntry>();
        }

        //- reading in --------------------------------------------------------

        internal static OboeBlock loadSection(BinaryIn infile, uint secaddr, uint secsize, uint sectype)
        {
            infile.seek(secaddr);
            String blockname = infile.getAsciiZString();
            OboeBlock block = new OboeBlock(blockname, sectype);
            uint blockaddr = infile.getFour();
            uint blocksize = infile.getFour();
            uint importaddr = infile.getFour();
            uint importcount = infile.getFour();
            uint exportaddr = infile.getFour();
            uint exportcount = infile.getFour();

            //block data
            infile.seek(blockaddr);
            block.blockdata = new List<byte>(infile.getRange(blocksize));

            //import list
            infile.seek(importaddr);
            for(int i = 0; i < importcount; i++)
            {
                ImportEntry imp = ImportEntry.loadFromFile(infile);
                block.imports.Add(imp);
            }

            //export list
            infile.seek(exportaddr);
            for (int i = 0; i < exportcount; i++)
            {
                ExportEntry exp = ExportEntry.loadFromFile(infile);
                block.exports.Add(exp);
            }

            return block;
        }

        //- writing out -------------------------------------------------------

        public override void writeOut(BinaryOut outfile)
        {
            base.writeOut(outfile);

            //initize block header
            uint hdrpos = outfile.getPos();
            outfile.skip(24);

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
                txtout.WriteLine("size: {0}", blockdata.Count.ToString("X4"));
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

    //-------------------------------------------------------------------------

    public class BSSBlock : Section
    {
        public static uint BSSBLOCK = 1003;

        //data vals
        public uint bssSize;
        public List<ExportEntry> exports;

        public BSSBlock() : base("BSS", BSSBLOCK)
        {
            bssSize = 0;
            exports = new List<ExportEntry>();
        }

        internal static Section loadSection(BinaryIn infile, uint secaddr, uint secsize)
        {
            infile.seek(secaddr);
            String blockname = infile.getAsciiZString();
            BSSBlock block = new BSSBlock();
            block.bssSize = infile.getFour();
            uint exportcount = infile.getFour();

            //export list
            for (int i = 0; i < exportcount; i++)
            {
                ExportEntry exp = ExportEntry.loadFromFile(infile);
                block.exports.Add(exp);
            }

            return block;
        }

        public override void writeOut(BinaryOut outfile)
        {
            base.writeOut(outfile);
            outfile.putFour(bssSize);
            outfile.putFour((uint)exports.Count);

            //write export list
            foreach (ExportEntry exp in exports)
            {
                exp.writeToFile(outfile);
            }
        }

        public override void dumpSection(StreamWriter txtout)
        {
            base.dumpSection(txtout);

            txtout.WriteLine("size: {0}", bssSize.ToString("X4"));
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