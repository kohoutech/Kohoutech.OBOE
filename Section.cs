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

namespace Origami.Windows
{
    class Section
    {
        const uint IMAGE_SCN_CNT_CODE = 0x00000020;

        protected Fluoroscope fluoro;
        protected SourceFile source;

        public uint imageBase;
        public int secNum;
        public String sectionName;
        public uint memloc;
        public uint memsize;

        protected uint fileloc;             //section file location
        protected uint filesize;            //section file size
        protected uint flags;

        public uint[] sourceBuf;

//using a factory method becuase we don't know what type of section it is until we read the section header
        public static Section getSection(Fluoroscope _fluoro, int _secnum, uint _imageBase) 
        {
            SourceFile source = _fluoro.source;
            String sectionName = source.getString(8);            
            uint memsize = source.getFour();
            uint memloc = source.getFour();
            uint filesize = source.getFour();
            uint fileloc = source.getFour();
            uint res1 = source.getFour();
            uint res2 = source.getFour();
            uint res3 = source.getFour();
            uint flags = source.getFour();

            Section result;
            if ((flags & IMAGE_SCN_CNT_CODE) != 0)
            {
                result = new CodeSection(_fluoro, _secnum, sectionName, memsize, memloc,
                    filesize, fileloc, flags, _imageBase);
            }
            else
            {
                result = new DataSection(_fluoro, _secnum, sectionName, memsize, memloc,
                    filesize, fileloc, flags, _imageBase);
            }

            return result;
        }

        public Section(Fluoroscope _fluoro, int _secnum, String _sectionName, uint _memsize, 
                uint _memloc, uint _filesize, uint _fileloc, uint _flags, uint _imagebase)
        {
            fluoro = _fluoro;
            source = fluoro.source;
            imageBase = _imagebase;
            secNum = _secnum;
            sectionName = _sectionName;
            memsize = _memsize;
            memloc = _memloc;
            filesize = _filesize;
            fileloc = _fileloc;
            flags = _flags;

            Console.Out.WriteLine("[" + secNum + "] sectionName = " + sectionName);
            Console.Out.WriteLine("[" + secNum + "] memsize = " + memsize.ToString("X"));
            Console.Out.WriteLine("[" + secNum + "] memloc = " + memloc.ToString("X"));
            Console.Out.WriteLine("[" + secNum + "] filesize = " + filesize.ToString("X"));
            Console.Out.WriteLine("[" + secNum + "] fileloc = " + fileloc.ToString("X"));
            Console.Out.WriteLine("[" + secNum + "] flags = " + flags.ToString("X"));

            sourceBuf = null;
        }

        public void loadSource() {

            sourceBuf = source.getRange(memloc, memsize);
        }
    }
}
