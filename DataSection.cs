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

//doesn't do much at the moment other than being a section subclass that is NOT a code section
//may be expanded in the future

namespace Origami.Win32
{
    class DataSection : Section
    {
        public DataSection(Win32Decoder decoder, SourceFile source, int _secnum, String _sectionName, uint _memsize,
                uint _memloc, uint _filesize, uint _fileloc, uint _pRelocations, uint _pLinenums,
            int _relocCount, int _linenumCount, uint _flags)
            : base(decoder, source, _secnum, _sectionName, _memsize, _memloc, _filesize, _fileloc, _pRelocations, _pLinenums,
            _relocCount, _linenumCount, _flags)
        {            
        }
    }
}
