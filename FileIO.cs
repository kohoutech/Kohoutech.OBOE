/* ----------------------------------------------------------------------------
Origami Win32 Library
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

namespace Origami.Win32
{

    //- reading in ----------------------------------------------------------------

    public class SourceFile
    {
        String filename;
        byte[] srcbuf;
        uint srclen;
        uint srcpos;

        //for reading fields from a disk file
        public SourceFile(String _filename)
        {
            filename = _filename;
            srcbuf = File.ReadAllBytes(filename);
            srclen = (uint)srcbuf.Length;
            srcpos = 0;
        }

        //for reading fields from a data buf
        public SourceFile(byte[] data)
        {
            filename = null;
            srcbuf = data;
            srclen = (uint)srcbuf.Length;
            srcpos = 0;
        }

        public uint getPos()
        {
            return srcpos;
        }

        public byte[] getRange(uint len)
        {
            byte[] result = new byte[len];
            Array.Copy(srcbuf, srcpos, result, 0, len);
            srcpos += len;
            return result;
        }

        public byte[] getRange(uint ofs, uint len)
        {
            byte[] result = new byte[len];
            Array.Copy(srcbuf, ofs, result, 0, len);
            return result;
        }

        public uint getOne()
        {
            byte a = srcbuf[srcpos++];
            uint result = (uint)(a);
            return result;
        }

        public uint getTwo()
        {
            byte b = srcbuf[srcpos++];
            byte a = srcbuf[srcpos++];
            uint result = (uint)a * 256 + b;
            return result;
        }

        public uint getFour()
        {
            byte d = srcbuf[srcpos++];
            byte c = srcbuf[srcpos++];
            byte b = srcbuf[srcpos++];
            byte a = srcbuf[srcpos++];
            uint result = (uint)(a * 256 + b);
            result = (result * 256 + c);
            result = (result * 256 + d);
            return result;
        }

        //fixed len string
        public String getAsciiString(int width)
        {
            String result = "";
            for (int i = 0; i < width; i++)
            {
                byte a = srcbuf[srcpos++];
                if ((a >= 0x20) && (a <= 0x7E))
                {
                    result += (char)a;
                }
            }
            return result;
        }

        public void skip(uint delta)
        {
            srcpos += delta;
        }

        public void seek(uint pos)
        {
            srcpos = pos;
        }
    }

    //- writing out ---------------------------------------------------------------

    public class OutputFile
    {
        static uint INITIAL_SIZE = 0x200;
        static uint SIZE_DELTA = 0x2000;

        String filename;
        byte[] outbuf;
        uint outlen;
        uint outpos;
        uint maxlen;

        //for writing fields to a disk file
        public OutputFile(String _filename)
            : this(_filename, INITIAL_SIZE)
        {
        }

        public OutputFile(String _filename, uint filelen)
        {
            filename = _filename;
            outlen = filelen;
            outbuf = new byte[outlen];
            outpos = 0;
            maxlen = 0;
        }

        public uint getPos()
        {
            return outpos;
        }

        public void checkSpace(uint size)
        {
            uint needed = outpos + size;
            if (needed > outbuf.Length)
            {
                byte[] temp = new byte[needed + SIZE_DELTA];
                outbuf.CopyTo(temp, 0);
                outbuf = temp;
            }
        }

        public void putOne(uint val)
        {
            checkSpace(1);
            outbuf[outpos++] = (byte)(val % 0x100);
        }

        public void putTwo(uint val)
        {
            checkSpace(2);
            byte a = (byte)(val % 0x100);
            val /= 0x100;
            byte b = (byte)(val % 0x100);
            outbuf[outpos++] = a;
            outbuf[outpos++] = b;
        }

        public void putFour(uint val)
        {
            checkSpace(4);
            byte a = (byte)(val % 0x100);
            val /= 0x100;
            byte b = (byte)(val % 0x100);
            val /= 0x100;
            byte c = (byte)(val % 0x100);
            val /= 0x100;
            byte d = (byte)(val % 0x100);
            outbuf[outpos++] = a;
            outbuf[outpos++] = b;
            outbuf[outpos++] = c;
            outbuf[outpos++] = d;
        }

        //asciiz string
        public void putString(String s)
        {
            checkSpace((uint)(s.Length + 1));
            for (int i = 0; i < s.Length; i++)
            {
                outbuf[outpos++] = (byte)s[i];
            }
            outbuf[outpos++] = 0x00;
        }

        //fixed len string
        public void putFixedString(String str, int width)
        {
            checkSpace((uint)width);
            for (int i = 0; i < width; i++)
            {
                if (i < str.Length)
                {
                    outbuf[outpos++] = (byte)str[i];
                }
                else
                {
                    outbuf[outpos++] = 0;
                }
            }
        }

        public void putRange(byte[] bytes)
        {
            uint len = (uint)bytes.Length;
            checkSpace(len);
            Array.Copy(bytes, 0, outbuf, outpos, len);
            outpos += len;
        }

        public void putZeros(uint len)
        {
            checkSpace(len);
            for (int i = 0; i < len; i++)
            {
                outbuf[outpos++] = 0;
            }
        }

        public void seek(uint pos)
        {
            checkSpace(pos - outpos);
            outpos = pos;
        }

        public void writeOut()
        {
            //remove unused space at end of file
            //any padding needed at end of file should be handled by caller
            if (outpos < outbuf.Length)
            {
                byte[] newbuf = new byte[outpos];
                Array.Copy(outbuf, newbuf, outpos);
                outbuf = newbuf;
            }
            File.WriteAllBytes(filename, outbuf);
        }
    }
}

//Console.WriteLine("there's no sun in the shadow of the wizard");