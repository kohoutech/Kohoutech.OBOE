/* ----------------------------------------------------------------------------
Kohoutech Binary Library
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

namespace Kohoutech.Binary
{

    //---------------------------------------------------------------------
    // READING IN
    //---------------------------------------------------------------------

    public class BinaryIn
    {
        String filename;
        byte[] srcbuf;
        uint srclen;
        uint srcpos;

        //for reading fields from a disk file
        public BinaryIn(String _filename)
        {
            filename = _filename;
            try
            {
                srcbuf = File.ReadAllBytes(filename);
            }
            catch (Exception e)
            {
                throw new BinaryReadException("error reading binary file " + filename);
            }
            srclen = (uint)srcbuf.Length;
            srcpos = 0;
        }

        public BinaryIn(byte[] data)
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

        public void checkData(uint len)
        {
            if (srcpos + len >= srclen)
            {
                throw new BinaryReadException("error reading binary data");
            }
        }

        public byte[] getRange(uint len)
        {
            checkData(len);
            byte[] result = new byte[len];
            Array.Copy(srcbuf, srcpos, result, 0, len);
            srcpos += len;
            return result;
        }

        public byte[] getRange(uint ofs, uint len)
        {
            checkData(ofs + len);
            byte[] result = new byte[len];
            Array.Copy(srcbuf, ofs, result, 0, len);
            return result;
        }

        //little endian unsigned int values
        public uint getOne()
        {
            checkData(1);
            byte a = srcbuf[srcpos++];
            uint result = (uint)(a);
            return result;
        }

        public uint getTwo()
        {
            checkData(2);
            byte b = srcbuf[srcpos++];
            byte a = srcbuf[srcpos++];
            uint result = (uint)a * 256 + b;
            return result;
        }

        public uint getFour()
        {
            checkData(4);
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
        public String getAsciiString(uint width)
        {
            checkData(width);
            String result = "";
            for (int i = 0; i < width; i++)
            {
                byte a = srcbuf[srcpos++];
                result += (char)a;
            }
            return result;
        }

        //C style string
        public String getAsciiZString()
        {
            String result = "";
            checkData(1);
            byte a = srcbuf[srcpos++];
            while (a != '\0')
            {
                result = result + (char)a;
                checkData(1);
                a = srcbuf[srcpos++];
            }
            return result;
        }

        public void skip(uint delta)
        {
            checkData(1);
            srcpos += delta;
        }

        public void seek(uint pos)
        {
            if (pos > srcpos)
            {
                checkData(pos - srcpos);
            }
            srcpos = pos;
        }
    }

    public class BinaryReadException : Exception
    {
        public BinaryReadException(string message)
            : base(message)
        {
        }
    }


    //---------------------------------------------------------------------
    // WRITING OUT
    //---------------------------------------------------------------------

    public class BinaryOut
    {
        static uint INITIAL_SIZE = 0x200;
        static uint SIZE_DELTA = 0x2000;

        String filename;
        byte[] outbuf;
        uint outlen;
        uint outpos;
        uint maxlen;

        //for write fields to a data buf
        public BinaryOut() : this(null)
        {
        }

        //for writing fields to a disk file
        public BinaryOut(String _filename)
            : this(_filename, INITIAL_SIZE)
        {
        }

        public BinaryOut(String _filename, uint filelen)
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

        //grow the outbuf as needed
        public void checkSpace(uint size)
        {
            uint needed = outpos + size;
            if (needed > outbuf.Length)
            {
                byte[] temp = new byte[needed + SIZE_DELTA];
                outbuf.CopyTo(temp, 0);
                outbuf = temp;
            }
            if (needed > maxlen)
            {
                maxlen = needed;
            }
        }

        //little endian unsigned int values
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

        //padding out data fields
        public void putZeros(uint len)
        {
            checkSpace(len);
            for (int i = 0; i < len; i++)
            {
                outbuf[outpos++] = 0;
            }
        }

        public void skip(uint delta)
        {
            uint newpos = outpos + delta;
            seek(newpos);
        }

        public void seek(uint pos)
        {
            if (pos > outpos)                   //if we are seeking beyond the cur pos in the output buf
            {
                checkSpace(pos - outpos);
            }
            outpos = pos;
        }

        public byte[] getData()
        {
            //remove unused space at end of file
            //any padding needed at end of file should be already handled by caller
            if (maxlen < outbuf.Length)
            {
                byte[] newbuf = new byte[maxlen];
                Array.Copy(outbuf, newbuf, maxlen);
                outbuf = newbuf;
            }
            return outbuf;
        }

        public void writeOut()
        {
            File.WriteAllBytes(filename, getData());
        }
    }
}

//Console.WriteLine("there's no sun in the shadow of the wizard");