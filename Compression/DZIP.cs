using System;
using System.IO;
using System.IO.Compression;

namespace Compression
{
    public static class DZIP
    {
        public static byte[] Compress(byte[] _Bytes)
        {
            using (MemoryStream _Memory_Stream = new MemoryStream())
            {
                using (DeflateStream _Deflate_Stream = new DeflateStream(_Memory_Stream, CompressionMode.Compress, true))
                {
                    _Deflate_Stream.Write(_Bytes, 0x0, _Bytes.Length);

                    _Memory_Stream.Position = 0x0;

                    byte[] _Compressed = new byte[_Memory_Stream.Length + 0x1];

                    _Memory_Stream.Read(_Compressed, 0x0, _Compressed.Length);

                    return _Compressed;
                }
            }
        }

        public static byte[] Decompress(byte[] _Bytes)
        {
            using (MemoryStream _Memory_Stream = new MemoryStream(_Bytes))
            {
                using (DeflateStream _Deflate_Stream = new DeflateStream(_Memory_Stream, CompressionMode.Decompress))
                {
                    byte[] _Buffer = new byte[0x4];

                    _Memory_Stream.Position = _Memory_Stream.Length - 0x5;

                    _Memory_Stream.Read(_Buffer, 0x0, 0x4);

                    int _Size = BitConverter.ToInt32(_Buffer, 0x0);

                    _Memory_Stream.Position = 0x0;

                    byte[] _Decompressed = new byte[_Size - 0x1 + 0x1];

                    _Deflate_Stream.Read(_Decompressed, 0x0, _Size);

                    return _Decompressed;
                }
            }
        }
    }
}