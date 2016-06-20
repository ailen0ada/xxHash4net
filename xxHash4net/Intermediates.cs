using System;

namespace System.Security.Cryptography.xxHash
{
    internal struct xxHashIntermediate32
    {
        public ulong Length;

        public uint Seed;

        public uint[] Values;

        public int MemorySize;

        public byte[] Payload;
    }

    internal struct xxHashIntermediate64
    {
        public ulong Length;

        public uint Seed;

        public ulong[] Values;

        public int MemorySize;

        public byte[] Payload;
    }
}
