/*
xxHash4net - C# implementation of xxHash derived HashAlgorithm class.
Copyright (C)2016 ailen0ada (ailen0ada@lapin.tokyo)
Original C Implementation Copyright (C) 2012-2014, Yann Collet. (https://github.com/Cyan4973/xxHash)
BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

using System;
using System.Collections.Generic;
using System.Security.Cryptography.xxHash;

namespace System.Security.Cryptography
{
    public sealed class xxHash64 : HashAlgorithm
    {

        private static readonly IList<ulong> primes64 =
            new[] {
                11400714785074694791UL,
                14029467366897019727UL,
                 1609587929392839161UL,
                 9650029242287828579UL,
                 2870177450012600261UL
            };

        private xxHashIntermediate64 intermediate;

        /// <summary>
        /// Gets the size, in bits, of the computed hash code.
        /// </summary>
        /// <returns>
        /// The size, in bits, of the computed hash code.
        /// </returns>
        public override int HashSize => 64;

        public new static xxHash64 Create(string hashName = "System.Security.Cryptography.xxHash64")
        {
            var ret = new xxHash64();
            ret.Initialize();
            return ret;
        }

        /// <summary>
        /// Initializes an implementation of the <see cref="T:System.Security.Cryptography.HashAlgorithm"/> class.
        /// </summary>
        public override void Initialize()
        {
            intermediate.Seed = 0;
            intermediate.Values = new[]
            {
                primes64[0] + primes64[1],
                primes64[1],
                0UL,
                0 - primes64[0]
            };
            intermediate.Length = 0;
            intermediate.MemorySize = 0;
            intermediate.Payload = new byte[32];
        }

        /// <summary>
        /// When overridden in a derived class, routes data written to the object into the hash algorithm for computing the hash.
        /// </summary>
        /// <param name="array">The input to compute the hash code for. </param><param name="ibStart">The offset into the byte array from which to begin using data. </param><param name="cbSize">The number of bytes in the byte array to use as data. </param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            array.ForEachSlice(ibStart, cbSize, 32,
                (dataGroup, pos, len) =>
                {
                    for (var x = pos; x < pos + len; x += 32)
                    {
                        for (var y = 0; y < 4; ++y)
                        {
                            var val = intermediate.Values[y];
                            val += UnSafeGetUInt64(dataGroup, x + (y << 3)) * primes64[1];
                            val = val.RotateLeft(31);
                            val *= primes64[0];
                            intermediate.Values[y] = val;
                        }
                    }
                    intermediate.Length += (ulong)len;
                },
                (remainder, pos, len) =>
                {
                    Buffer.BlockCopy(remainder, pos, intermediate.Payload, 0, len);
                    intermediate.Length += (ulong)len;
                    intermediate.MemorySize = len;
                });
        }

        /// <summary>
        /// When overridden in a derived class, finalizes the hash computation after the last data is processed by the cryptographic stream object.
        /// </summary>
        /// <returns>
        /// The computed hash code.
        /// </returns>
        protected override byte[] HashFinal()
        {
            ulong h;
            if (intermediate.Length >= 32)
            {
                h = intermediate.Values[0].RotateLeft(1) +
                    intermediate.Values[1].RotateLeft(7) +
                    intermediate.Values[2].RotateLeft(12) +
                    intermediate.Values[3].RotateLeft(18);

                foreach (ulong t in intermediate.Values)
                {
                    var val = t;
                    val *= primes64[1];
                    val = val.RotateLeft(31);
                    val *= primes64[0];

                    h ^= val;
                    h = (h * primes64[0]) + primes64[3];
                }
            }
            else
            {
                h = intermediate.Seed + primes64[4];
            }
            h += intermediate.Length;
            if (intermediate.MemorySize > 0)
            {

                for (int x = 0; x < intermediate.MemorySize >> 3; ++x)
                {
                    h ^= (UnSafeGetUInt64(intermediate.Payload, x << 3) * primes64[1]).RotateLeft(31) * primes64[0];
                    h = (h.RotateLeft(27) * primes64[0]) + primes64[3];
                }
                if ((intermediate.MemorySize & 7) >= 4)
                {
                    h ^= UnSafeGetUInt32(intermediate.Payload, intermediate.MemorySize - (intermediate.MemorySize & 7)) * primes64[0];
                    h = (h.RotateLeft(23) * primes64[1]) + primes64[2];
                }
                for (int x = intermediate.MemorySize - (intermediate.MemorySize & 3); x < intermediate.MemorySize; ++x)
                {
                    h ^= intermediate.Payload[x] * primes64[4];
                    h = h.RotateLeft(11) * primes64[0];
                }
            }

            h ^= h >> 33;
            h *= primes64[1];
            h ^= h >> 29;
            h *= primes64[2];
            h ^= h >> 32;

            return UnSafeGetBytes(h);
        }

        private static unsafe ulong UnSafeGetUInt64(byte[] bytes, int index)
        {
            fixed (byte* pointer = &bytes[index])
            {
                return *(ulong*)pointer;
            }
        }

        private static unsafe uint UnSafeGetUInt32(byte[] bytes, int index)
        {
            fixed (byte* pointer = &bytes[index])
            {
                return *(uint*)pointer;
            }
        }

        private static unsafe byte[] UnSafeGetBytes(ulong value)
        {
            var bytes = new byte[sizeof(ulong)];
            fixed (byte* pointer = bytes)
            {
                *(ulong*)pointer = value;
            }
            return bytes;
        }
    }
}
