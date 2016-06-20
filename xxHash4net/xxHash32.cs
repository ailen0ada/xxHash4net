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

    public sealed class xxHash32 : HashAlgorithm
    {
        private static readonly IList<uint> primes32 =
            new[] {
                2654435761U,
                2246822519U,
                3266489917U,
                668265263U,
                374761393U
            };

        private xxHashIntermediate32 intermediate;

        /// <summary>
        /// Gets the size, in bits, of the computed hash code.
        /// </summary>
        /// <returns>
        /// The size, in bits, of the computed hash code.
        /// </returns>
        public override int HashSize => 32;

        public new static xxHash32 Create(string hashName = "System.Security.Cryptography.xxHash32")
        {
            var ret = new xxHash32();
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
                primes32[0] + primes32[1],
                primes32[1],
                0U,
                0 - primes32[0]
            };
            intermediate.Length = 0;
            intermediate.MemorySize = 0;
            intermediate.Payload = new byte[16];
        }

        /// <summary>
        /// When overridden in a derived class, routes data written to the object into the hash algorithm for computing the hash.
        /// </summary>
        /// <param name="array">The input to compute the hash code for. </param><param name="ibStart">The offset into the byte array from which to begin using data. </param><param name="cbSize">The number of bytes in the byte array to use as data. </param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            array.ForEachSlice(ibStart, cbSize, 16,
                (dataGroup, pos, len) =>
                {
                    for (int x = pos; x < pos + len; x += 16)
                    {
                        for (var y = 0; y < 4; ++y)
                        {
                            intermediate.Values[y] += BitConverter.ToUInt32(dataGroup, x + (y << 2)) * primes32[1];
                            intermediate.Values[y] = intermediate.Values[y].RotateLeft(13);
                            intermediate.Values[y] *= primes32[0];
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
            uint h;
            if (intermediate.Length >= 16)
            {
                h = intermediate.Values[0].RotateLeft(1) +
                    intermediate.Values[1].RotateLeft(7) +
                    intermediate.Values[2].RotateLeft(12) +
                    intermediate.Values[3].RotateLeft(18);
            }
            else
            {
                h = intermediate.Seed + primes32[4];
            }
            h += (uint)intermediate.Length;
            if (intermediate.MemorySize > 0)
            {
                for (int x = 0; x < intermediate.MemorySize >> 2; ++x)
                {
                    h += BitConverter.ToUInt32(intermediate.Payload, x << 2) * primes32[2];
                    h = h.RotateLeft(17) * primes32[3];
                }

                for (int x = intermediate.MemorySize - (intermediate.MemorySize & 3); x < intermediate.MemorySize; ++x)
                {
                    h += intermediate.Payload[x] * primes32[4];
                    h = h.RotateLeft(11) * primes32[0];
                }
            }

            h ^= h >> 15;
            h *= primes32[1];
            h ^= h >> 13;
            h *= primes32[2];
            h ^= h >> 16;

            return BitConverter.GetBytes(h);
        }
    }
}
