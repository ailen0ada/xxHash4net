using System;

namespace System.Security.Cryptography.xxHash
{
    internal static class ByteArrayExtensions
    {
        public static void ForEachSlice(this byte[] data, int startIndex, int count, int sliceSize, Action<byte[], int, int> action, Action<byte[], int, int> remainderAction)
        {
            if (sliceSize <= 0)
                throw new ArgumentOutOfRangeException(nameof(sliceSize));
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (action == null)
                throw new ArgumentNullException(nameof(action));

            var remainderLength = count & (sliceSize - 1);
            if (count - remainderLength > 0)
                action(data, startIndex, count - remainderLength);
            if (remainderAction != null && remainderLength > 0)
                remainderAction(data, startIndex + count - remainderLength, remainderLength);
        }

        public static uint RotateLeft(this uint operand, int shiftCount)
        {
            shiftCount &= 0x1f;
            return (operand << shiftCount) | (operand >> (32 - shiftCount));
        }

        public static ulong RotateLeft(this ulong operand, int shiftCount)
        {
            shiftCount &= 0x3f;
            return (operand << shiftCount) | (operand >> (64 - shiftCount));
        }
    }
}
