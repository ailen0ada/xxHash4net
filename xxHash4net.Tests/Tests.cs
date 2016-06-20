using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NUnit.Framework;
using NUnit.Framework.Compatibility;

namespace System.Security.Cryptography.xxHash.Tests
{
    [TestFixture]
    public class Tests
    {
        [Test]
        public void Calculate32Test()
        {
            var testAssets = new Dictionary<string, uint>()
            {
                {"a", 1426945110},
                {"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aliquam at erat vel nulla gravida convallis eget non quam orci aliquam.", 165925826}
            };
            var hasher = xxHash32.Create();
            foreach (var asset in testAssets)
            {
                var input = Encoding.UTF8.GetBytes(asset.Key);
                var ret = BitConverter.ToUInt32(hasher.ComputeHash(input), 0);
                ret.Is(asset.Value);
            }
        }

        [Test]
        public void Calculate64Test()
        {
            var testAssets = new Dictionary<string, ulong>()
            {
                {"a", 15154266338359012955},
                {"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aliquam at erat vel nulla gravida convallis eget non quam orci aliquam.", 17860238105912946884}
            };
            var hasher = xxHash64.Create();
            foreach (var asset in testAssets)
            {
                var input = Encoding.UTF8.GetBytes(asset.Key);
                var ret = BitConverter.ToUInt64(hasher.ComputeHash(input), 0);
                ret.Is(asset.Value);
            }
        }

        public void BenchmarkTest()
        {
            var sw = new Stopwatch();
            var rnd = new Random();
            HashAlgorithm[] hashProviders = { new MD5Cng(), xxHash32.Create(), xxHash64.Create() };
            var assets = Enumerable.Range(0, 1000000).Select(_ =>
            {
                var buffer = new byte[1024];
                rnd.NextBytes(buffer);
                return buffer;
            }).ToArray();
            Console.WriteLine($"Number of test assets: {assets.Length}");
            foreach (var provider in hashProviders)
            {
                Console.Write($"{provider.GetType()} --> ");
                sw.Start();
                foreach (var asset in assets)
                    provider.ComputeHash(asset);
                sw.Stop();
                Console.WriteLine($"{sw.Elapsed}");
                sw.Reset();
            }
        }
    }
}
