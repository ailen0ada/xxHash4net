# xxHash4net
C# implementation of [xxHash](https://github.com/Cyan4973/xxHash)

[![Build status](https://ci.appveyor.com/api/projects/status/6o8a5j896eq41js8?svg=true)](https://ci.appveyor.com/project/ailen0ada/xxhash4net)
[![NuGet version](https://badge.fury.io/nu/xxHash4net.svg)](https://badge.fury.io/nu/xxHash4net)

## Install

`PM > Install-Package xxHash4net`

## Usage
xxHash4net is succeeded class of `System.Security.Cryptography.HashAlgorithm`.

Easily replaced from other HashAlgorithm like MD5.

```cs
var hasher = xxHash64.Create();

var input = Encoding.UTF8.GetBytes("a");
var hash = BitConverter.ToUInt64(hasher.ComputeHash(input), 0);
// hash is 15154266338359012955
```

## License
BSD 2-clause license.