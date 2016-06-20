# xxHash4net
C# implementation of [xxHash](https://github.com/Cyan4973/xxHash)

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