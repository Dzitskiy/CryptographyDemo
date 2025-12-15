using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using CryptographyDemo.Demos;
using System.Security.Cryptography;
using System.Text;

namespace CryptographyDemo.Benchmarks;

[MemoryDiagnoser]
[RankColumn]
public class CryptoBenchmarks
{
    private readonly byte[] _data = Encoding.UTF8.GetBytes("Test data for benchmarking");
    private readonly byte[] _aesKey = new byte[32];
    private readonly byte[] _iv = new byte[16];
    private readonly byte[] _hmacKey = new byte[32];
    private readonly RSA _rsa = RSA.Create(2048);
    private readonly ECDsa _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public CryptoBenchmarks()
    {
        RandomNumberGenerator.Fill(_aesKey);
        RandomNumberGenerator.Fill(_iv);
        RandomNumberGenerator.Fill(_hmacKey);
    }

    [Benchmark]
    public byte[] AesCbc_Encrypt() => AesCbcDemo.Encrypt(_data, _aesKey, _iv);

    [Benchmark]
    public byte[] AesCbc_Decrypt()
    {
        byte[] encrypted = AesCbcDemo.Encrypt(_data, _aesKey, _iv);
        return AesCbcDemo.Decrypt(encrypted, _aesKey, _iv);
    }

    [Benchmark]
    public (byte[], byte[]) AesGcm_Encrypt()
    {
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        return AesGcmDemo.Encrypt(_data, _aesKey, nonce);
    }

    [Benchmark]
    public byte[] Sha256_Hash() => SHA256.HashData(_data);

    [Benchmark]
    public byte[] Hmac_Compute() => HashingDemo.ComputeHmac(_data, _hmacKey);

    [Benchmark]
    public byte[] Rsa_Encrypt() => _rsa.Encrypt(_data, RSAEncryptionPadding.OaepSHA256);

    [Benchmark]
    public byte[] Ecdsa_Sign() => _ecdsa.SignData(_data, HashAlgorithmName.SHA256);
}