using BenchmarkDotNet.Running;
using CryptographyDemo.Benchmarks;
using CryptographyDemo.Demos;

namespace CryptographyDemo;

class Program
{
    static void Main(string[] args)
    {

        // Запуск демонстраций
        //AesCbcDemo.Show();
        //AesGcmDemo.Show();
        //RsaDemo.Show();
        //HashingDemo.Show();
        //EcdsaDemo.Show();
        //CombinedDemo.Show();

        BenchmarkRunner.Run<CryptoBenchmarks>();
    }
}