using System.Security.Cryptography;
using System.Text;

namespace CryptographyDemo.Demos;

public static class EcdsaDemo
{
    public static void Show()
    {
        Console.WriteLine("\n--- Цифровые подписи ECDsa ---");

        // Генерация ключей на кривой P-256
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string document = "Важный документ для подписания";
        byte[] documentBytes = Encoding.UTF8.GetBytes(document);

        // Создание подписи
        byte[] signature = ecdsa.SignData(documentBytes, HashAlgorithmName.SHA256);
        Console.WriteLine($"Подпись: {Convert.ToBase64String(signature)}");
        Console.WriteLine($"Длина подписи: {signature.Length} байт");

        // Проверка подписи
        bool isValid = ecdsa.VerifyData(documentBytes, signature, HashAlgorithmName.SHA256);
        Console.WriteLine($"Подпись верна: {isValid}");

        // Проверка с измененным документом
        documentBytes[0] ^= 0x01;
        bool isTampered = ecdsa.VerifyData(documentBytes, signature, HashAlgorithmName.SHA256);
        Console.WriteLine($"После изменений подпись верна: {isTampered}");

        // Экспорт публичного ключа
        byte[] publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        Console.WriteLine($"\nПубличный ключ (первые 50 байт): {Convert.ToBase64String(publicKey[..50])}...");
    }
}