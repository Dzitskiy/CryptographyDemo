using System.Security.Cryptography;
using System.Text;

namespace CryptographyDemo.Demos;

public static class HashingDemo
{
    public static void Show()
    {
        Console.WriteLine("\n--- Хеширование и HMAC ---");

        string message = "Важные данные для проверки целостности";
        byte[] messageBytes = Encoding.UTF8.GetBytes(message);

        // Простое хеширование
        byte[] hash = SHA256.HashData(messageBytes);
        Console.WriteLine($"SHA256 хеш: {Convert.ToBase64String(hash)}");
        Console.WriteLine($"Длина хеша: {hash.Length} байт");

        // HMAC для проверки целостности и аутентичности
        byte[] hmacKey = new byte[32];
        RandomNumberGenerator.Fill(hmacKey);

        byte[] hmac = ComputeHmac(messageBytes, hmacKey);
        Console.WriteLine($"HMAC-SHA256: {Convert.ToBase64String(hmac)}");

        // Проверка HMAC
        bool isValid = VerifyHmac(messageBytes, hmacKey, hmac);
        Console.WriteLine($"HMAC верен: {isValid}");

        // Попытка подмены
        messageBytes[0] ^= 0x01; // Изменяем данные
        bool isTampered = VerifyHmac(messageBytes, hmacKey, hmac);
        Console.WriteLine($"После подмены HMAC верен: {isTampered}");
    }

    public static byte[] ComputeHmac(byte[] data, byte[] key)
    {
        using var hmac = new HMACSHA256(key);
        return hmac.ComputeHash(data);
    }

    public static bool VerifyHmac(byte[] data, byte[] key, byte[] expectedHmac)
    {
        byte[] actualHmac = ComputeHmac(data, key);

        // Сравнение с постоянным временем выполнения
        return CryptographicOperations.FixedTimeEquals(actualHmac, expectedHmac);
    }
}