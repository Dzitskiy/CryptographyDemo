using System.Security.Cryptography;
using System.Text;

namespace CryptographyDemo.Demos;

public static class CombinedDemo
{
    public static void Show()
    {
        Console.WriteLine("\n--- Комбинированный пример: Шифрование с проверкой целостности ---");

        // Исходные данные
        string sensitiveData = "Очень секретные данные: пароль 12345";
        byte[] dataBytes = Encoding.UTF8.GetBytes(sensitiveData);

        // 1. Генерация ключей
        byte[] aesKey = new byte[32]; // AES-256
        byte[] hmacKey = new byte[32]; // HMAC-SHA256
        RandomNumberGenerator.Fill(aesKey);
        RandomNumberGenerator.Fill(hmacKey);

        // 2. Шифрование данных
        using var aes = Aes.Create();
        aes.Key = aesKey;
        aes.GenerateIV();
        aes.Mode = CipherMode.CBC;

        byte[] encryptedData;
        using (var encryptor = aes.CreateEncryptor())
        {
            encryptedData = encryptor.TransformFinalBlock(dataBytes, 0, dataBytes.Length);
        }

        // 3. Создание HMAC для проверки целостности
        byte[] dataToAuthenticate = aes.IV.Concat(encryptedData).ToArray();
        byte[] hmac;
        using (var hmacAlg = new HMACSHA256(hmacKey))
        {
            hmac = hmacAlg.ComputeHash(dataToAuthenticate);
        }

        Console.WriteLine($"Данные зашифрованы и аутентифицированы");
        Console.WriteLine($"IV: {Convert.ToBase64String(aes.IV)}");
        Console.WriteLine($"HMAC: {Convert.ToBase64String(hmac)}");

        // 4. Проверка целостности и расшифровка
        bool integrityValid = VerifyIntegrity(aes.IV, encryptedData, hmacKey, hmac);
        Console.WriteLine($"Целостность данных: {(integrityValid ? "OK" : "НАРУШЕНА")}");

        if (integrityValid)
        {
            byte[] decryptedData = DecryptWithIntegrityCheck(
                encryptedData, aesKey, aes.IV, hmacKey, hmac
            );
            string decryptedText = Encoding.UTF8.GetString(decryptedData);
            Console.WriteLine($"Расшифрованные данные: {decryptedText}");
            Console.WriteLine($"Совпадение: {sensitiveData == decryptedText}");
        }

        // 5. Демонстрация обнаружения подмены
        Console.WriteLine("\n--- Тест обнаружения подмены ---");
        encryptedData[0] ^= 0x01; // Изменяем шифртекст

        bool tamperedIntegrity = VerifyIntegrity(aes.IV, encryptedData, hmacKey, hmac);
        Console.WriteLine($"Целостность после подмены: {(tamperedIntegrity ? "OK" : "НАРУШЕНА")}");

        if (tamperedIntegrity)
        {
            try
            {
                DecryptWithIntegrityCheck(encryptedData, aesKey, aes.IV, hmacKey, hmac);
            }
            catch (CryptographicException ex)
            {
                Console.WriteLine($"Расшифровка отклонена: {ex.Message}");
            }
        }
    }

    private static bool VerifyIntegrity(byte[] iv, byte[] ciphertext, byte[] hmacKey, byte[] expectedHmac)
    {
        byte[] dataToAuthenticate = iv.Concat(ciphertext).ToArray();
        using var hmacAlg = new HMACSHA256(hmacKey);
        byte[] computedHmac = hmacAlg.ComputeHash(dataToAuthenticate);

        return CryptographicOperations.FixedTimeEquals(computedHmac, expectedHmac);
    }

    private static byte[] DecryptWithIntegrityCheck(
        byte[] ciphertext, byte[] aesKey, byte[] iv, byte[] hmacKey, byte[] expectedHmac)
    {
        // Сначала проверяем целостность
        if (!VerifyIntegrity(iv, ciphertext, hmacKey, expectedHmac))
        {
            throw new CryptographicException("Целостность данных нарушена");
        }

        // Затем расшифровываем
        using var aes = Aes.Create();
        aes.Key = aesKey;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;

        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
    }
}