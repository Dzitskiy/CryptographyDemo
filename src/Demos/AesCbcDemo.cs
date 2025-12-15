using System.Security.Cryptography;
using System.Text;

namespace CryptographyDemo.Demos;

public static class AesCbcDemo
{
    public static void Show()
    {
        Console.WriteLine("\n--- AES-CBC Шифрование ---");

        // Генерация ключа и IV
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();
        aes.GenerateIV();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        byte[] key = aes.Key;
        byte[] iv = aes.IV;
        string originalText = "Конфиденциальные данные для шифрования";

        // Шифрование
        byte[] encrypted = Encrypt(Encoding.UTF8.GetBytes(originalText), key, iv);
        Console.WriteLine($"Зашифровано: {Convert.ToBase64String(encrypted)}");

        // Расшифровка
        byte[] decrypted = Decrypt(encrypted, key, iv);
        string decryptedText = Encoding.UTF8.GetString(decrypted);
        Console.WriteLine($"Расшифровано: {decryptedText}");
        Console.WriteLine($"Совпадение: {originalText == decryptedText}");
    }

    public static byte[] Encrypt(byte[] data, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var encryptor = aes.CreateEncryptor();
        return encryptor.TransformFinalBlock(data, 0, data.Length);
    }

    public static byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(data, 0, data.Length);
    }
}