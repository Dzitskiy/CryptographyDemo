using System.Security.Cryptography;
using System.Text;

namespace CryptographyDemo.Demos;

public static class RsaDemo
{
    public static void Show()
    {
        Console.WriteLine("\n--- RSA Шифрование/Расшифровка ---");

        // Генерация ключей
        using var rsa = RSA.Create(2048);
        string originalText = "Секретное сообщение";

        // Шифрование открытым ключом
        byte[] encrypted = rsa.Encrypt(
            Encoding.UTF8.GetBytes(originalText),
            RSAEncryptionPadding.OaepSHA256
        );
        Console.WriteLine($"Зашифровано: {Convert.ToBase64String(encrypted)}");

        // Расшифровка закрытым ключом
        byte[] decrypted = rsa.Decrypt(encrypted, RSAEncryptionPadding.OaepSHA256);
        string decryptedText = Encoding.UTF8.GetString(decrypted);
        Console.WriteLine($"Расшифровано: {decryptedText}");
        Console.WriteLine($"Совпадение: {originalText == decryptedText}");

        // Экспорт/импорт ключей
        string publicKey = rsa.ExportSubjectPublicKeyInfoPem();
        string privateKey = rsa.ExportPkcs8PrivateKeyPem();
        Console.WriteLine($"\nПубличный ключ:\n{publicKey}");
        Console.WriteLine($"\nПриватный ключ (первые 100 символов):\n{privateKey[..100]}...");
    }
}