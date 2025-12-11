using System.Security.Cryptography;
using System.Text;

namespace CryptographyDemo.Demos;

public static class AesGcmDemo
{
    public static void Show()
    {
        Console.WriteLine("\n--- AES-GCM Аутентифицированное шифрование ---");

        // Генерация ключа и nonce
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        string originalText = "Данные с аутентификацией";

        // Шифрование
        var (ciphertext, tag) = Encrypt(Encoding.UTF8.GetBytes(originalText), key, nonce);
        Console.WriteLine($"Шифртекст: {Convert.ToBase64String(ciphertext)}");
        Console.WriteLine($"Тег аутентификации: {Convert.ToBase64String(tag)}");

        // Расшифровка и проверка
        byte[] decrypted = Decrypt(ciphertext, key, nonce, tag);
        string decryptedText = Encoding.UTF8.GetString(decrypted);
        Console.WriteLine($"Расшифровано: {decryptedText}");
        Console.WriteLine($"Совпадение: {originalText == decryptedText}");

        // Попытка подмены данных
        try
        {
            tag[0] ^= 0x01; // Изменяем тег
            Decrypt(ciphertext, key, nonce, tag);
            Console.WriteLine("ОШИБКА: Подмена не обнаружена!");
        }
        catch (CryptographicException)
        {
            Console.WriteLine("УСПЕХ: Подмена обнаружена и отклонена");
        }
    }

    public static (byte[] ciphertext, byte[] tag) Encrypt(byte[] data, byte[] key, byte[] nonce)
    {
        byte[] ciphertext = new byte[data.Length];
        byte[] tag = new byte[16];

        using var aesGcm = new AesGcm(key);
        aesGcm.Encrypt(nonce, data, ciphertext, tag);

        return (ciphertext, tag);
    }

    public static byte[] Decrypt(byte[] ciphertext, byte[] key, byte[] nonce, byte[] tag)
    {
        byte[] plaintext = new byte[ciphertext.Length];

        using var aesGcm = new AesGcm(key);
        aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);

        return plaintext;
    }
}