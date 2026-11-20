using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace VulnTrack.Api.Security;

public sealed class EncryptionOptions
{
    // The master key: 32 random bytes, base64 encoded. It comes from a Docker secret and is never stored in the database.
    public string? Key { get; set; }
}

// Envelope encryption with AES-256-GCM. Every owner (a finding) gets its own random data key, which encrypts
// its fields. The data key itself is stored encrypted with the master key, so the master key never touches the
// data, and it can be replaced by encrypting the small data keys again.
//
// Every encryption uses a new random nonce, and GCM's tag makes changed ciphertext fail instead of decrypting
// to something else. The owner id and field name are bound to the ciphertext as associated data, so ciphertext
// copied to another finding or another field doesn't decrypt either.
public sealed class FieldEncryption(IOptions<EncryptionOptions> options)
{
    public const string InvalidKeyMessage =
        "Encryption:Key must be 32 random bytes, base64 encoded. Generate one with: openssl rand -base64 32";

    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    // Stored first in every ciphertext, so the format can change later without guessing.
    private const byte FormatVersion = 1;
    private const int HeaderSize = 1 + NonceSize + TagSize;

    private readonly byte[] _masterKey = Convert.FromBase64String(options.Value.Key!);

    public static bool IsValidKey(string? key)
    {
        if (string.IsNullOrWhiteSpace(key)) return false;
        var bytes = new byte[key.Length];
        return Convert.TryFromBase64String(key, bytes, out var length) && length == KeySize;
    }

    public byte[] NewDataKey(Guid ownerId)
    {
        var dataKey = RandomNumberGenerator.GetBytes(KeySize);
        try
        {
            return Seal(_masterKey, dataKey, KeyContext(ownerId));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dataKey);
        }
    }

    public byte[] Encrypt(byte[] encryptedDataKey, Guid ownerId, string field, string plaintext)
    {
        var dataKey = Open(_masterKey, encryptedDataKey, KeyContext(ownerId));
        try
        {
            return Seal(dataKey, Encoding.UTF8.GetBytes(plaintext), FieldContext(ownerId, field));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dataKey);
        }
    }

    public string Decrypt(byte[] encryptedDataKey, Guid ownerId, string field, byte[] ciphertext)
    {
        var dataKey = Open(_masterKey, encryptedDataKey, KeyContext(ownerId));
        try
        {
            return Encoding.UTF8.GetString(Open(dataKey, ciphertext, FieldContext(ownerId, field)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dataKey);
        }
    }

    private static byte[] KeyContext(Guid ownerId) => Encoding.UTF8.GetBytes($"vulntrack:key:{ownerId}");

    private static byte[] FieldContext(Guid ownerId, string field) => Encoding.UTF8.GetBytes($"vulntrack:field:{ownerId}:{field}");

    // Layout: version (1 byte) | nonce (12) | tag (16) | ciphertext.
    private static byte[] Seal(byte[] key, byte[] plaintext, byte[] associatedData)
    {
        var output = new byte[HeaderSize + plaintext.Length];
        output[0] = FormatVersion;
        var nonce = output.AsSpan(1, NonceSize);
        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, output.AsSpan(HeaderSize), output.AsSpan(1 + NonceSize, TagSize), associatedData);
        return output;
    }

    private static byte[] Open(byte[] key, byte[] sealedData, byte[] associatedData)
    {
        if (sealedData.Length < HeaderSize || sealedData[0] != FormatVersion)
        {
            throw new CryptographicException("The ciphertext has an unknown format.");
        }

        var plaintext = new byte[sealedData.Length - HeaderSize];
        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(
            sealedData.AsSpan(1, NonceSize),
            sealedData.AsSpan(HeaderSize),
            sealedData.AsSpan(1 + NonceSize, TagSize),
            plaintext,
            associatedData);
        return plaintext;
    }
}
