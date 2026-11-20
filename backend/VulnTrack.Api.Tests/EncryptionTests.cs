using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using VulnTrack.Api.Data;
using VulnTrack.Api.Findings;
using VulnTrack.Api.Security;

namespace VulnTrack.Api.Tests;

public sealed class FieldEncryptionTests
{
    private static FieldEncryption NewEncryption() =>
        new(Options.Create(new EncryptionOptions { Key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) }));

    [Fact]
    public void Decrypt_ReturnsTheOriginalText()
    {
        var encryption = NewEncryption();
        var owner = Guid.NewGuid();
        var dataKey = encryption.NewDataKey(owner);

        var ciphertext = encryption.Encrypt(dataKey, owner, "Description", "Ærø 🐛 steps");

        Assert.Equal("Ærø 🐛 steps", encryption.Decrypt(dataKey, owner, "Description", ciphertext));
    }

    [Fact]
    public void SameText_GivesDifferentCiphertextEachTime()
    {
        var encryption = NewEncryption();
        var owner = Guid.NewGuid();
        var dataKey = encryption.NewDataKey(owner);

        var first = encryption.Encrypt(dataKey, owner, "Description", "same text");
        var second = encryption.Encrypt(dataKey, owner, "Description", "same text");

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void ChangedCiphertext_FailsToDecrypt()
    {
        var encryption = NewEncryption();
        var owner = Guid.NewGuid();
        var dataKey = encryption.NewDataKey(owner);
        var ciphertext = encryption.Encrypt(dataKey, owner, "Description", "original");

        ciphertext[^1] ^= 1;

        Assert.ThrowsAny<CryptographicException>(() => encryption.Decrypt(dataKey, owner, "Description", ciphertext));
    }

    [Fact]
    public void CiphertextOfAnotherOwnerOrField_FailsToDecrypt()
    {
        var encryption = NewEncryption();
        var owner = Guid.NewGuid();
        var dataKey = encryption.NewDataKey(owner);
        var ciphertext = encryption.Encrypt(dataKey, owner, "Description", "original");

        Assert.ThrowsAny<CryptographicException>(() => encryption.Decrypt(dataKey, owner, "ReporterEmail", ciphertext));
        Assert.ThrowsAny<CryptographicException>(() => encryption.Decrypt(dataKey, Guid.NewGuid(), "Description", ciphertext));
    }

    [Fact]
    public void AnotherMasterKey_CannotOpenTheDataKey()
    {
        var owner = Guid.NewGuid();
        var dataKey = NewEncryption().NewDataKey(owner);

        Assert.ThrowsAny<CryptographicException>(() => NewEncryption().Encrypt(dataKey, owner, "Description", "text"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("change-me")]
    [InlineData("c2hvcnQ=")]
    public void IsValidKey_RejectsMissingMalformedOrShortKeys(string? key)
    {
        Assert.False(FieldEncryption.IsValidKey(key));
    }

    [Fact]
    public void IsValidKey_AcceptsThirtyTwoBytes()
    {
        Assert.True(FieldEncryption.IsValidKey(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))));
    }
}

public sealed class FindingEncryptionTests(PostgresFactory factory) : IClassFixture<PostgresFactory>
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
    };

    private HttpClient Analyst => factory.CreateClientAs("alice", "analyst");

    private async Task<Guid> ReportAsync(string description, string email)
    {
        var response = await factory.CreateAnonymousClient($"10.7.0.{Random.Shared.Next(1, 250)}").PostAsJsonAsync("/api/reports", new
        {
            title = "Encrypted report",
            description,
            affectedAsset = "web",
            severity = "High",
            reporterEmail = email,
        }, Ct);
        return (await response.Content.ReadFromJsonAsync<ReportReceipt>(Ct))!.Reference;
    }

    private async Task<string> RawRowAsync(Guid id)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        return await db.Database
            .SqlQuery<string>($"""SELECT row_to_json(f)::text AS "Value" FROM "Findings" AS f WHERE f."Id" = {id}""")
            .SingleAsync(Ct);
    }

    private async Task<byte[]> StoredDescriptionAsync(Guid id)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        return await db.Database
            .SqlQuery<byte[]>($"""SELECT "EncryptedDescription" AS "Value" FROM "Findings" WHERE "Id" = {id}""")
            .SingleAsync(Ct);
    }

    [Fact]
    public async Task DatabaseHoldsNoPlainTextDescriptionOrEmail()
    {
        var id = await ReportAsync("Plain text repro steps", "plain.reporter@example.com");

        var row = await RawRowAsync(id);

        foreach (var secret in new[] { "Plain text repro steps", "plain.reporter@example.com" })
        {
            Assert.DoesNotContain(secret, row);
            Assert.DoesNotContain(Convert.ToHexString(Encoding.UTF8.GetBytes(secret)), row, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task Api_ReturnsTheDecryptedValues()
    {
        var id = await ReportAsync("Readable through the API", "api.reporter@example.com");

        var finding = await Analyst.GetFromJsonAsync<FindingResponse>($"/api/findings/{id}", Json, Ct);
        var inList = (await Analyst.GetFromJsonAsync<List<FindingResponse>>("/api/findings", Json, Ct))!.Single(f => f.Id == id);

        Assert.Equal("Readable through the API", finding!.Description);
        Assert.Equal("api.reporter@example.com", finding.ReporterEmail);
        Assert.Equal("Readable through the API", inList.Description);
    }

    [Fact]
    public async Task StatusChange_KeepsTheStoredDescription_ButAnEditEncryptsItAgain()
    {
        var id = await ReportAsync("Stays the same", "same@example.com");
        var original = await StoredDescriptionAsync(id);

        await Analyst.PutAsJsonAsync($"/api/findings/{id}/status", new { status = "Triaged" }, Ct);
        var afterStatus = await StoredDescriptionAsync(id);
        await Analyst.PutAsJsonAsync($"/api/findings/{id}", new { title = "Encrypted report", description = "Edited", affectedAsset = "web", severity = "High" }, Ct);
        var afterEdit = await StoredDescriptionAsync(id);

        Assert.Equal(original, afterStatus);
        Assert.NotEqual(original, afterEdit);
        Assert.Equal("Edited", (await Analyst.GetFromJsonAsync<FindingResponse>($"/api/findings/{id}", Json, Ct))!.Description);
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;
}

// Its own class, and so its own database, because the broken row would make every list of findings fail.
public sealed class TamperedFindingTests(PostgresFactory factory) : IClassFixture<PostgresFactory>
{
    private async Task<Guid> ReportAsync(string description, string email)
    {
        var response = await factory.CreateAnonymousClient($"10.6.0.{Random.Shared.Next(1, 250)}").PostAsJsonAsync("/api/reports", new
        {
            title = "Encrypted report",
            description,
            affectedAsset = "web",
            severity = "High",
            reporterEmail = email,
        }, Ct);
        return (await response.Content.ReadFromJsonAsync<ReportReceipt>(Ct))!.Reference;
    }

    [Fact]
    public async Task CiphertextCopiedFromAnotherFinding_FailsToLoad()
    {
        var victim = await ReportAsync("Victim description", "victim@example.com");
        var other = await ReportAsync("Other description", "other@example.com");

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await db.Database.ExecuteSqlAsync(
            $"""UPDATE "Findings" SET "EncryptedDescription" = (SELECT "EncryptedDescription" FROM "Findings" WHERE "Id" = {other}) WHERE "Id" = {victim}""",
            Ct);

        await Assert.ThrowsAnyAsync<CryptographicException>(() => db.Findings.SingleAsync(f => f.Id == victim, Ct));
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;
}
public sealed class EncryptionKeyStartupTests
{
    private sealed class FactoryWithKey(string key) : VulnTrackFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.UseSetting("Encryption:Key", key);
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("change-me")]
    [InlineData("c2hvcnQ=")]
    public void AppDoesNotStart_WithoutAValidKey(string key)
    {
        using var factory = new FactoryWithKey(key);

        var error = Assert.Throws<OptionsValidationException>(() => factory.CreateClient());
        Assert.Contains(FieldEncryption.InvalidKeyMessage, error.Message);
    }
}
