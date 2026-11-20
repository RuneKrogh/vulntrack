using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using VulnTrack.Api.Security;

namespace VulnTrack.Api.Findings;

// Encrypts a finding's description and reporter email when it's saved, and decrypts them when it's loaded.
// The endpoints only ever see the plain text, and the database only ever sees the ciphertext.
public static class FindingEncryption
{
    public static void EncryptForSave(Finding finding, EntityState state, FieldEncryption encryption)
    {
        if (state == EntityState.Added)
        {
            finding.EncryptedDataKey = encryption.NewDataKey(finding.Id);
            if (finding.ReporterEmail is not null)
            {
                finding.EncryptedReporterEmail =
                    encryption.Encrypt(finding.EncryptedDataKey, finding.Id, nameof(Finding.ReporterEmail), finding.ReporterEmail);
            }
        }

        // A new nonce gives new ciphertext every time, so an unchanged description isn't encrypted again.
        // Otherwise every save would look like an edit of the description.
        if (finding.Description != finding.StoredDescription)
        {
            finding.EncryptedDescription =
                encryption.Encrypt(finding.EncryptedDataKey, finding.Id, nameof(Finding.Description), finding.Description);
            finding.StoredDescription = finding.Description;
        }
    }
}

public sealed class FindingDecryption(FieldEncryption encryption) : IMaterializationInterceptor
{
    public object InitializedInstance(MaterializationInterceptionData materializationData, object entity)
    {
        if (entity is Finding finding)
        {
            finding.Description = encryption.Decrypt(
                finding.EncryptedDataKey, finding.Id, nameof(Finding.Description), finding.EncryptedDescription);
            finding.StoredDescription = finding.Description;
            if (finding.EncryptedReporterEmail is not null)
            {
                finding.ReporterEmail = encryption.Decrypt(
                    finding.EncryptedDataKey, finding.Id, nameof(Finding.ReporterEmail), finding.EncryptedReporterEmail);
            }
        }

        return entity;
    }
}
