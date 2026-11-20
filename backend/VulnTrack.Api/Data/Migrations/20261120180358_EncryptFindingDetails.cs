using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace VulnTrack.Api.Data.Migrations
{
    /// <inheritdoc />
    public partial class EncryptFindingDetails : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // A migration has no access to the encryption key, so it can't encrypt existing descriptions.
            // Stop instead of dropping them, and leave the choice to whoever runs it.
            migrationBuilder.Sql("""
                DO $$
                BEGIN
                    IF EXISTS (SELECT 1 FROM "Findings") THEN
                        RAISE EXCEPTION 'Findings exist that this migration would make unreadable. Back them up and reset the database.';
                    END IF;
                END $$;
                """);

            migrationBuilder.DropColumn(
                name: "Description",
                table: "Findings");

            migrationBuilder.DropColumn(
                name: "ReporterEmail",
                table: "Findings");

            migrationBuilder.AddColumn<byte[]>(
                name: "EncryptedDataKey",
                table: "Findings",
                type: "bytea",
                nullable: false,
                defaultValue: new byte[0]);

            migrationBuilder.AddColumn<byte[]>(
                name: "EncryptedDescription",
                table: "Findings",
                type: "bytea",
                nullable: false,
                defaultValue: new byte[0]);

            migrationBuilder.AddColumn<byte[]>(
                name: "EncryptedReporterEmail",
                table: "Findings",
                type: "bytea",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "EncryptedDataKey",
                table: "Findings");

            migrationBuilder.DropColumn(
                name: "EncryptedDescription",
                table: "Findings");

            migrationBuilder.DropColumn(
                name: "EncryptedReporterEmail",
                table: "Findings");

            migrationBuilder.AddColumn<string>(
                name: "Description",
                table: "Findings",
                type: "character varying(8192)",
                maxLength: 8192,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "ReporterEmail",
                table: "Findings",
                type: "character varying(254)",
                maxLength: 254,
                nullable: true);
        }
    }
}
