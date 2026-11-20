using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace VulnTrack.Api.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddAssignment : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "AssigneeId",
                table: "Findings",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AssigneeName",
                table: "Findings",
                type: "character varying(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<DateOnly>(
                name: "DueDate",
                table: "Findings",
                type: "date",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AssigneeId",
                table: "Findings");

            migrationBuilder.DropColumn(
                name: "AssigneeName",
                table: "Findings");

            migrationBuilder.DropColumn(
                name: "DueDate",
                table: "Findings");
        }
    }
}
