using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuillSign.Data.Migrations
{
    /// <inheritdoc />
    public partial class SignerFieldAdoptionBinding : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Fields_EnvelopeId_SignerId",
                table: "Fields");

            migrationBuilder.AddColumn<byte[]>(
                name: "ImageSha256",
                table: "Fields",
                type: "varbinary(32)",
                maxLength: 32,
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "SignatureAdoptionId",
                table: "Fields",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddUniqueConstraint(
                name: "AK_SignaturePreviews_EnvelopeId_SignerId_Id",
                table: "SignaturePreviews",
                columns: new[] { "EnvelopeId", "SignerId", "Id" });

            migrationBuilder.CreateIndex(
                name: "IX_Fields_EnvelopeId_SignerId_SignatureAdoptionId",
                table: "Fields",
                columns: new[] { "EnvelopeId", "SignerId", "SignatureAdoptionId" });

            migrationBuilder.AddCheckConstraint(
                name: "CK_DocumentField_ImageSha256",
                table: "Fields",
                sql: "[ImageSha256] IS NULL OR DATALENGTH([ImageSha256]) = 32");

            migrationBuilder.AddCheckConstraint(
                name: "CK_Field_MarkBinding",
                table: "Fields",
                sql: "([SignatureAdoptionId] IS NULL AND [ImageSha256] IS NULL) OR ([SignatureAdoptionId] IS NOT NULL AND [ImageSha256] IS NOT NULL AND [Type] IN ('Signature','Initials') AND [SignerId] IS NOT NULL AND [FilledAt] IS NOT NULL AND [FilledBy] IS NOT NULL AND [FilledBy] = 'Signer' AND [Value] IS NOT NULL)");

            migrationBuilder.AddForeignKey(
                name: "FK_Fields_SignaturePreviews_EnvelopeId_SignerId_SignatureAdoptionId",
                table: "Fields",
                columns: new[] { "EnvelopeId", "SignerId", "SignatureAdoptionId" },
                principalTable: "SignaturePreviews",
                principalColumns: new[] { "EnvelopeId", "SignerId", "Id" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Fields_SignaturePreviews_EnvelopeId_SignerId_SignatureAdoptionId",
                table: "Fields");

            migrationBuilder.DropUniqueConstraint(
                name: "AK_SignaturePreviews_EnvelopeId_SignerId_Id",
                table: "SignaturePreviews");

            migrationBuilder.DropIndex(
                name: "IX_Fields_EnvelopeId_SignerId_SignatureAdoptionId",
                table: "Fields");

            migrationBuilder.DropCheckConstraint(
                name: "CK_DocumentField_ImageSha256",
                table: "Fields");

            migrationBuilder.DropCheckConstraint(
                name: "CK_Field_MarkBinding",
                table: "Fields");

            migrationBuilder.DropColumn(
                name: "ImageSha256",
                table: "Fields");

            migrationBuilder.DropColumn(
                name: "SignatureAdoptionId",
                table: "Fields");

            migrationBuilder.CreateIndex(
                name: "IX_Fields_EnvelopeId_SignerId",
                table: "Fields",
                columns: new[] { "EnvelopeId", "SignerId" });
        }
    }
}
