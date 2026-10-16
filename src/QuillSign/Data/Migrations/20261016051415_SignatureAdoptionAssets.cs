using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuillSign.Data.Migrations
{
    /// <inheritdoc />
    public partial class SignatureAdoptionAssets : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<byte[]>(
                name: "InitialsImageSha256",
                table: "Signers",
                type: "varbinary(32)",
                maxLength: 32,
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "SignatureAdoptedAt",
                table: "Signers",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "SignatureAdoptionId",
                table: "Signers",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SignatureAdoptionVersion",
                table: "Signers",
                type: "nvarchar(512)",
                maxLength: 512,
                nullable: true);

            migrationBuilder.AddColumn<byte[]>(
                name: "SignatureImageSha256",
                table: "Signers",
                type: "varbinary(32)",
                maxLength: 32,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SignatureNormalizationVersion",
                table: "Signers",
                type: "nvarchar(512)",
                maxLength: 512,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SignatureTypedInitials",
                table: "Signers",
                type: "nvarchar(512)",
                maxLength: 512,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SignatureTypedName",
                table: "Signers",
                type: "nvarchar(512)",
                maxLength: 512,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "SignaturePreviews",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EnvelopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SignerId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    DocumentId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SignatureObjectId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    InitialsObjectId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SignatureSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    InitialsSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    DocumentSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    DisclosureSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    SessionSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    BaselineSignerVersion = table.Column<byte[]>(type: "varbinary(8)", maxLength: 8, nullable: false),
                    SignatureWidth = table.Column<int>(type: "int", nullable: false),
                    SignatureHeight = table.Column<int>(type: "int", nullable: false),
                    InitialsWidth = table.Column<int>(type: "int", nullable: false),
                    InitialsHeight = table.Column<int>(type: "int", nullable: false),
                    Method = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    TypedName = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    TypedInitials = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    NormalizationVersion = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    AdoptionVersion = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    UsedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SignaturePreviews", x => x.Id);
                    table.CheckConstraint("CK_SignaturePreview_BaselineSignerVersion", "[BaselineSignerVersion] IS NULL OR DATALENGTH([BaselineSignerVersion]) = 8");
                    table.CheckConstraint("CK_SignaturePreview_Dimensions", "[SignatureWidth] BETWEEN 1 AND 2048 AND [InitialsWidth] BETWEEN 1 AND 2048 AND [SignatureHeight] BETWEEN 1 AND 1024 AND [InitialsHeight] BETWEEN 1 AND 1024");
                    table.CheckConstraint("CK_SignaturePreview_DisclosureSha256", "[DisclosureSha256] IS NULL OR DATALENGTH([DisclosureSha256]) = 32");
                    table.CheckConstraint("CK_SignaturePreview_DocumentSha256", "[DocumentSha256] IS NULL OR DATALENGTH([DocumentSha256]) = 32");
                    table.CheckConstraint("CK_SignaturePreview_Expiry", "[ExpiresAt] > [CreatedAt] AND ([UsedAt] IS NULL OR [UsedAt] >= [CreatedAt])");
                    table.CheckConstraint("CK_SignaturePreview_InitialsSha256", "[InitialsSha256] IS NULL OR DATALENGTH([InitialsSha256]) = 32");
                    table.CheckConstraint("CK_SignaturePreview_Method", "[Method] IS NULL OR [Method] IN ('Typed','Drawn','Uploaded')");
                    table.CheckConstraint("CK_SignaturePreview_SessionSha256", "[SessionSha256] IS NULL OR DATALENGTH([SessionSha256]) = 32");
                    table.CheckConstraint("CK_SignaturePreview_SignatureSha256", "[SignatureSha256] IS NULL OR DATALENGTH([SignatureSha256]) = 32");
                    table.ForeignKey(
                        name: "FK_SignaturePreviews_Envelopes_EnvelopeId",
                        column: x => x.EnvelopeId,
                        principalTable: "Envelopes",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_SignaturePreviews_Signers_EnvelopeId_SignerId",
                        columns: x => new { x.EnvelopeId, x.SignerId },
                        principalTable: "Signers",
                        principalColumns: new[] { "EnvelopeId", "Id" });
                });

            migrationBuilder.AddCheckConstraint(
                name: "CK_Signer_InitialsImageSha256",
                table: "Signers",
                sql: "[InitialsImageSha256] IS NULL OR DATALENGTH([InitialsImageSha256]) = 32");

            migrationBuilder.AddCheckConstraint(
                name: "CK_Signer_SignatureImageSha256",
                table: "Signers",
                sql: "[SignatureImageSha256] IS NULL OR DATALENGTH([SignatureImageSha256]) = 32");

            migrationBuilder.CreateIndex(
                name: "IX_SignaturePreviews_EnvelopeId_SignerId_ExpiresAt",
                table: "SignaturePreviews",
                columns: new[] { "EnvelopeId", "SignerId", "ExpiresAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "SignaturePreviews");

            migrationBuilder.DropCheckConstraint(
                name: "CK_Signer_InitialsImageSha256",
                table: "Signers");

            migrationBuilder.DropCheckConstraint(
                name: "CK_Signer_SignatureImageSha256",
                table: "Signers");

            migrationBuilder.DropColumn(
                name: "InitialsImageSha256",
                table: "Signers");

            migrationBuilder.DropColumn(
                name: "SignatureAdoptedAt",
                table: "Signers");

            migrationBuilder.DropColumn(
                name: "SignatureAdoptionId",
                table: "Signers");

            migrationBuilder.DropColumn(
                name: "SignatureAdoptionVersion",
                table: "Signers");

            migrationBuilder.DropColumn(
                name: "SignatureImageSha256",
                table: "Signers");

            migrationBuilder.DropColumn(
                name: "SignatureNormalizationVersion",
                table: "Signers");

            migrationBuilder.DropColumn(
                name: "SignatureTypedInitials",
                table: "Signers");

            migrationBuilder.DropColumn(
                name: "SignatureTypedName",
                table: "Signers");
        }
    }
}
