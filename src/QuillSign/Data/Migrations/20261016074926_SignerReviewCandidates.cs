using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuillSign.Data.Migrations
{
    /// <inheritdoc />
    public partial class SignerReviewCandidates : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "SignerReviewCandidates",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EnvelopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SignerId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    AdoptionId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SourceObjectId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PdfObjectId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PdfLength = table.Column<long>(type: "bigint", nullable: false),
                    SourceSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    DisclosureSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    SessionSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    SnapshotSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    PdfSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    RecipeSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    RendererVersion = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    SnapshotVersion = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    ProspectiveDate = table.Column<DateOnly>(type: "date", nullable: false),
                    PreparedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    UsedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    SupersededAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SignerReviewCandidates", x => x.Id);
                    table.CheckConstraint("CK_SignerReviewCandidate_DisclosureSha256", "[DisclosureSha256] IS NULL OR DATALENGTH([DisclosureSha256]) = 32");
                    table.CheckConstraint("CK_SignerReviewCandidate_Expiry", "[ExpiresAt] > [PreparedAt] AND [ExpiresAt] <= DATEADD(minute,10,[PreparedAt]) AND [ProspectiveDate] = CONVERT(date,SWITCHOFFSET([PreparedAt],'+00:00')) AND [ExpiresAt] <= DATEADD(day,1,CONVERT(datetimeoffset,[ProspectiveDate]))");
                    table.CheckConstraint("CK_SignerReviewCandidate_Pdf", "[PdfLength] BETWEEN 16 AND 67108864 AND [SourceObjectId] <> [PdfObjectId]");
                    table.CheckConstraint("CK_SignerReviewCandidate_PdfSha256", "[PdfSha256] IS NULL OR DATALENGTH([PdfSha256]) = 32");
                    table.CheckConstraint("CK_SignerReviewCandidate_RecipeSha256", "[RecipeSha256] IS NULL OR DATALENGTH([RecipeSha256]) = 32");
                    table.CheckConstraint("CK_SignerReviewCandidate_SessionSha256", "[SessionSha256] IS NULL OR DATALENGTH([SessionSha256]) = 32");
                    table.CheckConstraint("CK_SignerReviewCandidate_SnapshotSha256", "[SnapshotSha256] IS NULL OR DATALENGTH([SnapshotSha256]) = 32");
                    table.CheckConstraint("CK_SignerReviewCandidate_SourceSha256", "[SourceSha256] IS NULL OR DATALENGTH([SourceSha256]) = 32");
                    table.CheckConstraint("CK_SignerReviewCandidate_State", "([UsedAt] IS NULL OR [UsedAt] >= [PreparedAt]) AND ([SupersededAt] IS NULL OR [SupersededAt] >= [PreparedAt]) AND ([UsedAt] IS NULL OR [SupersededAt] IS NULL)");
                    table.ForeignKey(
                        name: "FK_SignerReviewCandidates_Envelopes_EnvelopeId",
                        column: x => x.EnvelopeId,
                        principalTable: "Envelopes",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_SignerReviewCandidates_SignaturePreviews_EnvelopeId_SignerId_AdoptionId",
                        columns: x => new { x.EnvelopeId, x.SignerId, x.AdoptionId },
                        principalTable: "SignaturePreviews",
                        principalColumns: new[] { "EnvelopeId", "SignerId", "Id" });
                    table.ForeignKey(
                        name: "FK_SignerReviewCandidates_Signers_EnvelopeId_SignerId",
                        columns: x => new { x.EnvelopeId, x.SignerId },
                        principalTable: "Signers",
                        principalColumns: new[] { "EnvelopeId", "Id" });
                });

            migrationBuilder.CreateIndex(
                name: "IX_SignerReviewCandidates_EnvelopeId_PdfObjectId",
                table: "SignerReviewCandidates",
                columns: new[] { "EnvelopeId", "PdfObjectId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SignerReviewCandidates_EnvelopeId_SignerId_AdoptionId",
                table: "SignerReviewCandidates",
                columns: new[] { "EnvelopeId", "SignerId", "AdoptionId" });

            migrationBuilder.CreateIndex(
                name: "IX_SignerReviewCandidates_EnvelopeId_SignerId_ExpiresAt",
                table: "SignerReviewCandidates",
                columns: new[] { "EnvelopeId", "SignerId", "ExpiresAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "SignerReviewCandidates");
        }
    }
}
