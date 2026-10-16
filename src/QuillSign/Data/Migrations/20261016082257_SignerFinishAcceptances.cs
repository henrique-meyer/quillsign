using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuillSign.Data.Migrations
{
    /// <inheritdoc />
    public partial class SignerFinishAcceptances : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddUniqueConstraint(
                name: "AK_SignerReviewCandidates_EnvelopeId_SignerId_Id",
                table: "SignerReviewCandidates",
                columns: new[] { "EnvelopeId", "SignerId", "Id" });

            migrationBuilder.CreateTable(
                name: "SignerFinishAcceptances",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EnvelopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SignerId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ReviewCandidateId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
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
                    FieldsSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    StatementSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    FieldsJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    SnapshotVersion = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    StatementVersion = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    Statement = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    ProspectiveDate = table.Column<DateOnly>(type: "date", nullable: false),
                    ReviewPreparedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    ReviewExpiresAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    FinishedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    Ip = table.Column<string>(type: "nvarchar(45)", maxLength: 45, nullable: true),
                    UserAgent = table.Column<string>(type: "nvarchar(2048)", maxLength: 2048, nullable: true),
                    ProcessedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SignerFinishAcceptances", x => x.Id);
                    table.CheckConstraint("CK_SignerFinishAcceptance_DisclosureSha256", "[DisclosureSha256] IS NULL OR DATALENGTH([DisclosureSha256]) = 32");
                    table.CheckConstraint("CK_SignerFinishAcceptance_Fields", "ISJSON([FieldsJson]) = 1 AND DATALENGTH([FieldsJson]) BETWEEN 2 AND 16777216");
                    table.CheckConstraint("CK_SignerFinishAcceptance_FieldsJson", "[FieldsJson] IS NULL OR ISJSON([FieldsJson]) = 1");
                    table.CheckConstraint("CK_SignerFinishAcceptance_FieldsSha256", "[FieldsSha256] IS NULL OR DATALENGTH([FieldsSha256]) = 32");
                    table.CheckConstraint("CK_SignerFinishAcceptance_Pdf", "[PdfLength] BETWEEN 16 AND 67108864 AND [SourceObjectId] <> [PdfObjectId]");
                    table.CheckConstraint("CK_SignerFinishAcceptance_PdfSha256", "[PdfSha256] IS NULL OR DATALENGTH([PdfSha256]) = 32");
                    table.CheckConstraint("CK_SignerFinishAcceptance_RecipeSha256", "[RecipeSha256] IS NULL OR DATALENGTH([RecipeSha256]) = 32");
                    table.CheckConstraint("CK_SignerFinishAcceptance_SessionSha256", "[SessionSha256] IS NULL OR DATALENGTH([SessionSha256]) = 32");
                    table.CheckConstraint("CK_SignerFinishAcceptance_SnapshotSha256", "[SnapshotSha256] IS NULL OR DATALENGTH([SnapshotSha256]) = 32");
                    table.CheckConstraint("CK_SignerFinishAcceptance_SourceSha256", "[SourceSha256] IS NULL OR DATALENGTH([SourceSha256]) = 32");
                    table.CheckConstraint("CK_SignerFinishAcceptance_StatementSha256", "[StatementSha256] IS NULL OR DATALENGTH([StatementSha256]) = 32");
                    table.CheckConstraint("CK_SignerFinishAcceptance_Time", "[FinishedAt] >= [ReviewPreparedAt] AND [FinishedAt] < [ReviewExpiresAt] AND [ReviewExpiresAt] <= DATEADD(minute,10,[ReviewPreparedAt]) AND [ProspectiveDate] = CONVERT(date,SWITCHOFFSET([FinishedAt],'+00:00')) AND [ProspectiveDate] = CONVERT(date,SWITCHOFFSET([ReviewPreparedAt],'+00:00')) AND ([ProcessedAt] IS NULL OR [ProcessedAt] >= [FinishedAt])");
                    table.ForeignKey(
                        name: "FK_SignerFinishAcceptances_Envelopes_EnvelopeId",
                        column: x => x.EnvelopeId,
                        principalTable: "Envelopes",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_SignerFinishAcceptances_SignerReviewCandidates_EnvelopeId_SignerId_ReviewCandidateId",
                        columns: x => new { x.EnvelopeId, x.SignerId, x.ReviewCandidateId },
                        principalTable: "SignerReviewCandidates",
                        principalColumns: new[] { "EnvelopeId", "SignerId", "Id" });
                    table.ForeignKey(
                        name: "FK_SignerFinishAcceptances_Signers_EnvelopeId_SignerId",
                        columns: x => new { x.EnvelopeId, x.SignerId },
                        principalTable: "Signers",
                        principalColumns: new[] { "EnvelopeId", "Id" });
                });

            migrationBuilder.CreateIndex(
                name: "IX_SignerFinishAcceptances_EnvelopeId_SignerId",
                table: "SignerFinishAcceptances",
                columns: new[] { "EnvelopeId", "SignerId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SignerFinishAcceptances_EnvelopeId_SignerId_ReviewCandidateId",
                table: "SignerFinishAcceptances",
                columns: new[] { "EnvelopeId", "SignerId", "ReviewCandidateId" });

            migrationBuilder.CreateIndex(
                name: "IX_SignerFinishAcceptances_ProcessedAt_FinishedAt",
                table: "SignerFinishAcceptances",
                columns: new[] { "ProcessedAt", "FinishedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_SignerFinishAcceptances_ReviewCandidateId",
                table: "SignerFinishAcceptances",
                column: "ReviewCandidateId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "SignerFinishAcceptances");

            migrationBuilder.DropUniqueConstraint(
                name: "AK_SignerReviewCandidates_EnvelopeId_SignerId_Id",
                table: "SignerReviewCandidates");
        }
    }
}
