using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuillSign.Data.Migrations
{
    /// <inheritdoc />
    public partial class CompletionCandidates : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "CompletionCandidates",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EnvelopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    FinishId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CopyVersion = table.Column<int>(type: "int", nullable: false),
                    SourceObjectId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SourceSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    PdfObjectId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PdfLength = table.Column<long>(type: "bigint", nullable: false),
                    PdfSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    DocumentPages = table.Column<int>(type: "int", nullable: false),
                    CertificatePages = table.Column<int>(type: "int", nullable: false),
                    GeometryJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    EvidenceJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    EvidenceSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    FrozenStateSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    AuditSequence = table.Column<long>(type: "bigint", nullable: false),
                    AuditAnchor = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    RecipeSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    RendererVersion = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    SnapshotVersion = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    PreparedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CompletionCandidates", x => x.Id);
                    table.CheckConstraint("CK_CompletionCandidate_AuditAnchor", "[AuditAnchor] IS NULL OR DATALENGTH([AuditAnchor]) = 32");
                    table.CheckConstraint("CK_CompletionCandidate_EvidenceJson", "[EvidenceJson] IS NULL OR ISJSON([EvidenceJson]) = 1");
                    table.CheckConstraint("CK_CompletionCandidate_EvidenceSha256", "[EvidenceSha256] IS NULL OR DATALENGTH([EvidenceSha256]) = 32");
                    table.CheckConstraint("CK_CompletionCandidate_FrozenStateSha256", "[FrozenStateSha256] IS NULL OR DATALENGTH([FrozenStateSha256]) = 32");
                    table.CheckConstraint("CK_CompletionCandidate_GeometryJson", "[GeometryJson] IS NULL OR ISJSON([GeometryJson]) = 1");
                    table.CheckConstraint("CK_CompletionCandidate_Pdf", "[PdfLength] BETWEEN 16 AND 67108864 AND [PdfObjectId] <> [SourceObjectId] AND [DocumentPages] >= 1 AND [CertificatePages] BETWEEN 1 AND 64 AND [DocumentPages] + [CertificatePages] <= 200");
                    table.CheckConstraint("CK_CompletionCandidate_PdfSha256", "[PdfSha256] IS NULL OR DATALENGTH([PdfSha256]) = 32");
                    table.CheckConstraint("CK_CompletionCandidate_RecipeSha256", "[RecipeSha256] IS NULL OR DATALENGTH([RecipeSha256]) = 32");
                    table.CheckConstraint("CK_CompletionCandidate_Snapshot", "[CopyVersion] BETWEEN 1 AND 20 AND [AuditSequence] BETWEEN 1 AND 512 AND DATALENGTH([GeometryJson]) BETWEEN 2 AND 131072 AND DATALENGTH([EvidenceJson]) BETWEEN 2 AND 67108864");
                    table.CheckConstraint("CK_CompletionCandidate_SourceSha256", "[SourceSha256] IS NULL OR DATALENGTH([SourceSha256]) = 32");
                    table.ForeignKey(
                        name: "FK_CompletionCandidates_Envelopes_EnvelopeId",
                        column: x => x.EnvelopeId,
                        principalTable: "Envelopes",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_CompletionCandidates_SignerFinishAcceptances_EnvelopeId_FinishId",
                        columns: x => new { x.EnvelopeId, x.FinishId },
                        principalTable: "SignerFinishAcceptances",
                        principalColumns: new[] { "EnvelopeId", "Id" });
                });

            migrationBuilder.CreateIndex(
                name: "IX_CompletionCandidates_EnvelopeId",
                table: "CompletionCandidates",
                column: "EnvelopeId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CompletionCandidates_EnvelopeId_FinishId",
                table: "CompletionCandidates",
                columns: new[] { "EnvelopeId", "FinishId" });

            migrationBuilder.CreateIndex(
                name: "IX_CompletionCandidates_EnvelopeId_PdfObjectId",
                table: "CompletionCandidates",
                columns: new[] { "EnvelopeId", "PdfObjectId" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CompletionCandidates");
        }
    }
}
