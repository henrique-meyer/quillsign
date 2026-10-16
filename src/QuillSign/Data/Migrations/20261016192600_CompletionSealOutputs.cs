using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuillSign.Data.Migrations
{
    /// <inheritdoc />
    public partial class CompletionSealOutputs : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddUniqueConstraint(
                name: "AK_CompletionCandidates_EnvelopeId_Id",
                table: "CompletionCandidates",
                columns: new[] { "EnvelopeId", "Id" });

            migrationBuilder.CreateTable(
                name: "CompletionSealOutputs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EnvelopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CandidateId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Kind = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    SourceObjectId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SourceLength = table.Column<long>(type: "bigint", nullable: false),
                    SourceSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    PdfObjectId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PdfLength = table.Column<long>(type: "bigint", nullable: false),
                    PdfSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    PageCount = table.Column<int>(type: "int", nullable: false),
                    EvidenceSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    CandidateRecipeSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    ExecutedSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: true),
                    MetadataJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    RecipeVersion = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    RecipeSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CompletionSealOutputs", x => x.Id);
                    table.CheckConstraint("CK_CompletionSealOutput_CandidateRecipeSha256", "[CandidateRecipeSha256] IS NULL OR DATALENGTH([CandidateRecipeSha256]) = 32");
                    table.CheckConstraint("CK_CompletionSealOutput_EvidenceSha256", "[EvidenceSha256] IS NULL OR DATALENGTH([EvidenceSha256]) = 32");
                    table.CheckConstraint("CK_CompletionSealOutput_ExecutedSha256", "[ExecutedSha256] IS NULL OR DATALENGTH([ExecutedSha256]) = 32");
                    table.CheckConstraint("CK_CompletionSealOutput_Kind", "[Kind] IS NULL OR [Kind] IN ('Executed','Certificate')");
                    table.CheckConstraint("CK_CompletionSealOutput_Metadata", "DATALENGTH([MetadataJson]) BETWEEN 2 AND 262144 AND (([Kind]='Executed' AND [ExecutedSha256] IS NULL) OR ([Kind]='Certificate' AND [ExecutedSha256] IS NOT NULL))");
                    table.CheckConstraint("CK_CompletionSealOutput_MetadataJson", "[MetadataJson] IS NULL OR ISJSON([MetadataJson]) = 1");
                    table.CheckConstraint("CK_CompletionSealOutput_Pdf", "[SourceLength] BETWEEN 16 AND 67108864 AND [PdfLength] BETWEEN 16 AND 67108864 AND [SourceObjectId] <> [PdfObjectId] AND [PageCount] BETWEEN 1 AND 200");
                    table.CheckConstraint("CK_CompletionSealOutput_PdfSha256", "[PdfSha256] IS NULL OR DATALENGTH([PdfSha256]) = 32");
                    table.CheckConstraint("CK_CompletionSealOutput_RecipeSha256", "[RecipeSha256] IS NULL OR DATALENGTH([RecipeSha256]) = 32");
                    table.CheckConstraint("CK_CompletionSealOutput_SourceSha256", "[SourceSha256] IS NULL OR DATALENGTH([SourceSha256]) = 32");
                    table.ForeignKey(
                        name: "FK_CompletionSealOutputs_CompletionCandidates_EnvelopeId_CandidateId",
                        columns: x => new { x.EnvelopeId, x.CandidateId },
                        principalTable: "CompletionCandidates",
                        principalColumns: new[] { "EnvelopeId", "Id" });
                    table.ForeignKey(
                        name: "FK_CompletionSealOutputs_Envelopes_EnvelopeId",
                        column: x => x.EnvelopeId,
                        principalTable: "Envelopes",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateIndex(
                name: "IX_CompletionSealOutputs_EnvelopeId_CandidateId_Kind",
                table: "CompletionSealOutputs",
                columns: new[] { "EnvelopeId", "CandidateId", "Kind" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CompletionSealOutputs_EnvelopeId_PdfObjectId",
                table: "CompletionSealOutputs",
                columns: new[] { "EnvelopeId", "PdfObjectId" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CompletionSealOutputs");

            migrationBuilder.DropUniqueConstraint(
                name: "AK_CompletionCandidates_EnvelopeId_Id",
                table: "CompletionCandidates");
        }
    }
}
