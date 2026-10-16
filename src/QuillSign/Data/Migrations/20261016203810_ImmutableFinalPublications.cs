using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuillSign.Data.Migrations
{
    /// <inheritdoc />
    public partial class ImmutableFinalPublications : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "CompletionPublicationIntents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EnvelopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CandidateId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ExecutedOutputId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CertificateOutputId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ExecutedObjectId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CertificateObjectId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    BeforeEnvelopeJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    StageBindingsJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    RetentionDays = table.Column<int>(type: "int", nullable: false),
                    DevelopmentWriteOnce = table.Column<bool>(type: "bit", nullable: false),
                    PreparedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    RecipeSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CompletionPublicationIntents", x => x.Id);
                    table.UniqueConstraint("AK_CompletionPublicationIntents_EnvelopeId_Id", x => new { x.EnvelopeId, x.Id });
                    table.CheckConstraint("CK_CompletionPublicationIntent_BeforeEnvelopeJson", "[BeforeEnvelopeJson] IS NULL OR ISJSON([BeforeEnvelopeJson]) = 1");
                    table.CheckConstraint("CK_CompletionPublicationIntent_RecipeSha256", "[RecipeSha256] IS NULL OR DATALENGTH([RecipeSha256]) = 32");
                    table.CheckConstraint("CK_CompletionPublicationIntent_StageBindingsJson", "[StageBindingsJson] IS NULL OR ISJSON([StageBindingsJson]) = 1");
                    table.CheckConstraint("CK_PublicationIntent_Bounds", "[RetentionDays] BETWEEN 0 AND 36500 AND [ExecutedObjectId] <> [CertificateObjectId] AND DATALENGTH([BeforeEnvelopeJson]) BETWEEN 2 AND 524288 AND DATALENGTH([StageBindingsJson]) BETWEEN 2 AND 32768");
                    table.ForeignKey(
                        name: "FK_CompletionPublicationIntents_CompletionCandidates_EnvelopeId_CandidateId",
                        columns: x => new { x.EnvelopeId, x.CandidateId },
                        principalTable: "CompletionCandidates",
                        principalColumns: new[] { "EnvelopeId", "Id" });
                    table.ForeignKey(
                        name: "FK_CompletionPublicationIntents_Envelopes_EnvelopeId",
                        column: x => x.EnvelopeId,
                        principalTable: "Envelopes",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "CompletionPublicationResults",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EnvelopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    IntentId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    FinalDocumentsJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CompletedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    AfterEnvelopeSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    IntentRecipeSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    RecipeSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    AuditSequence = table.Column<long>(type: "bigint", nullable: false),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CompletionPublicationResults", x => x.Id);
                    table.CheckConstraint("CK_CompletionPublicationResult_AfterEnvelopeSha256", "[AfterEnvelopeSha256] IS NULL OR DATALENGTH([AfterEnvelopeSha256]) = 32");
                    table.CheckConstraint("CK_CompletionPublicationResult_FinalDocumentsJson", "[FinalDocumentsJson] IS NULL OR ISJSON([FinalDocumentsJson]) = 1");
                    table.CheckConstraint("CK_CompletionPublicationResult_IntentRecipeSha256", "[IntentRecipeSha256] IS NULL OR DATALENGTH([IntentRecipeSha256]) = 32");
                    table.CheckConstraint("CK_CompletionPublicationResult_RecipeSha256", "[RecipeSha256] IS NULL OR DATALENGTH([RecipeSha256]) = 32");
                    table.CheckConstraint("CK_PublicationResult_Bounds", "[AuditSequence] BETWEEN 1 AND 512 AND DATALENGTH([FinalDocumentsJson]) BETWEEN 2 AND 32768");
                    table.ForeignKey(
                        name: "FK_CompletionPublicationResults_CompletionPublicationIntents_EnvelopeId_IntentId",
                        columns: x => new { x.EnvelopeId, x.IntentId },
                        principalTable: "CompletionPublicationIntents",
                        principalColumns: new[] { "EnvelopeId", "Id" });
                    table.ForeignKey(
                        name: "FK_CompletionPublicationResults_Envelopes_EnvelopeId",
                        column: x => x.EnvelopeId,
                        principalTable: "Envelopes",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateIndex(
                name: "IX_CompletionPublicationIntents_EnvelopeId",
                table: "CompletionPublicationIntents",
                column: "EnvelopeId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CompletionPublicationIntents_EnvelopeId_CandidateId",
                table: "CompletionPublicationIntents",
                columns: new[] { "EnvelopeId", "CandidateId" });

            migrationBuilder.CreateIndex(
                name: "IX_CompletionPublicationResults_EnvelopeId",
                table: "CompletionPublicationResults",
                column: "EnvelopeId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CompletionPublicationResults_EnvelopeId_IntentId",
                table: "CompletionPublicationResults",
                columns: new[] { "EnvelopeId", "IntentId" });

            migrationBuilder.CreateIndex(
                name: "IX_CompletionPublicationResults_IntentId",
                table: "CompletionPublicationResults",
                column: "IntentId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CompletionPublicationResults");

            migrationBuilder.DropTable(
                name: "CompletionPublicationIntents");
        }
    }
}
