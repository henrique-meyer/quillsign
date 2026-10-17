using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuillSign.Data.Migrations
{
    /// <inheritdoc />
    public partial class DemoUploadRetentionSnapshots : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "DocumentRetentionSnapshots",
                columns: table => new
                {
                    EnvelopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PolicyVersion = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    Days = table.Column<int>(type: "int", nullable: false),
                    StartedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    DeleteAfter = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    OriginalObjectId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    OriginalSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    PdfObjectId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PdfSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DocumentRetentionSnapshots", x => x.EnvelopeId);
                    table.CheckConstraint("CK_DocumentRetentionSnapshot_Interval", "[Days] BETWEEN 1 AND 36500 AND DATEPART(TZOFFSET,[StartedAt]) = 0 AND DATEPART(TZOFFSET,[DeleteAfter]) = 0 AND [DeleteAfter] = DATEADD(day,[Days],[StartedAt])");
                    table.CheckConstraint("CK_DocumentRetentionSnapshot_Objects", "[OriginalObjectId] <> '00000000-0000-0000-0000-000000000000' AND [PdfObjectId] <> '00000000-0000-0000-0000-000000000000' AND [OriginalObjectId] <> [PdfObjectId]");
                    table.CheckConstraint("CK_DocumentRetentionSnapshot_OriginalSha256", "[OriginalSha256] IS NULL OR DATALENGTH([OriginalSha256]) = 32");
                    table.CheckConstraint("CK_DocumentRetentionSnapshot_PdfSha256", "[PdfSha256] IS NULL OR DATALENGTH([PdfSha256]) = 32");
                    table.ForeignKey(
                        name: "FK_DocumentRetentionSnapshots_Envelopes_EnvelopeId",
                        column: x => x.EnvelopeId,
                        principalTable: "Envelopes",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateIndex(
                name: "IX_DocumentRetentionSnapshots_DeleteAfter_EnvelopeId",
                table: "DocumentRetentionSnapshots",
                columns: new[] { "DeleteAfter", "EnvelopeId" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DocumentRetentionSnapshots");
        }
    }
}
