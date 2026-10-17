using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuillSign.Data.Migrations
{
    /// <inheritdoc />
    public partial class UploadedPdfHashIndexes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateIndex(
                name: "IX_Envelopes_CertificateSha256",
                table: "Envelopes",
                column: "CertificateSha256",
                filter: "[CertificateSha256] IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_Envelopes_FinalSha256",
                table: "Envelopes",
                column: "FinalSha256",
                filter: "[FinalSha256] IS NOT NULL");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Envelopes_CertificateSha256",
                table: "Envelopes");

            migrationBuilder.DropIndex(
                name: "IX_Envelopes_FinalSha256",
                table: "Envelopes");
        }
    }
}
