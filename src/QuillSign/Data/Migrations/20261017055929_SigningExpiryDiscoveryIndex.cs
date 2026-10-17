using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuillSign.Data.Migrations
{
    /// <inheritdoc />
    public partial class SigningExpiryDiscoveryIndex : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateIndex(
                name: "IX_Envelopes_ExpiresAt_Id",
                table: "Envelopes",
                columns: new[] { "ExpiresAt", "Id" },
                filter: "[Status] = 'Sent' AND [ExpiresAt] IS NOT NULL");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Envelopes_ExpiresAt_Id",
                table: "Envelopes");
        }
    }
}
