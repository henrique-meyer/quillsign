using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuillSign.Data.Migrations
{
    /// <inheritdoc />
    public partial class ElectronicRecordSnapshot : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ErsdText",
                table: "Envelopes",
                type: "nvarchar(max)",
                maxLength: 32768,
                nullable: true);

            migrationBuilder.AddCheckConstraint(
                name: "CK_Envelope_ErsdText",
                table: "Envelopes",
                sql: "[ErsdText] IS NULL OR DATALENGTH([ErsdText]) <= 65536");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_Envelope_ErsdText",
                table: "Envelopes");

            migrationBuilder.DropColumn(
                name: "ErsdText",
                table: "Envelopes");
        }
    }
}
