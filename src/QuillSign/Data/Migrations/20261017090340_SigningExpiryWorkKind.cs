using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuillSign.Data.Migrations
{
    /// <inheritdoc />
    public partial class SigningExpiryWorkKind : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_WorkItem_Kind",
                table: "WorkItems");

            migrationBuilder.AddCheckConstraint(
                name: "CK_WorkItem_Kind",
                table: "WorkItems",
                sql: "[Kind] IS NULL OR [Kind] IN ('Conversion','Ai','Rendering','Sealing','Email','Purge','Expiry')");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_WorkItem_Kind",
                table: "WorkItems");

            migrationBuilder.AddCheckConstraint(
                name: "CK_WorkItem_Kind",
                table: "WorkItems",
                sql: "[Kind] IS NULL OR [Kind] IN ('Conversion','Ai','Rendering','Sealing','Email','Purge')");
        }
    }
}
