using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuillSign.Data.Migrations
{
    /// <inheritdoc />
    public partial class PrivateOperatorAccessReceipts : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ProductionOperatorAccessReceipts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    At = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    PayloadSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    ProtectedReceipt = table.Column<string>(type: "nvarchar(max)", maxLength: 8192, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ProductionOperatorAccessReceipts", x => x.Id);
                    table.CheckConstraint("CK_OperatorAccess_Receipt", "[Id]<>'00000000-0000-0000-0000-000000000000' AND DATEPART(TZOFFSET,[At])=0 AND DATALENGTH([PayloadSha256])=32 AND DATALENGTH([ProtectedReceipt]) BETWEEN 2 AND 16384");
                    table.CheckConstraint("CK_ProductionOperatorAccessReceipt_PayloadSha256", "[PayloadSha256] IS NULL OR DATALENGTH([PayloadSha256]) = 32");
                });
            migrationBuilder.Sql("CREATE TRIGGER [dbo].[TR_ProductionOperatorAccess_Immutable] ON [dbo].[ProductionOperatorAccessReceipts] AFTER UPDATE, DELETE AS BEGIN SET NOCOUNT ON; THROW 51000, 'Private operator access evidence is append-only.', 1; END;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ProductionOperatorAccessReceipts");
        }
    }
}
