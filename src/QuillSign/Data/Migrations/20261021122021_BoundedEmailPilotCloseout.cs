using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuillSign.Data.Migrations
{
    /// <inheritdoc />
    public partial class BoundedEmailPilotCloseout : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "EmailPilotCloseouts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    Until = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    DeleteAfter = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    CapabilitySha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    ManifestSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    ProtectedManifest = table.Column<string>(type: "nvarchar(max)", maxLength: 65536, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EmailPilotCloseouts", x => x.Id);
                    table.CheckConstraint("CK_EmailPilotCloseoutHeaderRecord_CapabilitySha256", "[CapabilitySha256] IS NULL OR DATALENGTH([CapabilitySha256]) = 32");
                    table.CheckConstraint("CK_EmailPilotCloseoutHeaderRecord_ManifestSha256", "[ManifestSha256] IS NULL OR DATALENGTH([ManifestSha256]) = 32");
                    table.CheckConstraint("CK_PilotCloseout_Header", "[Id]<>'00000000-0000-0000-0000-000000000000' AND DATEPART(TZOFFSET,[CreatedAt])=0 AND DATEPART(TZOFFSET,[Until])=0 AND DATEPART(TZOFFSET,[DeleteAfter])=0 AND [Until]>[CreatedAt] AND [Until]<=DATEADD(minute,30,[CreatedAt]) AND [DeleteAfter]>[Until] AND DATALENGTH([CapabilitySha256])=32 AND DATALENGTH([ManifestSha256])=32");
                    table.CheckConstraint("CK_PilotCloseout_Secret", "[ProtectedManifest] IS NULL OR DATALENGTH([ProtectedManifest]) BETWEEN 2 AND 131072");
                });

            migrationBuilder.CreateTable(
                name: "EmailPilotCloseoutOperations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CloseoutId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Kind = table.Column<int>(type: "int", nullable: false),
                    Step = table.Column<int>(type: "int", nullable: false),
                    SubjectEnvelopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    WorkId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    At = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    EncodedBytes = table.Column<int>(type: "int", nullable: false),
                    RequestSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    ProtectedReceipt = table.Column<string>(type: "nvarchar(max)", maxLength: 8192, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EmailPilotCloseoutOperations", x => x.Id);
                    table.CheckConstraint("CK_EmailPilotCloseoutOperationRecord_RequestSha256", "[RequestSha256] IS NULL OR DATALENGTH([RequestSha256]) = 32");
                    table.CheckConstraint("CK_PilotCloseout_Accounting", "([Kind]=0 AND [Step] BETWEEN 6 AND 9 AND [EncodedBytes]=0) OR ([Kind]=1 AND [EncodedBytes] BETWEEN 1 AND 1048576)");
                    table.CheckConstraint("CK_PilotCloseout_Operation", "[Id]<>'00000000-0000-0000-0000-000000000000' AND [WorkId]<>'00000000-0000-0000-0000-000000000000' AND [SubjectEnvelopeId]<>'00000000-0000-0000-0000-000000000000' AND DATEPART(TZOFFSET,[At])=0 AND [Step] BETWEEN 0 AND 9 AND DATALENGTH([RequestSha256])=32 AND DATALENGTH([ProtectedReceipt]) BETWEEN 2 AND 16384");
                    table.ForeignKey(
                        name: "FK_EmailPilotCloseoutOperations_EmailPilotCloseouts_CloseoutId",
                        column: x => x.CloseoutId,
                        principalTable: "EmailPilotCloseouts",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateIndex(
                name: "IX_EmailPilotCloseoutOperations_CloseoutId_Kind_Step",
                table: "EmailPilotCloseoutOperations",
                columns: new[] { "CloseoutId", "Kind", "Step" },
                unique: true);
            // Only the encrypted private carrier is removed. Header and every
            // consumed reservation remain immutable counter tombstones.
            migrationBuilder.Sql("""
                CREATE OR ALTER PROCEDURE [dbo].[RemoveExpiredEmailPilotCloseoutSecret] @Id uniqueidentifier
                WITH EXECUTE AS OWNER
                AS
                BEGIN
                    SET NOCOUNT ON; SET XACT_ABORT ON;
                    IF @Id IS NULL OR @Id='00000000-0000-0000-0000-000000000000'
                        THROW 50001,'Supply one exact closeout purpose.',1;
                    UPDATE dbo.EmailPilotCloseouts SET ProtectedManifest=NULL
                    WHERE Id=@Id AND ProtectedManifest IS NOT NULL
                        AND DATEPART(TZOFFSET,CreatedAt)=0 AND DATEPART(TZOFFSET,[Until])=0
                        AND DATEPART(TZOFFSET,DeleteAfter)=0 AND [Until]>CreatedAt
                        AND [Until]<=DATEADD(minute,30,CreatedAt) AND DeleteAfter>[Until]
                        AND DeleteAfter<=SYSUTCDATETIME();
                END
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("DROP PROCEDURE IF EXISTS dbo.RemoveExpiredEmailPilotCloseoutSecret");
            migrationBuilder.DropTable(
                name: "EmailPilotCloseoutOperations");

            migrationBuilder.DropTable(
                name: "EmailPilotCloseouts");
        }
    }
}
