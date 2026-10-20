using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuillSign.Data.Migrations
{
    /// <inheritdoc />
    public partial class ProductionHoldRequests : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ProductionHoldRequests",
                columns: table => new
                {
                    CommandId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EnvelopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    HoldId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Revision = table.Column<long>(type: "bigint", nullable: false),
                    Operation = table.Column<int>(type: "int", nullable: false),
                    At = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    PolicySha256 = table.Column<string>(type: "varchar(64)", unicode: false, maxLength: 64, nullable: false),
                    CommandSha256 = table.Column<string>(type: "varchar(64)", unicode: false, maxLength: 64, nullable: false),
                    ProtectedEvidence = table.Column<string>(type: "nvarchar(max)", maxLength: 32768, nullable: false),
                    PreviousHash = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: true),
                    Hash = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ProductionHoldRequests", x => x.CommandId);
                    table.CheckConstraint("CK_ProductionHoldRequest_Bounds", "[Revision] BETWEEN 1 AND 512 AND [Operation] IN (0,1) AND DATEPART(TZOFFSET,[At])=0 AND DATALENGTH([PolicySha256])=64 AND DATALENGTH([CommandSha256])=64 AND DATALENGTH([ProtectedEvidence]) BETWEEN 64 AND 65536");
                    table.CheckConstraint("CK_ProductionHoldRequest_Hash", "DATALENGTH([Hash])=32 AND (([Revision]=1 AND [PreviousHash] IS NULL) OR ([Revision]>1 AND DATALENGTH([PreviousHash])=32))");
                    table.CheckConstraint("CK_ProductionHoldRequest_Ids", "[CommandId]<>'00000000-0000-0000-0000-000000000000' AND [HoldId]<>'00000000-0000-0000-0000-000000000000'");
                    table.CheckConstraint("CK_ProductionHoldRequestRecord_Hash", "[Hash] IS NULL OR DATALENGTH([Hash]) = 32");
                    table.CheckConstraint("CK_ProductionHoldRequestRecord_PreviousHash", "[PreviousHash] IS NULL OR DATALENGTH([PreviousHash]) = 32");
                    table.ForeignKey(
                        name: "FK_ProductionHoldRequests_Envelopes_EnvelopeId",
                        column: x => x.EnvelopeId,
                        principalTable: "Envelopes",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_ProductionHoldRequests_ProductionRetentionPolicies_EnvelopeId",
                        column: x => x.EnvelopeId,
                        principalTable: "ProductionRetentionPolicies",
                        principalColumn: "EnvelopeId");
                });

            migrationBuilder.CreateIndex(
                name: "IX_ProductionHoldRequests_EnvelopeId_HoldId_Operation",
                table: "ProductionHoldRequests",
                columns: new[] { "EnvelopeId", "HoldId", "Operation" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ProductionHoldRequests_EnvelopeId_Revision",
                table: "ProductionHoldRequests",
                columns: new[] { "EnvelopeId", "Revision" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ProductionHoldRequests");
        }
    }
}
