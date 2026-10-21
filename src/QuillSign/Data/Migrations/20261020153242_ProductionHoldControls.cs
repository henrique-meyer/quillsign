using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuillSign.Data.Migrations
{
    /// <inheritdoc />
    public partial class ProductionHoldControls : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ProductionHoldControls",
                columns: table => new
                {
                    EventId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EnvelopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    HoldId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PlanId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Sequence = table.Column<long>(type: "bigint", nullable: false),
                    Kind = table.Column<int>(type: "int", nullable: false),
                    At = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    PolicySha256 = table.Column<string>(type: "varchar(64)", unicode: false, maxLength: 64, nullable: false),
                    PlanSha256 = table.Column<string>(type: "varchar(64)", unicode: false, maxLength: 64, nullable: false),
                    ItemSha256 = table.Column<string>(type: "varchar(64)", unicode: false, maxLength: 64, nullable: true),
                    PayloadSha256 = table.Column<string>(type: "varchar(64)", unicode: false, maxLength: 64, nullable: true),
                    PlanPayload = table.Column<byte[]>(type: "varbinary(max)", maxLength: 42991616, nullable: true),
                    ProtectedEvidence = table.Column<string>(type: "nvarchar(max)", maxLength: 65536, nullable: false),
                    PreviousHash = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: true),
                    Hash = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ProductionHoldControls", x => x.EventId);
                    table.CheckConstraint("CK_ProductionHoldControl_Bounds", "[Sequence] BETWEEN 1 AND 16384 AND [Kind] IN (0,1) AND DATEPART(TZOFFSET,[At])=0 AND DATALENGTH([PolicySha256])=64 AND DATALENGTH([PlanSha256])=64 AND DATALENGTH([ProtectedEvidence]) BETWEEN 64 AND 131072");
                    table.CheckConstraint("CK_ProductionHoldControl_Hash", "DATALENGTH([Hash])=32 AND (([Sequence]=1 AND [PreviousHash] IS NULL) OR ([Sequence]>1 AND DATALENGTH([PreviousHash])=32))");
                    table.CheckConstraint("CK_ProductionHoldControl_Ids", "[EventId]<>'00000000-0000-0000-0000-000000000000' AND [HoldId]<>'00000000-0000-0000-0000-000000000000' AND [PlanId]<>'00000000-0000-0000-0000-000000000000'");
                    table.CheckConstraint("CK_ProductionHoldControl_Payload", "([Kind]=0 AND [EventId]=[PlanId] AND [ItemSha256] IS NULL AND [PayloadSha256] IS NOT NULL AND DATALENGTH([PayloadSha256])=64 AND [PlanPayload] IS NOT NULL AND DATALENGTH([PlanPayload]) BETWEEN 1 AND 42991616) OR ([Kind]=1 AND [ItemSha256] IS NOT NULL AND DATALENGTH([ItemSha256])=64 AND [PayloadSha256] IS NULL AND [PlanPayload] IS NULL)");
                    table.CheckConstraint("CK_ProductionHoldControlRecord_Hash", "[Hash] IS NULL OR DATALENGTH([Hash]) = 32");
                    table.CheckConstraint("CK_ProductionHoldControlRecord_PreviousHash", "[PreviousHash] IS NULL OR DATALENGTH([PreviousHash]) = 32");
                    table.ForeignKey(
                        name: "FK_ProductionHoldControls_Envelopes_EnvelopeId",
                        column: x => x.EnvelopeId,
                        principalTable: "Envelopes",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_ProductionHoldControls_ProductionRetentionPolicies_EnvelopeId",
                        column: x => x.EnvelopeId,
                        principalTable: "ProductionRetentionPolicies",
                        principalColumn: "EnvelopeId");
                });

            migrationBuilder.CreateIndex(
                name: "IX_ProductionHoldControls_EnvelopeId_PlanId",
                table: "ProductionHoldControls",
                columns: new[] { "EnvelopeId", "PlanId" },
                unique: true,
                filter: "[Kind]=0");

            migrationBuilder.CreateIndex(
                name: "IX_ProductionHoldControls_EnvelopeId_PlanId_ItemSha256",
                table: "ProductionHoldControls",
                columns: new[] { "EnvelopeId", "PlanId", "ItemSha256" },
                unique: true,
                filter: "[Kind]=1");

            migrationBuilder.CreateIndex(
                name: "IX_ProductionHoldControls_EnvelopeId_Sequence",
                table: "ProductionHoldControls",
                columns: new[] { "EnvelopeId", "Sequence" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ProductionHoldControls");
        }
    }
}
