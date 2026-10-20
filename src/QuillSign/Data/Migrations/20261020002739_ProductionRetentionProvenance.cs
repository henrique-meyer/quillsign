using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuillSign.Data.Migrations
{
    /// <inheritdoc />
    public partial class ProductionRetentionProvenance : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ProductionRetentionPolicies",
                columns: table => new
                {
                    EnvelopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    OriginalCreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    EnrolledAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    PolicyJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    PolicySha256 = table.Column<string>(type: "varchar(64)", unicode: false, maxLength: 64, nullable: false),
                    OriginSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    AuditSequence = table.Column<long>(type: "bigint", nullable: false),
                    AuditHash = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ProductionRetentionPolicies", x => x.EnvelopeId);
                    table.CheckConstraint("CK_ProductionRetentionPolicy_Bounds", "DATALENGTH([PolicyJson]) BETWEEN 2 AND 16384 AND DATALENGTH([PolicySha256])=64 AND [AuditSequence] BETWEEN 1 AND 512");
                    table.CheckConstraint("CK_ProductionRetentionPolicy_Clock", "DATEPART(TZOFFSET,[OriginalCreatedAt])=0 AND DATEPART(TZOFFSET,[EnrolledAt])=0 AND [EnrolledAt]>=[OriginalCreatedAt]");
                    table.CheckConstraint("CK_ProductionRetentionPolicyRecord_AuditHash", "[AuditHash] IS NULL OR DATALENGTH([AuditHash]) = 32");
                    table.CheckConstraint("CK_ProductionRetentionPolicyRecord_OriginSha256", "[OriginSha256] IS NULL OR DATALENGTH([OriginSha256]) = 32");
                    table.CheckConstraint("CK_ProductionRetentionPolicyRecord_PolicyJson", "[PolicyJson] IS NULL OR ISJSON([PolicyJson]) = 1");
                    table.ForeignKey(
                        name: "FK_ProductionRetentionPolicies_Envelopes_EnvelopeId",
                        column: x => x.EnvelopeId,
                        principalTable: "Envelopes",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "ProductionRetentionTerminals",
                columns: table => new
                {
                    EnvelopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Status = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    PolicySha256 = table.Column<string>(type: "varchar(64)", unicode: false, maxLength: 64, nullable: false),
                    OriginalAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    ClockAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    RecordedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    SourceAuditSequence = table.Column<long>(type: "bigint", nullable: false),
                    SourceAuditHash = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    AuditSequence = table.Column<long>(type: "bigint", nullable: false),
                    AuditHash = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ProductionRetentionTerminals", x => x.EnvelopeId);
                    table.CheckConstraint("CK_ProductionRetentionTerminal_Bounds", "[Status] IN ('Completed','Expired','Declined','Voided') AND DATALENGTH([PolicySha256])=64 AND [SourceAuditSequence] BETWEEN 1 AND 511 AND [AuditSequence] BETWEEN 2 AND 512 AND [AuditSequence]>[SourceAuditSequence]");
                    table.CheckConstraint("CK_ProductionRetentionTerminal_Clock", "DATEPART(TZOFFSET,[OriginalAt])=0 AND DATEPART(TZOFFSET,[ClockAt])=0 AND DATEPART(TZOFFSET,[RecordedAt])=0 AND [RecordedAt]>=[OriginalAt] AND [ClockAt]<=[OriginalAt] AND DATEDIFF_BIG(nanosecond,[ClockAt],[OriginalAt]) BETWEEN 0 AND 999999999 AND DATEPART(nanosecond,[ClockAt])=0");
                    table.CheckConstraint("CK_ProductionRetentionTerminalRecord_AuditHash", "[AuditHash] IS NULL OR DATALENGTH([AuditHash]) = 32");
                    table.CheckConstraint("CK_ProductionRetentionTerminalRecord_SourceAuditHash", "[SourceAuditHash] IS NULL OR DATALENGTH([SourceAuditHash]) = 32");
                    table.CheckConstraint("CK_ProductionRetentionTerminalRecord_Status", "[Status] IS NULL OR [Status] IN ('Draft','Sent','Completed','Declined','Voided','Expired')");
                    table.ForeignKey(
                        name: "FK_ProductionRetentionTerminals_Envelopes_EnvelopeId",
                        column: x => x.EnvelopeId,
                        principalTable: "Envelopes",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_ProductionRetentionTerminals_ProductionRetentionPolicies_EnvelopeId",
                        column: x => x.EnvelopeId,
                        principalTable: "ProductionRetentionPolicies",
                        principalColumn: "EnvelopeId");
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ProductionRetentionTerminals");

            migrationBuilder.DropTable(
                name: "ProductionRetentionPolicies");
        }
    }
}
