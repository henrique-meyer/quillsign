using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuillSign.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddEmailPilotLookup : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "EmailPilotLookupRequestId",
                table: "AuthTokens",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "EmailPilotLookupRequests",
                columns: table => new
                {
                    RunId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RequestId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SubjectEnvelopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PublicationId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PublicationRecipeSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    RequestSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    WorkSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    RetentionSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    RequestedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    ProtectedBinding = table.Column<string>(type: "nvarchar(max)", maxLength: 4096, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EmailPilotLookupRequests", x => x.RunId);
                    table.UniqueConstraint("AK_EmailPilotLookupRequests_RequestId", x => x.RequestId);
                    table.CheckConstraint("CK_EmailPilotLookupRequestRecord_PublicationRecipeSha256", "[PublicationRecipeSha256] IS NULL OR DATALENGTH([PublicationRecipeSha256]) = 32");
                    table.CheckConstraint("CK_EmailPilotLookupRequestRecord_RequestSha256", "[RequestSha256] IS NULL OR DATALENGTH([RequestSha256]) = 32");
                    table.CheckConstraint("CK_EmailPilotLookupRequestRecord_RetentionSha256", "[RetentionSha256] IS NULL OR DATALENGTH([RetentionSha256]) = 32");
                    table.CheckConstraint("CK_EmailPilotLookupRequestRecord_WorkSha256", "[WorkSha256] IS NULL OR DATALENGTH([WorkSha256]) = 32");
                    table.CheckConstraint("CK_PilotLookupRequest_Binding", "DATALENGTH([ProtectedBinding]) BETWEEN 2 AND 8192");
                    table.CheckConstraint("CK_PilotLookupRequest_Ids", "[RunId]<>'00000000-0000-0000-0000-000000000000' AND [RequestId]<>'00000000-0000-0000-0000-000000000000' AND [SubjectEnvelopeId]<>'00000000-0000-0000-0000-000000000000' AND [PublicationId]<>'00000000-0000-0000-0000-000000000000'");
                    table.CheckConstraint("CK_PilotLookupRequest_Interval", "DATEPART(TZOFFSET,[RequestedAt])=0 AND DATEPART(TZOFFSET,[ExpiresAt])=0 AND [ExpiresAt]>[RequestedAt] AND [ExpiresAt]<=DATEADD(minute,60,[RequestedAt])");
                    table.ForeignKey(
                        name: "FK_EmailPilotLookupRequests_EmailPilotRuns_RunId",
                        column: x => x.RunId,
                        principalTable: "EmailPilotRuns",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "EmailPilotLookupTokens",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RunId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RequestId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Attempt = table.Column<int>(type: "int", nullable: false),
                    TokenSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    IssuedRevision = table.Column<string>(type: "nvarchar(12)", maxLength: 12, nullable: false),
                    IssuedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    ProtectedBinding = table.Column<string>(type: "nvarchar(max)", maxLength: 4096, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EmailPilotLookupTokens", x => x.Id);
                    table.CheckConstraint("CK_EmailPilotLookupTokenRecord_TokenSha256", "[TokenSha256] IS NULL OR DATALENGTH([TokenSha256]) = 32");
                    table.CheckConstraint("CK_PilotLookupToken_Binding", "DATALENGTH([ProtectedBinding]) BETWEEN 2 AND 8192 AND LEN([IssuedRevision])=12");
                    table.CheckConstraint("CK_PilotLookupToken_Ids", "[Id]<>'00000000-0000-0000-0000-000000000000' AND [RunId]<>'00000000-0000-0000-0000-000000000000' AND [RequestId]<>'00000000-0000-0000-0000-000000000000' AND [Attempt] BETWEEN 1 AND 10");
                    table.CheckConstraint("CK_PilotLookupToken_Interval", "DATEPART(TZOFFSET,[IssuedAt])=0 AND DATEPART(TZOFFSET,[ExpiresAt])=0 AND [ExpiresAt]>[IssuedAt] AND [ExpiresAt]<=DATEADD(minute,60,[IssuedAt])");
                    table.ForeignKey(
                        name: "FK_EmailPilotLookupTokens_EmailPilotLookupRequests_RequestId",
                        column: x => x.RequestId,
                        principalTable: "EmailPilotLookupRequests",
                        principalColumn: "RequestId");
                    table.ForeignKey(
                        name: "FK_EmailPilotLookupTokens_EmailPilotRuns_RunId",
                        column: x => x.RunId,
                        principalTable: "EmailPilotRuns",
                        principalColumn: "Id");
                });

            migrationBuilder.AddCheckConstraint(
                name: "CK_AuthToken_PilotLookup",
                table: "AuthTokens",
                sql: "[EmailPilotLookupRequestId] IS NULL OR ([EmailPilotLookupRequestId]<>'00000000-0000-0000-0000-000000000000' AND [Purpose]='Lookup' AND [EnvelopeId] IS NULL AND [PartyType]='System' AND [PartyId] IS NULL AND [Email]='' AND [Ip] IS NULL AND [DocumentId] IS NULL AND [DocumentSha256] IS NULL AND [DisclosureSha256] IS NULL AND [CompletionPublicationId] IS NULL AND [CompletionRecipeSha256] IS NULL AND [CompletionPartySha256] IS NULL AND [SignerContactRevisionId] IS NULL)");

            migrationBuilder.CreateIndex(
                name: "IX_EmailPilotLookupTokens_RequestId_Attempt",
                table: "EmailPilotLookupTokens",
                columns: new[] { "RequestId", "Attempt" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_EmailPilotLookupTokens_RunId",
                table: "EmailPilotLookupTokens",
                column: "RunId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "EmailPilotLookupTokens");

            migrationBuilder.DropTable(
                name: "EmailPilotLookupRequests");

            migrationBuilder.DropCheckConstraint(
                name: "CK_AuthToken_PilotLookup",
                table: "AuthTokens");

            migrationBuilder.DropColumn(
                name: "EmailPilotLookupRequestId",
                table: "AuthTokens");
        }
    }
}
