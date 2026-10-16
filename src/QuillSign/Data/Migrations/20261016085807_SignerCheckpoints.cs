using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuillSign.Data.Migrations
{
    /// <inheritdoc />
    public partial class SignerCheckpoints : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "NextInvitationId",
                table: "SignerFinishAcceptances",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "CurrentCopyVersion",
                table: "Envelopes",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<Guid>(
                name: "CurrentFinishId",
                table: "Envelopes",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<byte[]>(
                name: "DisclosureSha256",
                table: "AuthTokens",
                type: "varbinary(32)",
                maxLength: 32,
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "DocumentId",
                table: "AuthTokens",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<byte[]>(
                name: "DocumentSha256",
                table: "AuthTokens",
                type: "varbinary(32)",
                maxLength: 32,
                nullable: true);

            migrationBuilder.AddUniqueConstraint(
                name: "AK_SignerFinishAcceptances_EnvelopeId_Id",
                table: "SignerFinishAcceptances",
                columns: new[] { "EnvelopeId", "Id" });

            migrationBuilder.CreateIndex(
                name: "IX_SignerFinishAcceptances_NextInvitationId",
                table: "SignerFinishAcceptances",
                column: "NextInvitationId",
                unique: true,
                filter: "[NextInvitationId] IS NOT NULL");

            migrationBuilder.AddCheckConstraint(
                name: "CK_SignerFinishAcceptance_Invitation",
                table: "SignerFinishAcceptances",
                sql: "[NextInvitationId] IS NULL OR [ProcessedAt] IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_Envelopes_Id_CurrentFinishId",
                table: "Envelopes",
                columns: new[] { "Id", "CurrentFinishId" });

            migrationBuilder.AddCheckConstraint(
                name: "CK_Envelope_CurrentCopy",
                table: "Envelopes",
                sql: "([CurrentFinishId] IS NULL AND [CurrentCopyVersion] = 0) OR ([CurrentFinishId] IS NOT NULL AND [CurrentCopyVersion] BETWEEN 1 AND 100)");

            migrationBuilder.AddCheckConstraint(
                name: "CK_AuthToken_DisclosureSha256",
                table: "AuthTokens",
                sql: "[DisclosureSha256] IS NULL OR DATALENGTH([DisclosureSha256]) = 32");

            migrationBuilder.AddCheckConstraint(
                name: "CK_AuthToken_DocumentSha256",
                table: "AuthTokens",
                sql: "[DocumentSha256] IS NULL OR DATALENGTH([DocumentSha256]) = 32");

            migrationBuilder.AddCheckConstraint(
                name: "CK_Token_DocumentBinding",
                table: "AuthTokens",
                sql: "([DocumentId] IS NULL AND [DocumentSha256] IS NULL AND [DisclosureSha256] IS NULL) OR ([DocumentId] IS NOT NULL AND [DocumentSha256] IS NOT NULL AND [DisclosureSha256] IS NOT NULL)");

            migrationBuilder.AddForeignKey(
                name: "FK_Envelopes_SignerFinishAcceptances_Id_CurrentFinishId",
                table: "Envelopes",
                columns: new[] { "Id", "CurrentFinishId" },
                principalTable: "SignerFinishAcceptances",
                principalColumns: new[] { "EnvelopeId", "Id" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Envelopes_SignerFinishAcceptances_Id_CurrentFinishId",
                table: "Envelopes");

            migrationBuilder.DropUniqueConstraint(
                name: "AK_SignerFinishAcceptances_EnvelopeId_Id",
                table: "SignerFinishAcceptances");

            migrationBuilder.DropIndex(
                name: "IX_SignerFinishAcceptances_NextInvitationId",
                table: "SignerFinishAcceptances");

            migrationBuilder.DropCheckConstraint(
                name: "CK_SignerFinishAcceptance_Invitation",
                table: "SignerFinishAcceptances");

            migrationBuilder.DropIndex(
                name: "IX_Envelopes_Id_CurrentFinishId",
                table: "Envelopes");

            migrationBuilder.DropCheckConstraint(
                name: "CK_Envelope_CurrentCopy",
                table: "Envelopes");

            migrationBuilder.DropCheckConstraint(
                name: "CK_AuthToken_DisclosureSha256",
                table: "AuthTokens");

            migrationBuilder.DropCheckConstraint(
                name: "CK_AuthToken_DocumentSha256",
                table: "AuthTokens");

            migrationBuilder.DropCheckConstraint(
                name: "CK_Token_DocumentBinding",
                table: "AuthTokens");

            migrationBuilder.DropColumn(
                name: "NextInvitationId",
                table: "SignerFinishAcceptances");

            migrationBuilder.DropColumn(
                name: "CurrentCopyVersion",
                table: "Envelopes");

            migrationBuilder.DropColumn(
                name: "CurrentFinishId",
                table: "Envelopes");

            migrationBuilder.DropColumn(
                name: "DisclosureSha256",
                table: "AuthTokens");

            migrationBuilder.DropColumn(
                name: "DocumentId",
                table: "AuthTokens");

            migrationBuilder.DropColumn(
                name: "DocumentSha256",
                table: "AuthTokens");
        }
    }
}
