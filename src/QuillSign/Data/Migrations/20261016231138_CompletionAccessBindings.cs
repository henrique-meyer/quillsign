using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuillSign.Data.Migrations
{
    /// <inheritdoc />
    public partial class CompletionAccessBindings : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_AuthToken_Purpose",
                table: "AuthTokens");

            migrationBuilder.AddColumn<byte[]>(
                name: "CompletionPartySha256",
                table: "AuthTokens",
                type: "varbinary(32)",
                maxLength: 32,
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "CompletionPublicationId",
                table: "AuthTokens",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<byte[]>(
                name: "CompletionRecipeSha256",
                table: "AuthTokens",
                type: "varbinary(32)",
                maxLength: 32,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_AuthTokens_CompletionPublicationId",
                table: "AuthTokens",
                column: "CompletionPublicationId");

            migrationBuilder.AddCheckConstraint(
                name: "CK_AuthToken_CompletionPartySha256",
                table: "AuthTokens",
                sql: "[CompletionPartySha256] IS NULL OR DATALENGTH([CompletionPartySha256]) = 32");

            migrationBuilder.AddCheckConstraint(
                name: "CK_AuthToken_CompletionRecipeSha256",
                table: "AuthTokens",
                sql: "[CompletionRecipeSha256] IS NULL OR DATALENGTH([CompletionRecipeSha256]) = 32");

            migrationBuilder.AddCheckConstraint(
                name: "CK_AuthToken_Purpose",
                table: "AuthTokens",
                sql: "[Purpose] IS NULL OR [Purpose] IN ('SenderVerify','SenderStatus','SignerAccess','Lookup','CompletionAccess')");

            migrationBuilder.AddCheckConstraint(
                name: "CK_Token_CompletionBinding",
                table: "AuthTokens",
                sql: "([Purpose] = 'CompletionAccess' AND [CompletionPublicationId] IS NOT NULL AND [CompletionRecipeSha256] IS NOT NULL AND [CompletionPartySha256] IS NOT NULL AND [DocumentId] IS NULL AND [DocumentSha256] IS NULL AND [DisclosureSha256] IS NULL AND (([PartyType] = 'Sender' AND [PartyId] IS NULL) OR ([PartyType] IN ('Signer','Recipient') AND [PartyId] IS NOT NULL))) OR ([Purpose] <> 'CompletionAccess' AND [CompletionPublicationId] IS NULL AND [CompletionRecipeSha256] IS NULL AND [CompletionPartySha256] IS NULL)");

            migrationBuilder.AddForeignKey(
                name: "FK_AuthTokens_CompletionPublicationResults_CompletionPublicationId",
                table: "AuthTokens",
                column: "CompletionPublicationId",
                principalTable: "CompletionPublicationResults",
                principalColumn: "Id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_AuthTokens_CompletionPublicationResults_CompletionPublicationId",
                table: "AuthTokens");

            migrationBuilder.DropIndex(
                name: "IX_AuthTokens_CompletionPublicationId",
                table: "AuthTokens");

            migrationBuilder.DropCheckConstraint(
                name: "CK_AuthToken_CompletionPartySha256",
                table: "AuthTokens");

            migrationBuilder.DropCheckConstraint(
                name: "CK_AuthToken_CompletionRecipeSha256",
                table: "AuthTokens");

            migrationBuilder.DropCheckConstraint(
                name: "CK_AuthToken_Purpose",
                table: "AuthTokens");

            migrationBuilder.DropCheckConstraint(
                name: "CK_Token_CompletionBinding",
                table: "AuthTokens");

            migrationBuilder.DropColumn(
                name: "CompletionPartySha256",
                table: "AuthTokens");

            migrationBuilder.DropColumn(
                name: "CompletionPublicationId",
                table: "AuthTokens");

            migrationBuilder.DropColumn(
                name: "CompletionRecipeSha256",
                table: "AuthTokens");

            migrationBuilder.AddCheckConstraint(
                name: "CK_AuthToken_Purpose",
                table: "AuthTokens",
                sql: "[Purpose] IS NULL OR [Purpose] IN ('SenderVerify','SenderStatus','SignerAccess','Lookup')");
        }
    }
}
