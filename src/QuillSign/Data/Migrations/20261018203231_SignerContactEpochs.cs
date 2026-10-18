using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuillSign.Data.Migrations
{
    /// <inheritdoc />
    public partial class SignerContactEpochs : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_AuthTokens_EnvelopeId",
                table: "AuthTokens");

            migrationBuilder.AddColumn<Guid>(
                name: "SignerContactRevisionId",
                table: "AuthTokens",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "SignerContactRevisions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EnvelopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SignerId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Number = table.Column<int>(type: "int", nullable: false),
                    PreviousRevisionId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ChangedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    EvidenceJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    RetirementJson = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SignerContactRevisions", x => x.Id);
                    table.UniqueConstraint("AK_SignerContactRevisions_EnvelopeId_SignerId_Id", x => new { x.EnvelopeId, x.SignerId, x.Id });
                    table.CheckConstraint("CK_ContactRevision_Json", "ISJSON([EvidenceJson])=1 AND DATALENGTH([EvidenceJson]) BETWEEN 2 AND 16384 AND ISJSON([RetirementJson])=1 AND DATALENGTH([RetirementJson]) BETWEEN 2 AND 4194304");
                    table.CheckConstraint("CK_ContactRevision_Number", "[Number] BETWEEN 1 AND 100 AND (([Number]=1 AND [PreviousRevisionId] IS NULL) OR ([Number]>1 AND [PreviousRevisionId] IS NOT NULL AND [PreviousRevisionId]<>[Id]))");
                    table.CheckConstraint("CK_ContactRevision_Time", "DATEPART(TZOFFSET,[ChangedAt])=0");
                    table.CheckConstraint("CK_SignerContactRevisionRecord_EvidenceJson", "[EvidenceJson] IS NULL OR ISJSON([EvidenceJson]) = 1");
                    table.CheckConstraint("CK_SignerContactRevisionRecord_RetirementJson", "[RetirementJson] IS NULL OR ISJSON([RetirementJson]) = 1");
                    table.ForeignKey(
                        name: "FK_SignerContactRevisions_Envelopes_EnvelopeId",
                        column: x => x.EnvelopeId,
                        principalTable: "Envelopes",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_SignerContactRevisions_SignerContactRevisions_EnvelopeId_SignerId_PreviousRevisionId",
                        columns: x => new { x.EnvelopeId, x.SignerId, x.PreviousRevisionId },
                        principalTable: "SignerContactRevisions",
                        principalColumns: new[] { "EnvelopeId", "SignerId", "Id" });
                    table.ForeignKey(
                        name: "FK_SignerContactRevisions_Signers_EnvelopeId_SignerId",
                        columns: x => new { x.EnvelopeId, x.SignerId },
                        principalTable: "Signers",
                        principalColumns: new[] { "EnvelopeId", "Id" });
                });

            migrationBuilder.CreateTable(
                name: "SignerContactSessions",
                columns: table => new
                {
                    SessionId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EnvelopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SignerId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RevisionId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SessionSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SignerContactSessions", x => x.SessionId);
                    table.CheckConstraint("CK_ContactSession_Identity", "[SessionId]<>'00000000-0000-0000-0000-000000000000' AND DATALENGTH([SessionSha256])=32");
                    table.CheckConstraint("CK_ContactSession_Time", "DATEPART(TZOFFSET,[CreatedAt])=0 AND DATEPART(TZOFFSET,[ExpiresAt])=0 AND [ExpiresAt]>[CreatedAt] AND [ExpiresAt]<=DATEADD(hour,24,[CreatedAt])");
                    table.CheckConstraint("CK_SignerContactSession_SessionSha256", "[SessionSha256] IS NULL OR DATALENGTH([SessionSha256]) = 32");
                    table.ForeignKey(
                        name: "FK_SignerContactSessions_Envelopes_EnvelopeId",
                        column: x => x.EnvelopeId,
                        principalTable: "Envelopes",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_SignerContactSessions_SignerContactRevisions_EnvelopeId_SignerId_RevisionId",
                        columns: x => new { x.EnvelopeId, x.SignerId, x.RevisionId },
                        principalTable: "SignerContactRevisions",
                        principalColumns: new[] { "EnvelopeId", "SignerId", "Id" });
                });

            migrationBuilder.CreateIndex(
                name: "IX_AuthTokens_EnvelopeId_PartyId_SignerContactRevisionId",
                table: "AuthTokens",
                columns: new[] { "EnvelopeId", "PartyId", "SignerContactRevisionId" });

            migrationBuilder.AddCheckConstraint(
                name: "CK_Token_ContactRevision",
                table: "AuthTokens",
                sql: "[SignerContactRevisionId] IS NULL OR ([Purpose]='SignerAccess' AND [PartyType]='Signer' AND [EnvelopeId] IS NOT NULL AND [PartyId] IS NOT NULL)");

            migrationBuilder.CreateIndex(
                name: "IX_SignerContactRevisions_EnvelopeId_SignerId_Number",
                table: "SignerContactRevisions",
                columns: new[] { "EnvelopeId", "SignerId", "Number" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SignerContactRevisions_EnvelopeId_SignerId_PreviousRevisionId",
                table: "SignerContactRevisions",
                columns: new[] { "EnvelopeId", "SignerId", "PreviousRevisionId" });

            migrationBuilder.CreateIndex(
                name: "IX_SignerContactSessions_EnvelopeId_SignerId_RevisionId",
                table: "SignerContactSessions",
                columns: new[] { "EnvelopeId", "SignerId", "RevisionId" });

            migrationBuilder.AddForeignKey(
                name: "FK_AuthTokens_SignerContactRevisions_EnvelopeId_PartyId_SignerContactRevisionId",
                table: "AuthTokens",
                columns: new[] { "EnvelopeId", "PartyId", "SignerContactRevisionId" },
                principalTable: "SignerContactRevisions",
                principalColumns: new[] { "EnvelopeId", "SignerId", "Id" });
            migrationBuilder.Sql("""
                CREATE OR ALTER PROCEDURE [dbo].[RemoveExpiredDemoPrivateRecords]
                    @EnvelopeId uniqueidentifier, @WorkId uniqueidentifier, @Owner uniqueidentifier,
                    @Attempt int, @Until datetimeoffset, @PolicySha256 nvarchar(64), @DeleteAfter datetimeoffset
                AS
                BEGIN
                    SET NOCOUNT ON;
                    SET XACT_ABORT ON;
                    DECLARE @Now datetimeoffset=TODATETIMEOFFSET(SYSUTCDATETIME(),'+00:00');
                    IF @@TRANCOUNT=0 OR XACT_STATE()<>1 OR @EnvelopeId IS NULL OR @WorkId IS NULL OR @Owner IS NULL
                       OR @EnvelopeId='00000000-0000-0000-0000-000000000000'
                       OR @WorkId='00000000-0000-0000-0000-000000000000'
                       OR @Owner='00000000-0000-0000-0000-000000000000'
                       OR @Attempt IS NULL OR @Attempt<1 OR @Until IS NULL OR @Until<=@Now
                       OR @DeleteAfter IS NULL OR @DeleteAfter>@Now OR DATEPART(TZOFFSET,@DeleteAfter)<>0
                       OR DATEPART(nanosecond,@DeleteAfter)<>0 OR @PolicySha256 IS NULL OR DATALENGTH(@PolicySha256)<>128
                       OR @PolicySha256 COLLATE Latin1_General_100_BIN2 LIKE N'%[^0-9a-f]%'
                        THROW 50001,'A current expired-demo cleanup scope is required.',1;
                    DECLARE @Present bit=0,@Demo bit;
                    SELECT @Present=1,@Demo=[IsDemo] FROM [dbo].[Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]=@EnvelopeId;
                    DECLARE @Payload nvarchar(1024)=N'{"version":"demo-purge-storage-v1","envelopeId":"'
                        +LOWER(CONVERT(nvarchar(36),@EnvelopeId))+N'","retentionSha256":"'+@PolicySha256
                        +N'","deleteAfter":"'+CONVERT(nvarchar(19),CONVERT(datetime2,@DeleteAfter),126)+N'+00:00"}';
                    IF NOT EXISTS(SELECT 1 FROM [dbo].[WorkItems] WITH(UPDLOCK,HOLDLOCK)
                        WHERE [Id]=@WorkId AND [Kind] COLLATE Latin1_General_100_BIN2=N'Purge'
                        AND [Status] COLLATE Latin1_General_100_BIN2=N'Leased' AND [Attempts]=@Attempt
                        AND [LeaseOwner]=@Owner AND [LeaseExpiresAt]=@Until AND [AvailableAt]<=@Now
                        AND DATALENGTH([PayloadJson])=DATALENGTH(@Payload)
                        AND [PayloadJson] COLLATE Latin1_General_100_BIN2=@Payload
                        AND ((@Present=1 AND [EnvelopeId]=@EnvelopeId) OR (@Present=0 AND [EnvelopeId] IS NULL)))
                        THROW 50001,'The cleanup lease or payload could not be verified.',1;
                    IF @Present=0 BEGIN SELECT CAST(0 AS bit); RETURN; END;
                    IF @Demo<>1 OR NOT EXISTS(SELECT 1 FROM [dbo].[DocumentRetentionSnapshots] AS p
                        WHERE p.[EnvelopeId]=@EnvelopeId AND p.[PolicyVersion] COLLATE Latin1_General_100_BIN2=N'demo-upload-retention-v1'
                        AND DATALENGTH(p.[PolicyVersion])=DATALENGTH(N'demo-upload-retention-v1') AND DATEPART(nanosecond,p.[StartedAt])=0
                        AND p.[Days] BETWEEN 1 AND 36500 AND p.[DeleteAfter]=@DeleteAfter
                        AND DATEPART(TZOFFSET,p.[StartedAt])=0 AND p.[DeleteAfter]=DATEADD(day,p.[Days],p.[StartedAt])
                        AND (SELECT COUNT_BIG(*) FROM [dbo].[AuditEvents] WHERE [EnvelopeId]=@EnvelopeId
                            AND [Event] COLLATE Latin1_General_100_BIN2=N'document_uploaded')=1
                        AND EXISTS(SELECT 1 FROM [dbo].[AuditEvents] AS a JOIN [dbo].[Envelopes] AS e ON e.[Id]=a.[EnvelopeId]
                            WHERE a.[EnvelopeId]=@EnvelopeId AND a.[Event] COLLATE Latin1_General_100_BIN2=N'document_uploaded'
                            AND a.[ActorType] COLLATE Latin1_General_100_BIN2=N'Sender'
                            AND a.[ActorEmail] COLLATE Latin1_General_100_BIN2=e.[SenderEmail] COLLATE Latin1_General_100_BIN2
                            AND a.[At]>=p.[StartedAt] AND a.[At]<p.[DeleteAfter] AND DATALENGTH(a.[DataJson])<=32768
                            AND JSON_VALUE(a.[DataJson],'$.retentionSha256') COLLATE Latin1_General_100_BIN2=@PolicySha256
                            AND JSON_VALUE(a.[DataJson],'$.originalSha256') COLLATE Latin1_General_100_BIN2=LOWER(CONVERT(varchar(64),p.[OriginalSha256],2))
                            AND JSON_VALUE(a.[DataJson],'$.pdfSha256') COLLATE Latin1_General_100_BIN2=LOWER(CONVERT(varchar(64),p.[PdfSha256],2))))
                        THROW 50001,'The saved demo enrollment could not be verified.',1;

                    -- All components are constrained ASCII. Match the immutable .NET
                    -- enrollment digest, including base64 hashes, before erasing evidence.
                    DECLARE @PolicyJson varchar(max);
                    SELECT @PolicyJson='{"EnvelopeId":"'+LOWER(CONVERT(varchar(36),p.[EnvelopeId]))
                        +'","PolicyVersion":"demo-upload-retention-v1","Days":'+CONVERT(varchar(5),p.[Days])
                        +',"StartedAt":"'+CONVERT(varchar(19),CONVERT(datetime2,p.[StartedAt]),126)+'+00:00'
                        +'","DeleteAfter":"'+CONVERT(varchar(19),CONVERT(datetime2,p.[DeleteAfter]),126)+'+00:00'
                        +'","OriginalObjectId":"'+LOWER(CONVERT(varchar(36),p.[OriginalObjectId]))
                        +'","OriginalSha256":"'+(SELECT CONVERT(varbinary(32),p.[OriginalSha256]) FOR XML PATH(''),BINARY BASE64)
                        +'","PdfObjectId":"'+LOWER(CONVERT(varchar(36),p.[PdfObjectId]))
                        +'","PdfSha256":"'+(SELECT CONVERT(varbinary(32),p.[PdfSha256]) FOR XML PATH(''),BINARY BASE64)+'"}'
                        FROM [dbo].[DocumentRetentionSnapshots] AS p WHERE p.[EnvelopeId]=@EnvelopeId;
                    IF @PolicyJson IS NULL OR LOWER(CONVERT(varchar(64),HASHBYTES('SHA2_256',@PolicyJson),2)) COLLATE Latin1_General_100_BIN2<>@PolicySha256
                        THROW 50001,'The saved demo policy digest could not be verified.',1;

                    UPDATE [dbo].[Envelopes] SET [CurrentFinishId]=NULL,[CurrentCopyVersion]=0 WHERE [Id]=@EnvelopeId;
                    DELETE FROM [dbo].[AuthTokens] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[Fields] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[CompletionPublicationResults] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[CompletionPublicationIntents] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[CompletionSealOutputs] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[CompletionCandidates] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[SignerFinishAcceptances] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[SignerReviewCandidates] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[SignaturePreviews] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[SignerContactSessions] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[SignerContactRevisions] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[Signers] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[Recipients] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[WorkItems] WHERE [EnvelopeId]=@EnvelopeId AND [Id]<>@WorkId;
                    DELETE FROM [dbo].[EmailOutbox] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[AuditEvents] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[DocumentRetentionSnapshots] WHERE [EnvelopeId]=@EnvelopeId;
                    UPDATE [dbo].[WorkItems] SET [EnvelopeId]=NULL,[LastError]=NULL WHERE [Id]=@WorkId;
                    DELETE FROM [dbo].[Envelopes] WHERE [Id]=@EnvelopeId;
                    IF @Until<=TODATETIMEOFFSET(SYSUTCDATETIME(),'+00:00')
                        THROW 50001,'The cleanup lease expired before commit.',1;
                    SELECT CAST(1 AS bit);
                END
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                CREATE OR ALTER PROCEDURE [dbo].[RemoveExpiredDemoPrivateRecords]
                    @EnvelopeId uniqueidentifier, @WorkId uniqueidentifier, @Owner uniqueidentifier,
                    @Attempt int, @Until datetimeoffset, @PolicySha256 nvarchar(64), @DeleteAfter datetimeoffset
                AS
                BEGIN
                    SET NOCOUNT ON;
                    SET XACT_ABORT ON;
                    DECLARE @Now datetimeoffset=TODATETIMEOFFSET(SYSUTCDATETIME(),'+00:00');
                    IF @@TRANCOUNT=0 OR XACT_STATE()<>1 OR @EnvelopeId IS NULL OR @WorkId IS NULL OR @Owner IS NULL
                       OR @EnvelopeId='00000000-0000-0000-0000-000000000000'
                       OR @WorkId='00000000-0000-0000-0000-000000000000'
                       OR @Owner='00000000-0000-0000-0000-000000000000'
                       OR @Attempt IS NULL OR @Attempt<1 OR @Until IS NULL OR @Until<=@Now
                       OR @DeleteAfter IS NULL OR @DeleteAfter>@Now OR DATEPART(TZOFFSET,@DeleteAfter)<>0
                       OR DATEPART(nanosecond,@DeleteAfter)<>0 OR @PolicySha256 IS NULL OR DATALENGTH(@PolicySha256)<>128
                       OR @PolicySha256 COLLATE Latin1_General_100_BIN2 LIKE N'%[^0-9a-f]%'
                        THROW 50001,'A current expired-demo cleanup scope is required.',1;
                    DECLARE @Present bit=0,@Demo bit;
                    SELECT @Present=1,@Demo=[IsDemo] FROM [dbo].[Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]=@EnvelopeId;
                    DECLARE @Payload nvarchar(1024)=N'{"version":"demo-purge-storage-v1","envelopeId":"'
                        +LOWER(CONVERT(nvarchar(36),@EnvelopeId))+N'","retentionSha256":"'+@PolicySha256
                        +N'","deleteAfter":"'+CONVERT(nvarchar(19),CONVERT(datetime2,@DeleteAfter),126)+N'+00:00"}';
                    IF NOT EXISTS(SELECT 1 FROM [dbo].[WorkItems] WITH(UPDLOCK,HOLDLOCK)
                        WHERE [Id]=@WorkId AND [Kind] COLLATE Latin1_General_100_BIN2=N'Purge'
                        AND [Status] COLLATE Latin1_General_100_BIN2=N'Leased' AND [Attempts]=@Attempt
                        AND [LeaseOwner]=@Owner AND [LeaseExpiresAt]=@Until AND [AvailableAt]<=@Now
                        AND DATALENGTH([PayloadJson])=DATALENGTH(@Payload)
                        AND [PayloadJson] COLLATE Latin1_General_100_BIN2=@Payload
                        AND ((@Present=1 AND [EnvelopeId]=@EnvelopeId) OR (@Present=0 AND [EnvelopeId] IS NULL)))
                        THROW 50001,'The cleanup lease or payload could not be verified.',1;
                    IF @Present=0 BEGIN SELECT CAST(0 AS bit); RETURN; END;
                    IF @Demo<>1 OR NOT EXISTS(SELECT 1 FROM [dbo].[DocumentRetentionSnapshots] AS p
                        WHERE p.[EnvelopeId]=@EnvelopeId AND p.[PolicyVersion] COLLATE Latin1_General_100_BIN2=N'demo-upload-retention-v1'
                        AND DATALENGTH(p.[PolicyVersion])=DATALENGTH(N'demo-upload-retention-v1') AND DATEPART(nanosecond,p.[StartedAt])=0
                        AND p.[Days] BETWEEN 1 AND 36500 AND p.[DeleteAfter]=@DeleteAfter
                        AND DATEPART(TZOFFSET,p.[StartedAt])=0 AND p.[DeleteAfter]=DATEADD(day,p.[Days],p.[StartedAt])
                        AND (SELECT COUNT_BIG(*) FROM [dbo].[AuditEvents] WHERE [EnvelopeId]=@EnvelopeId
                            AND [Event] COLLATE Latin1_General_100_BIN2=N'document_uploaded')=1
                        AND EXISTS(SELECT 1 FROM [dbo].[AuditEvents] AS a JOIN [dbo].[Envelopes] AS e ON e.[Id]=a.[EnvelopeId]
                            WHERE a.[EnvelopeId]=@EnvelopeId AND a.[Event] COLLATE Latin1_General_100_BIN2=N'document_uploaded'
                            AND a.[ActorType] COLLATE Latin1_General_100_BIN2=N'Sender'
                            AND a.[ActorEmail] COLLATE Latin1_General_100_BIN2=e.[SenderEmail] COLLATE Latin1_General_100_BIN2
                            AND a.[At]>=p.[StartedAt] AND a.[At]<p.[DeleteAfter] AND DATALENGTH(a.[DataJson])<=32768
                            AND JSON_VALUE(a.[DataJson],'$.retentionSha256') COLLATE Latin1_General_100_BIN2=@PolicySha256
                            AND JSON_VALUE(a.[DataJson],'$.originalSha256') COLLATE Latin1_General_100_BIN2=LOWER(CONVERT(varchar(64),p.[OriginalSha256],2))
                            AND JSON_VALUE(a.[DataJson],'$.pdfSha256') COLLATE Latin1_General_100_BIN2=LOWER(CONVERT(varchar(64),p.[PdfSha256],2))))
                        THROW 50001,'The saved demo enrollment could not be verified.',1;

                    -- All components are constrained ASCII. Match the immutable .NET
                    -- enrollment digest, including base64 hashes, before erasing evidence.
                    DECLARE @PolicyJson varchar(max);
                    SELECT @PolicyJson='{"EnvelopeId":"'+LOWER(CONVERT(varchar(36),p.[EnvelopeId]))
                        +'","PolicyVersion":"demo-upload-retention-v1","Days":'+CONVERT(varchar(5),p.[Days])
                        +',"StartedAt":"'+CONVERT(varchar(19),CONVERT(datetime2,p.[StartedAt]),126)+'+00:00'
                        +'","DeleteAfter":"'+CONVERT(varchar(19),CONVERT(datetime2,p.[DeleteAfter]),126)+'+00:00'
                        +'","OriginalObjectId":"'+LOWER(CONVERT(varchar(36),p.[OriginalObjectId]))
                        +'","OriginalSha256":"'+(SELECT CONVERT(varbinary(32),p.[OriginalSha256]) FOR XML PATH(''),BINARY BASE64)
                        +'","PdfObjectId":"'+LOWER(CONVERT(varchar(36),p.[PdfObjectId]))
                        +'","PdfSha256":"'+(SELECT CONVERT(varbinary(32),p.[PdfSha256]) FOR XML PATH(''),BINARY BASE64)+'"}'
                        FROM [dbo].[DocumentRetentionSnapshots] AS p WHERE p.[EnvelopeId]=@EnvelopeId;
                    IF @PolicyJson IS NULL OR LOWER(CONVERT(varchar(64),HASHBYTES('SHA2_256',@PolicyJson),2)) COLLATE Latin1_General_100_BIN2<>@PolicySha256
                        THROW 50001,'The saved demo policy digest could not be verified.',1;

                    UPDATE [dbo].[Envelopes] SET [CurrentFinishId]=NULL,[CurrentCopyVersion]=0 WHERE [Id]=@EnvelopeId;
                    DELETE FROM [dbo].[AuthTokens] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[Fields] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[CompletionPublicationResults] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[CompletionPublicationIntents] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[CompletionSealOutputs] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[CompletionCandidates] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[SignerFinishAcceptances] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[SignerReviewCandidates] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[SignaturePreviews] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[Signers] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[Recipients] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[WorkItems] WHERE [EnvelopeId]=@EnvelopeId AND [Id]<>@WorkId;
                    DELETE FROM [dbo].[EmailOutbox] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[AuditEvents] WHERE [EnvelopeId]=@EnvelopeId;
                    DELETE FROM [dbo].[DocumentRetentionSnapshots] WHERE [EnvelopeId]=@EnvelopeId;
                    UPDATE [dbo].[WorkItems] SET [EnvelopeId]=NULL,[LastError]=NULL WHERE [Id]=@WorkId;
                    DELETE FROM [dbo].[Envelopes] WHERE [Id]=@EnvelopeId;
                    IF @Until<=TODATETIMEOFFSET(SYSUTCDATETIME(),'+00:00')
                        THROW 50001,'The cleanup lease expired before commit.',1;
                    SELECT CAST(1 AS bit);
                END
                """);
            migrationBuilder.DropForeignKey(
                name: "FK_AuthTokens_SignerContactRevisions_EnvelopeId_PartyId_SignerContactRevisionId",
                table: "AuthTokens");

            migrationBuilder.DropTable(
                name: "SignerContactSessions");

            migrationBuilder.DropTable(
                name: "SignerContactRevisions");

            migrationBuilder.DropIndex(
                name: "IX_AuthTokens_EnvelopeId_PartyId_SignerContactRevisionId",
                table: "AuthTokens");

            migrationBuilder.DropCheckConstraint(
                name: "CK_Token_ContactRevision",
                table: "AuthTokens");

            migrationBuilder.DropColumn(
                name: "SignerContactRevisionId",
                table: "AuthTokens");

            migrationBuilder.CreateIndex(
                name: "IX_AuthTokens_EnvelopeId",
                table: "AuthTokens",
                column: "EnvelopeId");
        }
    }
}
