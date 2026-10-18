using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuillSign.Data.Migrations
{
    /// <inheritdoc />
    public partial class LookupContactRetention : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "LookupContactRetentionSnapshots",
                columns: table => new
                {
                    RequestId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PolicyVersion = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    Days = table.Column<int>(type: "int", nullable: false),
                    StartedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    DeleteAfter = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LookupContactRetentionSnapshots", x => x.RequestId);
                    table.CheckConstraint("CK_LookupContactRetention_Interval", "[Days] BETWEEN 1 AND 36500 AND DATEPART(TZOFFSET,[StartedAt]) = 0 AND DATEPART(TZOFFSET,[DeleteAfter]) = 0 AND DATEPART(nanosecond,[StartedAt]) = 0 AND [DeleteAfter] = DATEADD(day,[Days],[StartedAt])");
                    table.ForeignKey(
                        name: "FK_LookupContactRetentionSnapshots_EmailOutbox_RequestId",
                        column: x => x.RequestId,
                        principalTable: "EmailOutbox",
                        principalColumn: "Id");
                });
            // Static same-owner scope: neither caller gets general snapshot deletion.
            // EXECUTE is granted only by the explicit worker provisioning command.
            migrationBuilder.Sql("""
                CREATE PROCEDURE [dbo].[RemoveExpiredLookupContacts]
                    @RequestId uniqueidentifier, @WorkId uniqueidentifier, @Owner uniqueidentifier,
                    @Attempt int, @Until datetimeoffset, @PolicySha256 nvarchar(64), @DeleteAfter datetimeoffset
                AS
                BEGIN
                    SET NOCOUNT ON;
                    SET XACT_ABORT ON;
                    DECLARE @Now datetimeoffset=TODATETIMEOFFSET(SYSUTCDATETIME(),'+00:00');
                    IF @@TRANCOUNT=0 OR XACT_STATE()<>1 OR @RequestId IS NULL OR @WorkId IS NULL OR @Owner IS NULL
                        OR @RequestId='00000000-0000-0000-0000-000000000000' OR @Owner='00000000-0000-0000-0000-000000000000'
                        OR @Attempt IS NULL OR @Attempt<1 OR @Until IS NULL OR @Until<=@Now
                        OR @DeleteAfter IS NULL OR @DeleteAfter>@Now OR DATEPART(TZOFFSET,@DeleteAfter)<>0 OR DATEPART(nanosecond,@DeleteAfter)<>0
                        OR @PolicySha256 IS NULL OR DATALENGTH(@PolicySha256)<>128
                        OR @PolicySha256 COLLATE Latin1_General_100_BIN2 LIKE N'%[^0-9a-f]%'
                        THROW 50001,'A current expired lookup contact cleanup scope is required.',1;
                    DECLARE @ExpectedWork uniqueidentifier=CONVERT(uniqueidentifier,SUBSTRING(HASHBYTES('SHA2_256',
                        'lookup-contact-purge-work-v1:'+REPLACE(LOWER(CONVERT(varchar(36),@RequestId)),'-','')),1,16));
                    IF @WorkId<>@ExpectedWork THROW 50001,'The lookup cleanup identifier is invalid.',1;
                    DECLARE @Lock int;
                    EXEC @Lock=sys.sp_getapplock @Resource=N'lookup-delivery-v1',@LockMode='Exclusive',@LockOwner='Transaction',@LockTimeout=5000;
                    IF @Lock<0 THROW 50002,'Lookup cleanup is temporarily busy.',1;
                    DECLARE @Payload nvarchar(1024)=N'{"version":"lookup-contact-purge-v1","requestId":"'
                        +LOWER(CONVERT(nvarchar(36),@RequestId))+N'","retentionSha256":"'+@PolicySha256
                        +N'","deleteAfter":"'+CONVERT(nvarchar(19),CONVERT(datetime2,@DeleteAfter),126)+N'+00:00"}';
                    IF NOT EXISTS(SELECT 1 FROM [dbo].[WorkItems] WITH(UPDLOCK,HOLDLOCK)
                        WHERE [Id]=@WorkId AND [EnvelopeId] IS NULL AND [Kind] COLLATE Latin1_General_100_BIN2=N'Purge'
                        AND [Status] COLLATE Latin1_General_100_BIN2=N'Leased' AND [Attempts]=@Attempt AND [LeaseOwner]=@Owner
                        AND [LeaseExpiresAt]=@Until AND [AvailableAt]<=@Now AND DATALENGTH([PayloadJson])=DATALENGTH(@Payload)
                        AND [PayloadJson] COLLATE Latin1_General_100_BIN2=@Payload)
                        THROW 50001,'The lookup cleanup lease or payload could not be verified.',1;
                    DECLARE @MailPayload nvarchar(100)=N'{"emailId":"'+LOWER(CONVERT(nvarchar(36),@RequestId))+N'"}';
                    DECLARE @MailStatus nvarchar(32),@MailLease datetimeoffset,@MailError nvarchar(4000);
                    SELECT @MailStatus=[Status],@MailLease=[LeaseExpiresAt],@MailError=[LastError]
                        FROM [dbo].[WorkItems] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]=@RequestId AND [EnvelopeId] IS NULL
                        AND [Kind] COLLATE Latin1_General_100_BIN2=N'Email' AND DATALENGTH([PayloadJson])=DATALENGTH(@MailPayload)
                        AND [PayloadJson] COLLATE Latin1_General_100_BIN2=@MailPayload;
                    IF @MailStatus IS NULL THROW 50001,'The original lookup email work scope is unavailable.',1;
                    IF @MailLease>TODATETIMEOFFSET(SYSUTCDATETIME(),'+00:00') THROW 50002,'Lookup delivery still owns a live lease.',1;
                    DECLARE @Present bit=0,@EnvelopeId uniqueidentifier,@Template nvarchar(512),@Attachments nvarchar(max),
                        @RequestedAt datetimeoffset,@Intent datetimeoffset,@EmailStatus nvarchar(32),@OutboxLease datetimeoffset;
                    SELECT @Present=1,@EnvelopeId=[EnvelopeId],@Template=[Template],@Attachments=[AttachmentsJson],@RequestedAt=[AvailableAt],
                        @Intent=[SubmissionStartedAt],@EmailStatus=[Status],@OutboxLease=[LeaseExpiresAt]
                        FROM [dbo].[EmailOutbox] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]=@RequestId;
                    IF @Present=0 BEGIN
                        IF EXISTS(SELECT 1 FROM [dbo].[LookupContactRetentionSnapshots] WHERE [RequestId]=@RequestId)
                            OR NOT ((@MailStatus COLLATE Latin1_General_100_BIN2=N'Completed' AND @MailError COLLATE Latin1_General_100_BIN2=N'lookup-contact-sent')
                                OR (@MailStatus COLLATE Latin1_General_100_BIN2=N'Failed' AND @MailError COLLATE Latin1_General_100_BIN2 IN (N'lookup-contact-expired',N'submission-ambiguous')))
                            THROW 50001,'The lookup cleanup replay binding is unavailable.',1;
                        SELECT CAST(0 AS bit); RETURN;
                    END;
                    IF @EnvelopeId IS NOT NULL OR @Template COLLATE Latin1_General_100_BIN2<>N'document-lookup'
                        OR DATALENGTH(@Template)<>DATALENGTH(N'document-lookup') OR @Attachments COLLATE Latin1_General_100_BIN2<>N'[]'
                        OR DATALENGTH(@Attachments)<>4 OR DATEPART(TZOFFSET,@RequestedAt)<>0
                        THROW 50001,'Only the exact envelope-null lookup outbox may be cleaned.',1;
                    IF @OutboxLease>TODATETIMEOFFSET(SYSUTCDATETIME(),'+00:00') THROW 50002,'The outbox still owns a live lease.',1;
                    DECLARE @PolicyJson varchar(max),@StartedAt datetimeoffset,@Days int;
                    SELECT @StartedAt=[StartedAt],@Days=[Days],@PolicyJson='{"RequestId":"'+LOWER(CONVERT(varchar(36),[RequestId]))
                        +'","PolicyVersion":"lookup-contact-retention-v1","Days":'+CONVERT(varchar(5),[Days])
                        +',"StartedAt":"'+CONVERT(varchar(19),CONVERT(datetime2,[StartedAt]),126)+'+00:00'
                        +'","DeleteAfter":"'+CONVERT(varchar(19),CONVERT(datetime2,[DeleteAfter]),126)+'+00:00"}'
                        FROM [dbo].[LookupContactRetentionSnapshots] WITH(UPDLOCK,HOLDLOCK)
                        WHERE [RequestId]=@RequestId AND [PolicyVersion] COLLATE Latin1_General_100_BIN2=N'lookup-contact-retention-v1'
                        AND DATALENGTH([PolicyVersion])=DATALENGTH(N'lookup-contact-retention-v1') AND [Days] BETWEEN 1 AND 36500
                        AND DATEPART(TZOFFSET,[StartedAt])=0 AND DATEPART(nanosecond,[StartedAt])=0
                        AND DATEPART(TZOFFSET,[DeleteAfter])=0 AND [DeleteAfter]=DATEADD(day,[Days],[StartedAt]) AND [DeleteAfter]=@DeleteAfter;
                    IF @PolicyJson IS NULL OR LOWER(CONVERT(varchar(64),HASHBYTES('SHA2_256',@PolicyJson),2)) COLLATE Latin1_General_100_BIN2<>@PolicySha256
                        OR @RequestedAt<@StartedAt OR @RequestedAt>=DATEADD(second,1,@StartedAt)
                        OR (@Days=1 AND @Intent>=TODATETIMEOFFSET(DATEADD(day,1,CONVERT(datetime2,CONVERT(date,@StartedAt))),'+00:00'))
                        THROW 50001,'The original lookup retention policy or daily-counter bound could not be verified.',1;
                    -- Preserve technical disposition, including uncertain submission, with
                    -- no recipient, IP hash, protected payload, provider ID or error text.
                    UPDATE [dbo].[WorkItems] SET
                        [Status]=CASE WHEN @EmailStatus IN(N'Sent',N'Bounced',N'Complained') THEN N'Completed' ELSE N'Failed' END,
                        [LastError]=CASE WHEN @EmailStatus IN(N'Sent',N'Bounced',N'Complained') THEN N'lookup-contact-sent'
                            WHEN @Intent IS NOT NULL OR @MailError=N'submission-ambiguous' THEN N'submission-ambiguous' ELSE N'lookup-contact-expired' END,
                        [PayloadJson]=@MailPayload,[LeaseOwner]=NULL,[LeaseExpiresAt]=NULL WHERE [Id]=@RequestId;
                    DELETE FROM [dbo].[LookupContactRetentionSnapshots] WHERE [RequestId]=@RequestId;
                    DELETE FROM [dbo].[EmailOutbox] WHERE [Id]=@RequestId;
                    IF @Until<=TODATETIMEOFFSET(SYSUTCDATETIME(),'+00:00') THROW 50001,'The lookup cleanup lease expired before commit.',1;
                    SELECT CAST(1 AS bit);
                END
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("DROP PROCEDURE [dbo].[RemoveExpiredLookupContacts]");
            migrationBuilder.DropTable(
                name: "LookupContactRetentionSnapshots");
        }
    }
}
