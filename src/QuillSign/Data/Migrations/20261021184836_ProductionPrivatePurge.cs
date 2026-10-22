using Microsoft.EntityFrameworkCore.Migrations;
#nullable disable
namespace QuillSign.Data.Migrations;
public partial class ProductionPrivatePurge : Migration
{
 protected override void Up(MigrationBuilder migrationBuilder)
 {
  migrationBuilder.DropCheckConstraint(name:"CK_WorkItem_Kind",table:"WorkItems");
  migrationBuilder.AddCheckConstraint(name:"CK_WorkItem_Kind",table:"WorkItems",sql:"[Kind] IS NULL OR [Kind] IN ('Conversion','Ai','Rendering','Sealing','Email','Purge','Expiry','Reminder','ProductionPurge')");
  migrationBuilder.Sql("""
   CREATE OR ALTER PROCEDURE [dbo].[RemoveExpiredProductionPrivateRecords]
    @EnvelopeId uniqueidentifier,@DeletionId uniqueidentifier,@WorkId uniqueidentifier,@Owner uniqueidentifier,
    @Attempt int,@Until datetimeoffset,@ParentRowVersion varbinary(8),@PolicySha256 varchar(64),@EligibleAt datetimeoffset,
    @RequestRevision bigint,@FenceHash varchar(64)=NULL,@ControlSequence bigint=0,@ControlHash varchar(64)=NULL,
    @CountsJson nvarchar(max)=NULL,@PlanSha256 varchar(64)=NULL,@StorageReceiptSha256 varchar(64)=NULL
   AS
   BEGIN
    SET NOCOUNT ON;SET XACT_ABORT ON;
    DECLARE @Now datetimeoffset=TODATETIMEOFFSET(SYSUTCDATETIME(),'+00:00');
    IF @@TRANCOUNT=0 OR XACT_STATE()<>1 OR @EnvelopeId IS NULL OR @DeletionId IS NULL OR @WorkId IS NULL OR @Owner IS NULL
    OR @EnvelopeId='00000000-0000-0000-0000-000000000000' OR @DeletionId='00000000-0000-0000-0000-000000000000'
    OR @WorkId='00000000-0000-0000-0000-000000000000' OR @Owner='00000000-0000-0000-0000-000000000000'
    OR @Attempt IS NULL OR @Attempt<1 OR @Until IS NULL OR @Until<=@Now OR DATEPART(TZOFFSET,@Until)<>0
    OR DATALENGTH(@ParentRowVersion)<>8 OR @ParentRowVersion IS NULL OR @EligibleAt IS NULL OR @EligibleAt>@Now OR DATEPART(TZOFFSET,@EligibleAt)<>0
    OR @RequestRevision IS NULL OR @RequestRevision NOT BETWEEN 0 AND 512 OR @ControlSequence IS NULL OR @ControlSequence NOT BETWEEN 0 AND 16384
    OR @PolicySha256 IS NULL OR DATALENGTH(@PolicySha256)<>64 OR @PolicySha256 COLLATE Latin1_General_100_BIN2 LIKE '%[^0-9a-f]%'
    OR @PlanSha256 IS NULL OR DATALENGTH(@PlanSha256)<>64 OR @PlanSha256 COLLATE Latin1_General_100_BIN2 LIKE '%[^0-9a-f]%'
    OR @StorageReceiptSha256 IS NULL OR DATALENGTH(@StorageReceiptSha256)<>64 OR @StorageReceiptSha256 COLLATE Latin1_General_100_BIN2 LIKE '%[^0-9a-f]%'
     THROW 50001,'A current exact production deletion SQL scope is required.',1;
    -- External authenticated scope/journal prove deletion authority. These hashes
    -- correlate that intent only; SQL does not prove DP/provider/copy commitments.
    DECLARE @Present bit=0,@Demo bit,@Status nvarchar(32),@Created datetimeoffset,@Version binary(8);
    SELECT @Present=1,@Demo=[IsDemo],@Status=[Status],@Created=[CreatedAt],@Version=[RowVersion]
    FROM [dbo].[Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]=@EnvelopeId;
    DECLARE @Payload nvarchar(1024)=N'{"Version":"production-delete-work-v1","RecordId":"'
    +LOWER(CONVERT(nvarchar(36),@EnvelopeId))+N'","DeletionId":"'+LOWER(CONVERT(nvarchar(36),@DeletionId))+N'"}';
    IF NOT EXISTS(SELECT 1 FROM [dbo].[WorkItems] WITH(UPDLOCK,HOLDLOCK)
    WHERE [Id]=@WorkId AND [Kind] COLLATE Latin1_General_100_BIN2=N'ProductionPurge'
    AND [Status] COLLATE Latin1_General_100_BIN2=N'Leased' AND [Attempts]=@Attempt AND [LeaseOwner]=@Owner
    AND [LeaseExpiresAt]=@Until AND [AvailableAt]<=@Now AND DATALENGTH([PayloadJson])=DATALENGTH(@Payload)
    AND [PayloadJson] COLLATE Latin1_General_100_BIN2=@Payload AND ((@Present=1 AND [EnvelopeId]=@EnvelopeId) OR (@Present=0 AND [EnvelopeId] IS NULL)))
     THROW 50001,'The exact production deletion lease or payload is unavailable.',1;
    IF @Present=0 BEGIN SELECT CAST(0 AS bit);RETURN;END;
    IF @Demo<>0 OR @Version<>@ParentRowVersion OR EXISTS(SELECT 1 FROM [dbo].[DocumentRetentionSnapshots] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId)
    OR EXISTS(SELECT 1 FROM [dbo].[EmailPilotEnrollments] WITH(HOLDLOCK) WHERE [SubjectEnvelopeId]=@EnvelopeId)
    OR EXISTS(SELECT 1 FROM [dbo].[EmailPilotReservations] WITH(HOLDLOCK) WHERE [SubjectEnvelopeId]=@EnvelopeId)
    OR EXISTS(SELECT 1 FROM [dbo].[EmailPilotLookupRequests] WITH(HOLDLOCK) WHERE [SubjectEnvelopeId]=@EnvelopeId)
     THROW 50001,'Production provenance or direct pilot association changed.',1;
    -- Forward-compatible fixed SQL name; no dynamic SQL or opaque-manifest scan.
    IF OBJECT_ID(N'dbo.EmailPilotCloseoutOperations',N'U') IS NOT NULL
    BEGIN
     IF EXISTS(SELECT 1 FROM [dbo].[EmailPilotCloseoutOperations] WITH(HOLDLOCK) WHERE [SubjectEnvelopeId]=@EnvelopeId)
      THROW 50001,'A closeout association prevents production deletion.',1;
    END;
    IF EXISTS(SELECT 1 FROM [dbo].[AuthTokens] AS t WITH(HOLDLOCK) JOIN [dbo].[CompletionPublicationResults] AS p WITH(HOLDLOCK)
    ON p.[Id]=t.[CompletionPublicationId] WHERE p.[EnvelopeId]=@EnvelopeId AND (t.[EnvelopeId] IS NULL OR t.[EnvelopeId]<>@EnvelopeId))
     THROW 50001,'A foreign publication token prevents deletion.',1;
    DECLARE @PolicyJson nvarchar(max),@Original datetimeoffset;
    SELECT @PolicyJson=[PolicyJson],@Original=[OriginalCreatedAt] FROM [dbo].[ProductionRetentionPolicies] WITH(HOLDLOCK)
    WHERE [EnvelopeId]=@EnvelopeId AND [PolicySha256] COLLATE Latin1_General_100_BIN2=@PolicySha256;
    IF @PolicyJson IS NULL OR @Original<>@Created OR ISJSON(@PolicyJson)<>1
    OR LOWER(CONVERT(varchar(64),HASHBYTES('SHA2_256',CONVERT(varchar(max),@PolicyJson COLLATE Latin1_General_100_BIN2_UTF8)),2)) COLLATE Latin1_General_100_BIN2<>@PolicySha256
    OR ISNULL(JSON_VALUE(@PolicyJson,'$.FormatVersion'),N'') COLLATE Latin1_General_100_BIN2<>'production-retention-v1'
    OR ISNULL(TRY_CONVERT(uniqueidentifier,JSON_VALUE(@PolicyJson,'$.RecordId')),'00000000-0000-0000-0000-000000000000')<>@EnvelopeId
     THROW 50001,'The exact original production policy changed.',1;
    DECLARE @Days int,@Start datetimeoffset,@TerminalStatus nvarchar(32);
    IF @Status COLLATE Latin1_General_100_BIN2=N'Draft'
    BEGIN
     IF EXISTS(SELECT 1 FROM [dbo].[ProductionRetentionTerminals] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId)
      THROW 50001,'Draft terminal provenance changed.',1;
     SET @Days=TRY_CONVERT(int,JSON_VALUE(@PolicyJson,'$.Policy.AbandonedDraftDays'));SET @Start=@Original;
    END
    ELSE
    BEGIN
     SELECT @Start=[OriginalAt],@TerminalStatus=[Status] FROM [dbo].[ProductionRetentionTerminals] WITH(HOLDLOCK)
      WHERE [EnvelopeId]=@EnvelopeId AND [PolicySha256] COLLATE Latin1_General_100_BIN2=@PolicySha256;
     IF @TerminalStatus IS NULL OR @TerminalStatus COLLATE Latin1_General_100_BIN2<>@Status COLLATE Latin1_General_100_BIN2
      THROW 50001,'Exact terminal production provenance is required.',1;
     SET @Days=CASE @Status COLLATE Latin1_General_100_BIN2 WHEN N'Completed' THEN TRY_CONVERT(int,JSON_VALUE(@PolicyJson,'$.Policy.CompletedDays'))
      WHEN N'Expired' THEN TRY_CONVERT(int,JSON_VALUE(@PolicyJson,'$.Policy.ExpiredDays')) WHEN N'Declined' THEN TRY_CONVERT(int,JSON_VALUE(@PolicyJson,'$.Policy.DeclinedDays'))
      WHEN N'Voided' THEN TRY_CONVERT(int,JSON_VALUE(@PolicyJson,'$.Policy.VoidedDays')) END;
    END;
    IF @Days IS NULL OR @Days NOT BETWEEN 1 AND 36500 OR @Start IS NULL OR DATEADD(day,@Days,@Start)<>@EligibleAt
     THROW 50001,'The original finite production policy is not eligible.',1;
    IF (SELECT COUNT_BIG(*) FROM [dbo].[ProductionHoldRequests] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId)<>@RequestRevision
    OR (@RequestRevision=0 AND @FenceHash IS NOT NULL) OR (@RequestRevision>0 AND (@FenceHash IS NULL OR NOT EXISTS(
    SELECT 1 FROM [dbo].[ProductionHoldRequests] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId AND [Revision]=@RequestRevision
    AND LOWER(CONVERT(varchar(64),[Hash],2)) COLLATE Latin1_General_100_BIN2=@FenceHash)))
    OR EXISTS(SELECT 1 FROM [dbo].[ProductionHoldRequests] AS p WITH(HOLDLOCK) WHERE p.[EnvelopeId]=@EnvelopeId AND p.[Operation]=0
    AND NOT EXISTS(SELECT 1 FROM [dbo].[ProductionHoldRequests] AS q WITH(HOLDLOCK) WHERE q.[EnvelopeId]=@EnvelopeId AND q.[HoldId]=p.[HoldId] AND q.[Operation]=1 AND q.[Revision]>p.[Revision]))
     THROW 50001,'A hold request or exact release prefix changed.',1;
    IF (SELECT COUNT_BIG(*) FROM [dbo].[ProductionHoldControls] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId)<>@ControlSequence
    OR (@ControlSequence=0 AND @ControlHash IS NOT NULL) OR (@ControlSequence>0 AND (@ControlHash IS NULL OR NOT EXISTS(
    SELECT 1 FROM [dbo].[ProductionHoldControls] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId AND [Sequence]=@ControlSequence
    AND LOWER(CONVERT(varchar(64),[Hash],2)) COLLATE Latin1_General_100_BIN2=@ControlHash)))
     THROW 50001,'The exact authenticated control prefix changed.',1;
    DECLARE @Actual TABLE([Name] nvarchar(128) PRIMARY KEY,[Count] bigint NOT NULL);
   INSERT @Actual SELECT N'AuthTokens',COUNT_BIG(*) FROM [dbo].[AuthTokens] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId;
   INSERT @Actual SELECT N'AuditEvents',COUNT_BIG(*) FROM [dbo].[AuditEvents] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId;
   INSERT @Actual SELECT N'CompletionCandidates',COUNT_BIG(*) FROM [dbo].[CompletionCandidates] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId;
   INSERT @Actual SELECT N'CompletionPublicationIntents',COUNT_BIG(*) FROM [dbo].[CompletionPublicationIntents] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId;
   INSERT @Actual SELECT N'CompletionPublicationResults',COUNT_BIG(*) FROM [dbo].[CompletionPublicationResults] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId;
   INSERT @Actual SELECT N'CompletionSealOutputs',COUNT_BIG(*) FROM [dbo].[CompletionSealOutputs] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId;
   INSERT @Actual SELECT N'DocumentRetentionSnapshots',COUNT_BIG(*) FROM [dbo].[DocumentRetentionSnapshots] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId;
   INSERT @Actual SELECT N'EmailOutbox',COUNT_BIG(*) FROM [dbo].[EmailOutbox] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId;
   INSERT @Actual SELECT N'Envelopes',COUNT_BIG(*) FROM [dbo].[Envelopes] WITH(HOLDLOCK) WHERE [Id]=@EnvelopeId;
   INSERT @Actual SELECT N'Fields',COUNT_BIG(*) FROM [dbo].[Fields] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId;
   INSERT @Actual SELECT N'LookupContactRetentionSnapshots',COUNT_BIG(*) FROM [dbo].[LookupContactRetentionSnapshots] WITH(HOLDLOCK) WHERE [RequestId] IN (SELECT [Id] FROM [dbo].[EmailOutbox] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId);
   INSERT @Actual SELECT N'ProductionHoldControls',COUNT_BIG(*) FROM [dbo].[ProductionHoldControls] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId;
   INSERT @Actual SELECT N'ProductionHoldRequests',COUNT_BIG(*) FROM [dbo].[ProductionHoldRequests] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId;
   INSERT @Actual SELECT N'ProductionRetentionPolicies',COUNT_BIG(*) FROM [dbo].[ProductionRetentionPolicies] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId;
   INSERT @Actual SELECT N'ProductionRetentionTerminals',COUNT_BIG(*) FROM [dbo].[ProductionRetentionTerminals] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId;
   INSERT @Actual SELECT N'Recipients',COUNT_BIG(*) FROM [dbo].[Recipients] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId;
   INSERT @Actual SELECT N'SignaturePreviews',COUNT_BIG(*) FROM [dbo].[SignaturePreviews] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId;
   INSERT @Actual SELECT N'SignerContactRevisions',COUNT_BIG(*) FROM [dbo].[SignerContactRevisions] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId;
   INSERT @Actual SELECT N'SignerContactSessions',COUNT_BIG(*) FROM [dbo].[SignerContactSessions] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId;
   INSERT @Actual SELECT N'SignerFinishAcceptances',COUNT_BIG(*) FROM [dbo].[SignerFinishAcceptances] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId;
   INSERT @Actual SELECT N'SignerReviewCandidates',COUNT_BIG(*) FROM [dbo].[SignerReviewCandidates] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId;
   INSERT @Actual SELECT N'Signers',COUNT_BIG(*) FROM [dbo].[Signers] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId;
   INSERT @Actual SELECT N'WorkItems',COUNT_BIG(*) FROM [dbo].[WorkItems] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId;
    IF @CountsJson IS NULL OR DATALENGTH(@CountsJson)>8192 OR ISJSON(@CountsJson)<>1
     THROW 50001,'Closed owned SQL counts are required.',1;
    IF (SELECT COUNT_BIG(*) FROM OPENJSON(@CountsJson))<>23 OR EXISTS(SELECT [key] FROM OPENJSON(@CountsJson) GROUP BY [key] HAVING COUNT_BIG(*)<>1)
    OR EXISTS(SELECT 1 FROM OPENJSON(@CountsJson) WHERE [type]<>2 OR TRY_CONVERT(bigint,[value]) IS NULL OR TRY_CONVERT(bigint,[value])<0)
    OR EXISTS(SELECT 1 FROM OPENJSON(@CountsJson) AS e FULL JOIN @Actual AS a ON e.[key] COLLATE Latin1_General_100_BIN2=a.[Name]
    WHERE a.[Name] IS NULL OR e.[key] IS NULL OR TRY_CONVERT(bigint,e.[value])<>a.[Count])
    OR (SELECT COALESCE(SUM([Count]),0) FROM @Actual WHERE [Name]<>N'ProductionHoldControls')>4096
    OR (SELECT [Count] FROM @Actual WHERE [Name]=N'ProductionHoldControls')>16384
     THROW 50001,'Exact bounded owned SQL counts changed.',1;
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
   DELETE FROM [dbo].[LookupContactRetentionSnapshots] WHERE [RequestId] IN (SELECT [Id] FROM [dbo].[EmailOutbox] WITH(HOLDLOCK) WHERE [EnvelopeId]=@EnvelopeId);
   DELETE FROM [dbo].[WorkItems] WHERE [EnvelopeId]=@EnvelopeId AND [Id]<>@WorkId;
   DELETE FROM [dbo].[EmailOutbox] WHERE [EnvelopeId]=@EnvelopeId;
   DELETE FROM [dbo].[AuditEvents] WHERE [EnvelopeId]=@EnvelopeId;
   DELETE FROM [dbo].[ProductionHoldControls] WHERE [EnvelopeId]=@EnvelopeId;
   DELETE FROM [dbo].[ProductionHoldRequests] WHERE [EnvelopeId]=@EnvelopeId;
   DELETE FROM [dbo].[ProductionRetentionTerminals] WHERE [EnvelopeId]=@EnvelopeId;
   DELETE FROM [dbo].[ProductionRetentionPolicies] WHERE [EnvelopeId]=@EnvelopeId;
    UPDATE [dbo].[WorkItems] SET [EnvelopeId]=NULL WHERE [Id]=@WorkId;
    DELETE FROM [dbo].[Envelopes] WHERE [Id]=@EnvelopeId;
    IF @Until<=TODATETIMEOFFSET(SYSUTCDATETIME(),'+00:00') THROW 50001,'The original production deletion lease expired.',1;
    SELECT CAST(1 AS bit);
   END
   """);
 }
 protected override void Down(MigrationBuilder migrationBuilder)
 {
  migrationBuilder.Sql("IF EXISTS(SELECT 1 FROM [dbo].[WorkItems] WHERE [Kind]=N'ProductionPurge') THROW 50001,'Preserve existing production cleanup work before rollback.',1;");
  migrationBuilder.Sql("DROP PROCEDURE [dbo].[RemoveExpiredProductionPrivateRecords];");
  migrationBuilder.DropCheckConstraint(name:"CK_WorkItem_Kind",table:"WorkItems");
  migrationBuilder.AddCheckConstraint(name:"CK_WorkItem_Kind",table:"WorkItems",sql:"[Kind] IS NULL OR [Kind] IN ('Conversion','Ai','Rendering','Sealing','Email','Purge','Expiry','Reminder')");
 }
}
