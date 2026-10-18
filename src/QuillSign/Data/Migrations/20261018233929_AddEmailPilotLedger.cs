using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuillSign.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddEmailPilotLedger : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "EmailPilotRuns",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    ManifestSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    CapabilitySha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EmailPilotRuns", x => x.Id);
                    table.CheckConstraint("CK_EmailPilotRun_Interval", "[Id]<>'00000000-0000-0000-0000-000000000000' AND DATEPART(TZOFFSET,[CreatedAt])=0 AND DATEPART(TZOFFSET,[ExpiresAt])=0 AND [ExpiresAt]=DATEADD(minute,60,[CreatedAt])");
                    table.CheckConstraint("CK_EmailPilotRunRecord_CapabilitySha256", "[CapabilitySha256] IS NULL OR DATALENGTH([CapabilitySha256]) = 32");
                    table.CheckConstraint("CK_EmailPilotRunRecord_ManifestSha256", "[ManifestSha256] IS NULL OR DATALENGTH([ManifestSha256]) = 32");
                });

            migrationBuilder.CreateTable(
                name: "EmailPilotEnrollments",
                columns: table => new
                {
                    SubjectEnvelopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RunId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Scenario = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    EnrolledAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    ProtectedBinding = table.Column<string>(type: "nvarchar(2048)", maxLength: 2048, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EmailPilotEnrollments", x => x.SubjectEnvelopeId);
                    table.UniqueConstraint("AK_EmailPilotEnrollments_RunId_SubjectEnvelopeId", x => new { x.RunId, x.SubjectEnvelopeId });
                    table.CheckConstraint("CK_EmailPilotEnrollment_Scope", "[SubjectEnvelopeId]<>'00000000-0000-0000-0000-000000000000' AND DATEPART(TZOFFSET,[EnrolledAt])=0");
                    table.CheckConstraint("CK_EmailPilotEnrollmentRecord_Scenario", "[Scenario] IS NULL OR [Scenario] IN ('Completion','Void','Decline')");
                    table.ForeignKey(
                        name: "FK_EmailPilotEnrollments_EmailPilotRuns_RunId",
                        column: x => x.RunId,
                        principalTable: "EmailPilotRuns",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "EmailPilotSecrets",
                columns: table => new
                {
                    RunId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ProtectedManifest = table.Column<string>(type: "nvarchar(max)", maxLength: 16384, nullable: false),
                    DeleteAfter = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EmailPilotSecrets", x => x.RunId);
                    table.CheckConstraint("CK_EmailPilotSecret_Deadline", "DATEPART(TZOFFSET,[DeleteAfter])=0 AND DATALENGTH([ProtectedManifest]) BETWEEN 2 AND 32768");
                    table.ForeignKey(
                        name: "FK_EmailPilotSecrets_EmailPilotRuns_RunId",
                        column: x => x.RunId,
                        principalTable: "EmailPilotRuns",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "EmailPilotReservations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RunId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SubjectEnvelopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    OperationId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Kind = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    Role = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    EncodedBytes = table.Column<int>(type: "int", nullable: false),
                    RequestSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    ReservedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    ProtectedReceipt = table.Column<string>(type: "nvarchar(max)", maxLength: 4096, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EmailPilotReservations", x => x.Id);
                    table.CheckConstraint("CK_EmailPilotReservation_Bytes", "([Kind]='Timestamp' AND [EncodedBytes]=0 AND [Role]='None' AND [SubjectEnvelopeId] IS NOT NULL) OR ([Kind]='Application' AND [EncodedBytes] BETWEEN 1 AND 1048576 AND [Role] IN ('Sender','FirstSigner','SecondSigner','Recipient') AND [SubjectEnvelopeId] IS NOT NULL) OR ([Kind]='Simulator' AND [EncodedBytes] BETWEEN 1 AND 1048576 AND [Role]='Simulator' AND [SubjectEnvelopeId] IS NULL)");
                    table.CheckConstraint("CK_EmailPilotReservation_Receipt", "DATALENGTH([ProtectedReceipt]) BETWEEN 2 AND 8192");
                    table.CheckConstraint("CK_EmailPilotReservation_Scope", "[Id]<>'00000000-0000-0000-0000-000000000000' AND [OperationId]<>'00000000-0000-0000-0000-000000000000' AND DATEPART(TZOFFSET,[ReservedAt])=0");
                    table.CheckConstraint("CK_EmailPilotReservationRecord_Kind", "[Kind] IS NULL OR [Kind] IN ('Application','Simulator','Timestamp')");
                    table.CheckConstraint("CK_EmailPilotReservationRecord_RequestSha256", "[RequestSha256] IS NULL OR DATALENGTH([RequestSha256]) = 32");
                    table.CheckConstraint("CK_EmailPilotReservationRecord_Role", "[Role] IS NULL OR [Role] IN ('None','Sender','FirstSigner','SecondSigner','Recipient','Simulator')");
                    table.ForeignKey(
                        name: "FK_EmailPilotReservations_EmailPilotEnrollments_RunId_SubjectEnvelopeId",
                        columns: x => new { x.RunId, x.SubjectEnvelopeId },
                        principalTable: "EmailPilotEnrollments",
                        principalColumns: new[] { "RunId", "SubjectEnvelopeId" });
                    table.ForeignKey(
                        name: "FK_EmailPilotReservations_EmailPilotRuns_RunId",
                        column: x => x.RunId,
                        principalTable: "EmailPilotRuns",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateIndex(
                name: "IX_EmailPilotEnrollments_RunId_Scenario",
                table: "EmailPilotEnrollments",
                columns: new[] { "RunId", "Scenario" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_EmailPilotReservations_RunId_ReservedAt",
                table: "EmailPilotReservations",
                columns: new[] { "RunId", "ReservedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_EmailPilotReservations_RunId_Kind_OperationId_Role",
                table: "EmailPilotReservations",
                columns: new[] { "RunId", "Kind", "OperationId", "Role" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_EmailPilotReservations_RunId_SubjectEnvelopeId",
                table: "EmailPilotReservations",
                columns: new[] { "RunId", "SubjectEnvelopeId" });

            // No caller-controlled cutoff or document delete authority. Keep the
            // nonpersonal run/counter tombstones so cleanup cannot reset a budget.
            migrationBuilder.Sql("""
                CREATE OR ALTER PROCEDURE [dbo].[RemoveExpiredEmailPilotSecrets] @RunId uniqueidentifier
                WITH EXECUTE AS OWNER
                AS
                BEGIN
                    SET NOCOUNT ON; SET XACT_ABORT ON;
                    IF @RunId IS NULL OR @RunId='00000000-0000-0000-0000-000000000000'
                        THROW 50001,'Supply one exact pilot run.',1;
                    BEGIN TRANSACTION;
                    BEGIN TRY
                        DECLARE @result int;
                        DECLARE @resource nvarchar(255)=N'email-pilot:'+LOWER(REPLACE(CONVERT(nvarchar(36),@RunId),'-',''));
                        EXEC @result=sys.sp_getapplock @Resource=@resource,@LockMode='Exclusive',@LockOwner='Transaction',@LockTimeout=5000;
                        IF @result<0 THROW 50002,'Pilot cleanup is temporarily busy.',1;
                        DELETE s FROM dbo.EmailPilotSecrets s
                        JOIN dbo.EmailPilotRuns r ON r.Id=s.RunId
                        WHERE s.RunId=@RunId
                            AND DATEPART(TZOFFSET,r.CreatedAt)=0 AND DATEPART(TZOFFSET,r.ExpiresAt)=0
                            AND DATEPART(TZOFFSET,s.DeleteAfter)=0
                            AND r.ExpiresAt=DATEADD(minute,60,r.CreatedAt)
                            AND s.DeleteAfter=DATEADD(day,7,r.CreatedAt)
                            AND s.DeleteAfter<=SYSUTCDATETIME();
                        COMMIT TRANSACTION;
                    END TRY
                    BEGIN CATCH
                        IF @@TRANCOUNT>0 ROLLBACK TRANSACTION;
                        THROW;
                    END CATCH
                END
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("DROP PROCEDURE IF EXISTS dbo.RemoveExpiredEmailPilotSecrets");
            migrationBuilder.DropTable(
                name: "EmailPilotReservations");

            migrationBuilder.DropTable(
                name: "EmailPilotSecrets");

            migrationBuilder.DropTable(
                name: "EmailPilotEnrollments");

            migrationBuilder.DropTable(
                name: "EmailPilotRuns");
        }
    }
}
