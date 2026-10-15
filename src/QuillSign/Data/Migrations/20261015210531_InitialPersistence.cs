using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuillSign.Data.Migrations
{
    /// <inheritdoc />
    public partial class InitialPersistence : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Envelopes",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PublicId = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    Status = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    SenderEmail = table.Column<string>(type: "nvarchar(320)", maxLength: 320, nullable: false),
                    SenderName = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    SenderVerifiedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    Title = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    Message = table.Column<string>(type: "nvarchar(4000)", maxLength: 4000, nullable: true),
                    ReminderDaysJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    ErsdVersion = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    ErsdSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: true),
                    ExclusionsAckAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    OriginalBlob = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    OriginalSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: true),
                    OriginalMime = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    PdfBlob = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    PdfSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: true),
                    PageCount = table.Column<int>(type: "int", nullable: true),
                    PageSizesJson = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    PreviewConfirmedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    SentPdfBlob = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    SentPdfSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: true),
                    FinalBlob = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    FinalSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: true),
                    CertificateBlob = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    CertificateSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: true),
                    SealCertThumbprint = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    SealProvider = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    TsaUrl = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    AiRolesJson = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    AiModel = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    SentAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    CompletedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    PurgeAfter = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    IsDemo = table.Column<bool>(type: "bit", nullable: false),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Envelopes", x => x.Id);
                    table.CheckConstraint("CK_Envelope_AiRolesJson", "[AiRolesJson] IS NULL OR ISJSON([AiRolesJson]) = 1");
                    table.CheckConstraint("CK_Envelope_CertificateSha256", "[CertificateSha256] IS NULL OR DATALENGTH([CertificateSha256]) = 32");
                    table.CheckConstraint("CK_Envelope_ErsdSha256", "[ErsdSha256] IS NULL OR DATALENGTH([ErsdSha256]) = 32");
                    table.CheckConstraint("CK_Envelope_FinalSha256", "[FinalSha256] IS NULL OR DATALENGTH([FinalSha256]) = 32");
                    table.CheckConstraint("CK_Envelope_OriginalSha256", "[OriginalSha256] IS NULL OR DATALENGTH([OriginalSha256]) = 32");
                    table.CheckConstraint("CK_Envelope_PageCount", "[PageCount] IS NULL OR [PageCount] > 0");
                    table.CheckConstraint("CK_Envelope_PageSizesJson", "[PageSizesJson] IS NULL OR ISJSON([PageSizesJson]) = 1");
                    table.CheckConstraint("CK_Envelope_PdfSha256", "[PdfSha256] IS NULL OR DATALENGTH([PdfSha256]) = 32");
                    table.CheckConstraint("CK_Envelope_ReminderDaysJson", "[ReminderDaysJson] IS NULL OR ISJSON([ReminderDaysJson]) = 1");
                    table.CheckConstraint("CK_Envelope_SentPdfSha256", "[SentPdfSha256] IS NULL OR DATALENGTH([SentPdfSha256]) = 32");
                    table.CheckConstraint("CK_Envelope_Status", "[Status] IS NULL OR [Status] IN ('Draft','Sent','Completed','Declined','Voided','Expired')");
                });

            migrationBuilder.CreateTable(
                name: "Suppressions",
                columns: table => new
                {
                    Email = table.Column<string>(type: "nvarchar(320)", maxLength: 320, nullable: false),
                    Reason = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Suppressions", x => x.Email);
                    table.CheckConstraint("CK_Suppression_Reason", "[Reason] IS NULL OR [Reason] IN ('Bounce','Complaint','Unsubscribe','BlockedSender')");
                });

            migrationBuilder.CreateTable(
                name: "AuditEvents",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    EnvelopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Sequence = table.Column<long>(type: "bigint", nullable: false),
                    At = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    ActorType = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    ActorId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ActorEmail = table.Column<string>(type: "nvarchar(320)", maxLength: 320, nullable: true),
                    Event = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    Ip = table.Column<string>(type: "nvarchar(45)", maxLength: 45, nullable: true),
                    UserAgent = table.Column<string>(type: "nvarchar(2048)", maxLength: 2048, nullable: true),
                    DataJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    PrevHash = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: true),
                    Hash = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditEvents", x => x.Id);
                    table.CheckConstraint("CK_Audit_Chain", "([Sequence] = 1 AND [PrevHash] IS NULL) OR ([Sequence] > 1 AND [PrevHash] IS NOT NULL)");
                    table.CheckConstraint("CK_AuditEvent_ActorType", "[ActorType] IS NULL OR [ActorType] IN ('Sender','Signer','Recipient','System')");
                    table.CheckConstraint("CK_AuditEvent_DataJson", "[DataJson] IS NULL OR ISJSON([DataJson]) = 1");
                    table.CheckConstraint("CK_AuditEvent_Hash", "[Hash] IS NULL OR DATALENGTH([Hash]) = 32");
                    table.CheckConstraint("CK_AuditEvent_PrevHash", "[PrevHash] IS NULL OR DATALENGTH([PrevHash]) = 32");
                    table.ForeignKey(
                        name: "FK_AuditEvents_Envelopes_EnvelopeId",
                        column: x => x.EnvelopeId,
                        principalTable: "Envelopes",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "AuthTokens",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TokenSha256 = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    Purpose = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    EnvelopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    PartyType = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    PartyId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    Email = table.Column<string>(type: "nvarchar(320)", maxLength: 320, nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    UsedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    Ip = table.Column<string>(type: "nvarchar(45)", maxLength: 45, nullable: true),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuthTokens", x => x.Id);
                    table.CheckConstraint("CK_AuthToken_PartyType", "[PartyType] IS NULL OR [PartyType] IN ('Sender','Signer','Recipient','System')");
                    table.CheckConstraint("CK_AuthToken_Purpose", "[Purpose] IS NULL OR [Purpose] IN ('SenderVerify','SenderStatus','SignerAccess','Lookup')");
                    table.CheckConstraint("CK_AuthToken_TokenSha256", "[TokenSha256] IS NULL OR DATALENGTH([TokenSha256]) = 32");
                    table.CheckConstraint("CK_Token_Scope", "[Purpose] = 'Lookup' OR [EnvelopeId] IS NOT NULL");
                    table.ForeignKey(
                        name: "FK_AuthTokens_Envelopes_EnvelopeId",
                        column: x => x.EnvelopeId,
                        principalTable: "Envelopes",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "EmailOutbox",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EnvelopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    To = table.Column<string>(type: "nvarchar(320)", maxLength: 320, nullable: false),
                    Template = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    PayloadJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    AttachmentsJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Status = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    Provider = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    ProviderMessageId = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    Attempts = table.Column<int>(type: "int", nullable: false),
                    LastError = table.Column<string>(type: "nvarchar(4000)", maxLength: 4000, nullable: true),
                    AvailableAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    LeaseOwner = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    LeaseExpiresAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EmailOutbox", x => x.Id);
                    table.CheckConstraint("CK_Email_Lease", "[Attempts] >= 0 AND (([LeaseOwner] IS NULL AND [LeaseExpiresAt] IS NULL) OR ([LeaseOwner] IS NOT NULL AND [LeaseExpiresAt] IS NOT NULL))");
                    table.CheckConstraint("CK_EmailOutbox_AttachmentsJson", "[AttachmentsJson] IS NULL OR ISJSON([AttachmentsJson]) = 1");
                    table.CheckConstraint("CK_EmailOutbox_PayloadJson", "[PayloadJson] IS NULL OR ISJSON([PayloadJson]) = 1");
                    table.CheckConstraint("CK_EmailOutbox_Status", "[Status] IS NULL OR [Status] IN ('Queued','Sent','Failed','Bounced','Complained')");
                    table.ForeignKey(
                        name: "FK_EmailOutbox_Envelopes_EnvelopeId",
                        column: x => x.EnvelopeId,
                        principalTable: "Envelopes",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "Recipients",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EnvelopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    Email = table.Column<string>(type: "nvarchar(320)", maxLength: 320, nullable: false),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Recipients", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Recipients_Envelopes_EnvelopeId",
                        column: x => x.EnvelopeId,
                        principalTable: "Envelopes",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "Signers",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EnvelopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Order = table.Column<int>(type: "int", nullable: false),
                    FullName = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    Email = table.Column<string>(type: "nvarchar(320)", maxLength: 320, nullable: false),
                    Role = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    Color = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    Status = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    ConsentAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    ConsentIp = table.Column<string>(type: "nvarchar(45)", maxLength: 45, nullable: true),
                    ConsentUa = table.Column<string>(type: "nvarchar(2048)", maxLength: 2048, nullable: true),
                    SignedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    SignedIp = table.Column<string>(type: "nvarchar(45)", maxLength: 45, nullable: true),
                    SignedUa = table.Column<string>(type: "nvarchar(2048)", maxLength: 2048, nullable: true),
                    DeclineReason = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    SignatureImageBlob = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    InitialsImageBlob = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    SignatureMethod = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: true),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Signers", x => x.Id);
                    table.UniqueConstraint("AK_Signers_EnvelopeId_Id", x => new { x.EnvelopeId, x.Id });
                    table.CheckConstraint("CK_Signer_Order", "[Order] > 0");
                    table.CheckConstraint("CK_Signer_SignatureMethod", "[SignatureMethod] IS NULL OR [SignatureMethod] IN ('Typed','Drawn','Uploaded')");
                    table.CheckConstraint("CK_Signer_Status", "[Status] IS NULL OR [Status] IN ('Pending','Notified','Viewed','Signed','Declined')");
                    table.ForeignKey(
                        name: "FK_Signers_Envelopes_EnvelopeId",
                        column: x => x.EnvelopeId,
                        principalTable: "Envelopes",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "WorkItems",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EnvelopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    Kind = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    Status = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    PayloadJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Attempts = table.Column<int>(type: "int", nullable: false),
                    LastError = table.Column<string>(type: "nvarchar(4000)", maxLength: 4000, nullable: true),
                    AvailableAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    LeaseOwner = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    LeaseExpiresAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WorkItems", x => x.Id);
                    table.CheckConstraint("CK_Work_Lease", "[Attempts] >= 0 AND (([LeaseOwner] IS NULL AND [LeaseExpiresAt] IS NULL) OR ([LeaseOwner] IS NOT NULL AND [LeaseExpiresAt] IS NOT NULL))");
                    table.CheckConstraint("CK_WorkItem_Kind", "[Kind] IS NULL OR [Kind] IN ('Conversion','Ai','Rendering','Sealing','Email','Purge')");
                    table.CheckConstraint("CK_WorkItem_PayloadJson", "[PayloadJson] IS NULL OR ISJSON([PayloadJson]) = 1");
                    table.CheckConstraint("CK_WorkItem_Status", "[Status] IS NULL OR [Status] IN ('Queued','Leased','Completed','Failed')");
                    table.ForeignKey(
                        name: "FK_WorkItems_Envelopes_EnvelopeId",
                        column: x => x.EnvelopeId,
                        principalTable: "Envelopes",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "Fields",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EnvelopeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SignerId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    Type = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    Page = table.Column<int>(type: "int", nullable: false),
                    X = table.Column<decimal>(type: "decimal(10,8)", precision: 10, scale: 8, nullable: false),
                    Y = table.Column<decimal>(type: "decimal(10,8)", precision: 10, scale: 8, nullable: false),
                    Width = table.Column<decimal>(type: "decimal(10,8)", precision: 10, scale: 8, nullable: false),
                    Height = table.Column<decimal>(type: "decimal(10,8)", precision: 10, scale: 8, nullable: false),
                    Required = table.Column<bool>(type: "bit", nullable: false),
                    Label = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    Placeholder = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    DateFormat = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    Source = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    AiConfidence = table.Column<decimal>(type: "decimal(10,8)", precision: 10, scale: 8, nullable: true),
                    Value = table.Column<string>(type: "nvarchar(4000)", maxLength: 4000, nullable: true),
                    FilledAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    FilledBy = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: true),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Fields", x => x.Id);
                    table.CheckConstraint("CK_DocumentField_FilledBy", "[FilledBy] IS NULL OR [FilledBy] IN ('Sender','Signer','Recipient','System')");
                    table.CheckConstraint("CK_DocumentField_Source", "[Source] IS NULL OR [Source] IN ('Manual','Ai','AcroForm')");
                    table.CheckConstraint("CK_DocumentField_Type", "[Type] IS NULL OR [Type] IN ('Signature','Initials','FullName','DateSigned','Text','Checkbox','Date')");
                    table.CheckConstraint("CK_Field_Assignment", "[SignerId] IS NOT NULL OR [Type] IN ('Text','Checkbox','Date')");
                    table.CheckConstraint("CK_Field_Bounds", "[Page] >= 1 AND [X] >= 0 AND [Y] >= 0 AND [Width] > 0 AND [Height] > 0 AND [X] + [Width] <= 1 AND [Y] + [Height] <= 1");
                    table.CheckConstraint("CK_Field_Confidence", "[AiConfidence] IS NULL OR ([AiConfidence] >= 0 AND [AiConfidence] <= 1)");
                    table.ForeignKey(
                        name: "FK_Fields_Envelopes_EnvelopeId",
                        column: x => x.EnvelopeId,
                        principalTable: "Envelopes",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_Fields_Signers_EnvelopeId_SignerId",
                        columns: x => new { x.EnvelopeId, x.SignerId },
                        principalTable: "Signers",
                        principalColumns: new[] { "EnvelopeId", "Id" });
                });

            migrationBuilder.CreateIndex(
                name: "IX_AuditEvents_EnvelopeId_Sequence",
                table: "AuditEvents",
                columns: new[] { "EnvelopeId", "Sequence" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AuthTokens_EnvelopeId",
                table: "AuthTokens",
                column: "EnvelopeId");

            migrationBuilder.CreateIndex(
                name: "IX_AuthTokens_ExpiresAt",
                table: "AuthTokens",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_AuthTokens_TokenSha256",
                table: "AuthTokens",
                column: "TokenSha256",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_EmailOutbox_EnvelopeId",
                table: "EmailOutbox",
                column: "EnvelopeId");

            migrationBuilder.CreateIndex(
                name: "IX_EmailOutbox_Status_AvailableAt",
                table: "EmailOutbox",
                columns: new[] { "Status", "AvailableAt" });

            migrationBuilder.CreateIndex(
                name: "IX_Envelopes_PublicId",
                table: "Envelopes",
                column: "PublicId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Envelopes_PurgeAfter",
                table: "Envelopes",
                column: "PurgeAfter");

            migrationBuilder.CreateIndex(
                name: "IX_Fields_EnvelopeId_SignerId",
                table: "Fields",
                columns: new[] { "EnvelopeId", "SignerId" });

            migrationBuilder.CreateIndex(
                name: "IX_Recipients_EnvelopeId_Email",
                table: "Recipients",
                columns: new[] { "EnvelopeId", "Email" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Signers_EnvelopeId_Email",
                table: "Signers",
                columns: new[] { "EnvelopeId", "Email" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Signers_EnvelopeId_Order",
                table: "Signers",
                columns: new[] { "EnvelopeId", "Order" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_WorkItems_EnvelopeId",
                table: "WorkItems",
                column: "EnvelopeId");

            migrationBuilder.CreateIndex(
                name: "IX_WorkItems_Status_AvailableAt",
                table: "WorkItems",
                columns: new[] { "Status", "AvailableAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AuditEvents");

            migrationBuilder.DropTable(
                name: "AuthTokens");

            migrationBuilder.DropTable(
                name: "EmailOutbox");

            migrationBuilder.DropTable(
                name: "Fields");

            migrationBuilder.DropTable(
                name: "Recipients");

            migrationBuilder.DropTable(
                name: "Suppressions");

            migrationBuilder.DropTable(
                name: "WorkItems");

            migrationBuilder.DropTable(
                name: "Signers");

            migrationBuilder.DropTable(
                name: "Envelopes");
        }
    }
}
