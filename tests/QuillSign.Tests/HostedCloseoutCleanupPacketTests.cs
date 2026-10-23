using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using QuillSign.Data;
using QuillSign.Email.Pilot;

namespace QuillSign.Tests;

public sealed class HostedCloseoutCleanupPacketTests
{
    [Theory]
    [InlineData("valid")][InlineData("duplicate")][InlineData("unknown")][InlineData("gate")][InlineData("sid")]
    [InlineData("identity")][InlineData("allowance")][InlineData("parent")][InlineData("oversize")]
    public void Closed_cleanup_packet_cannot_supply_SQL_or_new_authority(string fault)
    {
        var at=DateTimeOffset.UtcNow.AddHours(-1);var hash=new string('a',64);
        var receipt=new EmailPilotCloseoutCommittedReceipt(EmailPilotCloseout.CommittedReceiptVersion,at.AddMinutes(2),Guid.NewGuid(),hash,hash,true,at,at.AddMinutes(30),at.AddDays(7),
            Enumerable.Range(0,5).Select(_=>Guid.NewGuid()).ToArray(),at.AddDays(7),Enumerable.Range(0,6).Select(_=>Guid.NewGuid()).ToArray(),12,4,4,27918,1,0,0,37,0,1,hash,hash,hash,hash,hash,true,HostedCloseoutStateVerificationCommand.ApplicationHash());
        if(fault=="allowance")receipt=receipt with{NewApplication=11,OperationCount=11};if(fault=="parent")receipt=receipt with{OriginalParentIds=[]};
        var packet=new HostedCloseoutCleanupProofConfiguration("closeout-cleanup-proof-v1","synthetic",Convert.ToBase64String(Guid.NewGuid().ToByteArray()),receipt);
        if(fault=="sid")packet=packet with{WorkerSqlSid="AA=="};var raw=JsonSerializer.Serialize(packet);
        if(fault=="duplicate")raw="{\"Version\":\"duplicate\","+raw[1..];if(fault=="unknown")raw="{\"Sql\":\"do-not-execute\","+raw[1..];if(fault=="oversize")raw=new string('x',24577);
        var settings=new Dictionary<string,string?>{{"EmailPilot:Closeout:EmitCleanupReceipt","true"},{"Email:Enabled",fault=="gate"?"true":"false"},{"EmailPilot:Enabled","false"},
            {"EmailPilot:Closeout:Enabled","false"},{"Work:Enabled","true"},{"EmailPilot:Closeout:AuthorizationId",fault=="identity"?Guid.NewGuid().ToString("N"):receipt.AuthorizationId.ToString("N")},
            {"EmailPilot:Closeout:CleanupProofBase64",Convert.ToBase64String(Encoding.UTF8.GetBytes(raw))}};
        var config=new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        if(fault!="valid")Assert.ThrowsAny<Exception>(()=>HostedCloseoutCleanupReceipt.Capture(config,out _));
        else {var result=HostedCloseoutCleanupReceipt.Capture(config,out var sha);Assert.Equal(receipt.AuthorizationId,result.FinalReceipt.AuthorizationId);Assert.Equal(64,sha.Length);}
    }
}
