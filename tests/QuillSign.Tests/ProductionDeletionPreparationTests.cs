using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using QuillSign.Lifecycle;

namespace QuillSign.Tests;

public sealed class ProductionDeletionPreparationTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Only_exact_acknowledged_inert_preparation_job_has_a_factual_old_graph_projection()
    {
        var ready=await new ProductionDeletionConnectedTests(fixture).CreateReady();await using var run=ready.Run;var work=await ready.Coordinator.PrepareAsync(run.Id);
        var state=await run.Journal.ReadAsync(run.Id);
        await using var db=fixture.Open();await using var tx=await db.Database.BeginTransactionAsync();
        var requests=await new ProductionHoldRequests(db,run.Keys,run.Time).ReadLockedAsync(run.Id);
        var snapshot=await new ProductionHoldSqlInventory(db,run.Keys,run.Time).CaptureAcknowledgementLockedAsync(run.Id,requests.Revision,requests.FenceHash);
        using var original=ProductionHoldSqlInventory.OpenAcknowledgementVerified(snapshot,run.Keys);
        using var projected=ProductionDeletionPreparationReferences.ProjectVerified(original.RootElement,state);
        JsonElement Rows(JsonElement root,string table)=>root.GetProperty("Tables").EnumerateArray().Single(t=>t.GetProperty("Table").GetString()==table).GetProperty("Rows");
        Assert.Equal(Rows(original.RootElement,"WorkItems").GetArrayLength()-1,Rows(projected.RootElement,"WorkItems").GetArrayLength());
        Assert.Equal(Rows(original.RootElement,"AuditEvents").GetRawText(),Rows(projected.RootElement,"AuditEvents").GetRawText());
        Assert.DoesNotContain(Rows(projected.RootElement,"WorkItems").EnumerateArray(),r=>r.GetProperty("Id").GetGuid()==work);
        Assert.Throws<InvalidDataException>(()=>ProductionDeletionPreparationReferences.ProjectVerified(original.RootElement,state with{SettledOperations=new Dictionary<Guid,string>()}));
        Assert.Throws<InvalidDataException>(()=>ProductionDeletionPreparationReferences.ProjectVerified(original.RootElement,state with{Outcomes=null}));
        foreach(var fault in new[]{"payload","attempt","lease","deadline","foreign-id","status"}){
            var changed=JsonNode.Parse(original.RootElement.GetRawText())!;var row=changed["Tables"]!.AsArray().Single(t=>t!["Table"]!.GetValue<string>()=="WorkItems")!["Rows"]!.AsArray().Single(r=>r!["Id"]!.GetValue<Guid>()==work)!;
            switch(fault){case "payload":row["PayloadJson"]="{}";break;case "attempt":row["Attempts"]=1;break;case "lease":row["LeaseOwner"]=Guid.NewGuid();break;
                case "deadline":row["AvailableAt"]=run.Time.Now.AddYears(1);break;case "foreign-id":row["Id"]=Guid.NewGuid();break;case "status":row["Status"]="Leased";break;}
            using var altered=JsonDocument.Parse(changed.ToJsonString());Assert.Throws<InvalidDataException>(()=>ProductionDeletionPreparationReferences.ProjectVerified(altered.RootElement,state));
        }
        Assert.Equal(state.HeadHash,(await run.Journal.ReadAsync(run.Id)).HeadHash);Assert.Equal(0,ready.Files.RootDeletes+ready.Files.VersionDeletes);
    }
}
