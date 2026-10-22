using QuillSign.Storage;
namespace QuillSign.Tests;

public sealed class ProductionPurgeSqlContractTests
{
    [Fact]
    public void Closed_table_registry_matches_the_ordinal_owned_count_map()
    {
        var counts=new SortedDictionary<string,long>(StringComparer.Ordinal);
        foreach(var table in ProductionPurgeSql.Tables)Assert.True(counts.TryAdd(table,0));
        Assert.Equal(23,counts.Count);
        Assert.Equal(counts.Keys,ProductionPurgeSql.Tables);
    }
}