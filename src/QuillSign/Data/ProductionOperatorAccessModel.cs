using Microsoft.EntityFrameworkCore;
namespace QuillSign.Data;
internal static class ProductionOperatorAccessModel
{
    internal static void Configure(ModelBuilder model)
    {
        model.Entity<ProductionOperatorAccessReceipt>().ToTable("ProductionOperatorAccessReceipts",t=>{t.UseSqlOutputClause(false);
            t.HasCheckConstraint("CK_OperatorAccess_Receipt","[Id]<>'00000000-0000-0000-0000-000000000000' AND DATEPART(TZOFFSET,[At])=0 AND DATALENGTH([PayloadSha256])=32 AND DATALENGTH([ProtectedReceipt]) BETWEEN 2 AND 16384");});
        model.Entity<ProductionOperatorAccessReceipt>().HasKey(x=>x.Id);
        model.Entity<ProductionOperatorAccessReceipt>().Property(x=>x.ProtectedReceipt).HasColumnType("nvarchar(max)").HasMaxLength(8192);
    }
}
