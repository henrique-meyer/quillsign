using System.Data;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using QuillSign.Data;

namespace QuillSign.Tests;

public sealed class HostedCloseoutStoredStateFingerprintTests
{
    private static readonly int[] Sets = [1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 13, 14, 15, 16, 17, 18, 19];
    public static IEnumerable<object[]> Indices => Sets.Select(x => new object[] { x });

    [Theory]
    [MemberData(nameof(Indices))]
    public void Saved_reader_JSON_and_actual_typed_data_reader_values_have_identical_fingerprints(int index)
    {
        var schema = HostedCloseoutStoredStateFingerprint.Schema(index);
        var original = Row(index);
        using var table = new DataTable();
        foreach (var column in schema.Columns) table.Columns.Add(column.Name, ClrType(column.SqlType));
        table.Rows.Add(original.Select(x => x ?? DBNull.Value).ToArray());
        using var reader = table.CreateDataReader();
        Assert.True(reader.Read());
        var values = new object[reader.FieldCount];
        Assert.Equal(values.Length, reader.GetValues(values));
        Assert.False(reader.Read());
        var actual = HostedCloseoutStoredStateFingerprint.Compute(index, [values]);
        var saved = HostedCloseoutStoredStateFingerprint.ComputeSaved(Saved(index, [original]));
        Equal(actual, saved);
        Assert.All(actual.Rows, x => { Assert.Matches("^[A-F0-9]{64}$", x.Key); Assert.Matches("^[A-F0-9]{64}$", x.Sha256); });
    }

    [Theory]
    [MemberData(nameof(Indices))]
    public void Every_selected_column_changes_full_row_and_set_fingerprints(int index)
    {
        var row = Row(index);
        var before = HostedCloseoutStoredStateFingerprint.Compute(index, [row]);
        var schema = HostedCloseoutStoredStateFingerprint.Schema(index);
        for (var i = 0; i < row.Length; i++)
        {
            var changed = row.ToArray();
            changed[i] = Change(row[i]!);
            var after = HostedCloseoutStoredStateFingerprint.Compute(index, [changed]);
            Assert.NotEqual(before.Sha256, after.Sha256);
            Assert.NotEqual(before.Rows.Single().Sha256, after.Rows.Single().Sha256);
            Assert.Equal(before.SchemaSha256, after.SchemaSha256);
            if (schema.Columns[i].Nullable)
            {
                changed[i] = null;
                var absent = HostedCloseoutStoredStateFingerprint.Compute(index, [changed]);
                Assert.NotEqual(before.Sha256, absent.Sha256);
                Equal(absent, HostedCloseoutStoredStateFingerprint.ComputeSaved(Saved(index, [changed])));
            }
        }
    }

    [Theory]
    [MemberData(nameof(Indices))]
    public void Exact_NULL_policy_empty_sets_order_independence_and_duplicate_key_refusal(int index)
    {
        var schema = HostedCloseoutStoredStateFingerprint.Schema(index);
        var first = Row(index);
        var second = Row(index);
        second[0] = Change(second[0]!);
        Equal(HostedCloseoutStoredStateFingerprint.Compute(index, [first, second]),
            HostedCloseoutStoredStateFingerprint.Compute(index, [second, first]));
        Assert.Throws<InvalidDataException>(() => HostedCloseoutStoredStateFingerprint.Compute(index, [first, first]));
        var empty = HostedCloseoutStoredStateFingerprint.Compute(index, []);
        Equal(empty, HostedCloseoutStoredStateFingerprint.ComputeSaved(Saved(index, [])));
        Assert.Empty(empty.Rows);
        Assert.NotEqual(empty.Sha256, HostedCloseoutStoredStateFingerprint.Compute(index, [first]).Sha256);
        for (var i = 0; i < schema.Columns.Length; i++)
        {
            var row = first.ToArray();
            row[i] = DBNull.Value;
            if (!schema.Columns[i].Nullable)
                Assert.Throws<InvalidDataException>(() => HostedCloseoutStoredStateFingerprint.Compute(index, [row]));
            else
            {
                var nullRow = first.ToArray();
                nullRow[i] = null;
                Equal(HostedCloseoutStoredStateFingerprint.Compute(index, [row]),
                    HostedCloseoutStoredStateFingerprint.Compute(index, [nullRow]));
            }
        }
    }

    [Theory]
    [InlineData("schema-name")]
    [InlineData("schema-type")]
    [InlineData("schema-order")]
    [InlineData("schema-extra")]
    [InlineData("schema-missing")]
    [InlineData("column-property")]
    [InlineData("root-property")]
    [InlineData("root-missing")]
    [InlineData("row-extra")]
    [InlineData("row-missing")]
    [InlineData("row-object")]
    [InlineData("rows-object")]
    [InlineData("unsupported-index")]
    [InlineData("integer-decimal")]
    [InlineData("integer-string")]
    [InlineData("integer-overflow")]
    [InlineData("integer-object")]
    [InlineData("guid-n-format")]
    [InlineData("guid-uppercase")]
    [InlineData("date-precision")]
    [InlineData("date-no-offset")]
    [InlineData("binary-whitespace")]
    [InlineData("binary-truncated")]
    [InlineData("binary-object")]
    public void Unknown_extra_truncated_or_wrong_typed_saved_shapes_refuse(string fault)
    {
        const int index = 10;
        var node = JsonNode.Parse(Saved(index, [Row(index)]).GetRawText())!.AsObject();
        var columns = node["Columns"]!.AsArray();
        var row = node["Rows"]![0]!.AsArray();
        switch (fault)
        {
            case "schema-name": columns[0]!["Name"] = "Other"; break;
            case "schema-type": columns[0]!["SqlType"] = "decimal"; break;
            case "schema-order": (columns[0], columns[1]) = (columns[1]!.DeepClone(), columns[0]!.DeepClone()); break;
            case "schema-extra": columns.Add(columns[0]!.DeepClone()); break;
            case "schema-missing": columns.RemoveAt(0); break;
            case "column-property": columns[0]!["Unknown"] = false; break;
            case "root-property": node["Complete"] = true; break;
            case "root-missing": node.Remove("Index"); break;
            case "row-extra": row.Add(1); break;
            case "row-missing": row.RemoveAt(0); break;
            case "row-object": node["Rows"]![0] = new JsonObject(); break;
            case "rows-object": node["Rows"] = new JsonObject(); break;
            case "unsupported-index": node["Index"] = 12; break;
            case "integer-decimal": row[9] = JsonNode.Parse("1.0"); break;
            case "integer-string": row[9] = "1"; break;
            case "integer-overflow": row[9] = (long)int.MaxValue + 1; break;
            case "integer-object": row[9] = new JsonObject(); break;
            case "guid-n-format": row[0] = ((Guid)Row(index)[0]!).ToString("N"); break;
            case "guid-uppercase": row[0] = ((Guid)Row(index)[0]!).ToString("D").ToUpperInvariant(); break;
            case "date-precision": row[11] = "2030-01-02T03:04:05+00:00"; break;
            case "date-no-offset": row[11] = "2030-01-02T03:04:05.1234567"; break;
            case "binary-whitespace": row[14] = " " + row[14]!.GetValue<string>(); break;
            case "binary-truncated": row[14] = Convert.ToBase64String(new byte[7]); break;
            case "binary-object": row[14] = new JsonObject(); break;
            default: throw new InvalidOperationException();
        }
        var error = Assert.Throws<InvalidDataException>(() =>
            HostedCloseoutStoredStateFingerprint.ComputeSaved(JsonSerializer.SerializeToElement(node)));
        Assert.Equal("Stored-state fingerprint refused.", error.Message);
        Assert.Null(error.InnerException);
    }

    [Fact]
    public void Duplicate_JSON_properties_are_not_silently_overwritten()
    {
        var raw = Saved(3, [Row(3)]).GetRawText();
        using var duplicateRoot = JsonDocument.Parse(raw.Replace("\"Index\":3", "\"Index\":3,\"Index\":3", StringComparison.Ordinal));
        Assert.Throws<InvalidDataException>(() => HostedCloseoutStoredStateFingerprint.ComputeSaved(duplicateRoot.RootElement));
        using var duplicateColumn = JsonDocument.Parse(raw.Replace("\"Name\":\"RunId\"", "\"Name\":\"RunId\",\"Name\":\"RunId\"", StringComparison.Ordinal));
        Assert.Throws<InvalidDataException>(() => HostedCloseoutStoredStateFingerprint.ComputeSaved(duplicateColumn.RootElement));
    }

    [Fact]
    public void Unicode_opaque_JSON_ciphertext_NULL_and_empty_are_not_normalized()
    {
        var row = Row(10);
        var hashes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var text in new[] { "", " ", "é", "e\u0301", "💠\0終", "{\"a\":1}", "{ \"a\":1}", "opaque+/_=-" })
        {
            row[7] = text;
            var result = HostedCloseoutStoredStateFingerprint.Compute(10, [row]);
            Assert.True(hashes.Add(result.Sha256));
            Equal(result, HostedCloseoutStoredStateFingerprint.ComputeSaved(Saved(10, [row])));
            Assert.DoesNotContain(text.Length == 0 ? "not-a-digest" : text, result.Rows.Single().Key, StringComparison.Ordinal);
        }
        row[7] = null;
        Assert.True(hashes.Add(HostedCloseoutStoredStateFingerprint.Compute(10, [row]).Sha256));
        row[7] = "\uD800";
        Assert.Throws<InvalidDataException>(() => HostedCloseoutStoredStateFingerprint.Compute(10, [row]));
    }

    [Fact]
    public void Original_datetimeoffset_ticks_and_offset_and_binary_RV_are_exact()
    {
        var row = Row(10);
        var before = HostedCloseoutStoredStateFingerprint.Compute(10, [row]);
        var date = (DateTimeOffset)row[11]!;
        row[11] = date.AddTicks(1);
        Assert.NotEqual(before.Sha256, HostedCloseoutStoredStateFingerprint.Compute(10, [row]).Sha256);
        row[11] = date.ToOffset(TimeSpan.FromMinutes(330));
        Assert.Equal(date.UtcTicks, ((DateTimeOffset)row[11]!).UtcTicks);
        Assert.NotEqual(before.Sha256, HostedCloseoutStoredStateFingerprint.Compute(10, [row]).Sha256);
        Equal(HostedCloseoutStoredStateFingerprint.Compute(10, [row]),
            HostedCloseoutStoredStateFingerprint.ComputeSaved(Saved(10, [row])));
        row[11] = date;
        var version = (byte[])row[14]!;
        version[^1] ^= 1;
        Assert.NotEqual(before.Sha256, HostedCloseoutStoredStateFingerprint.Compute(10, [row]).Sha256);
        version[^1] ^= 1;
        Equal(before, HostedCloseoutStoredStateFingerprint.Compute(10, [row]));
        row[14] = new byte[9];
        Assert.Throws<InvalidDataException>(() => HostedCloseoutStoredStateFingerprint.Compute(10, [row]));
    }

    [Fact]
    public void Integral_ranges_are_preserved_and_numeric_coercion_is_forbidden()
    {
        var row = Row(10);
        row[9] = int.MinValue;
        var minimum = HostedCloseoutStoredStateFingerprint.Compute(10, [row]);
        Equal(minimum, HostedCloseoutStoredStateFingerprint.ComputeSaved(Saved(10, [row])));
        row[9] = int.MaxValue;
        var maximum = HostedCloseoutStoredStateFingerprint.Compute(10, [row]);
        Equal(maximum, HostedCloseoutStoredStateFingerprint.ComputeSaved(Saved(10, [row])));
        Assert.NotEqual(minimum.Sha256, maximum.Sha256);
        foreach (var invalid in new object[] { 1L, 1m, 1d, "1", (short)1, JsonSerializer.SerializeToElement(1) })
        {
            row[9] = invalid;
            Assert.Throws<InvalidDataException>(() => HostedCloseoutStoredStateFingerprint.Compute(10, [row]));
        }
        var audit = Row(17);
        audit[0] = long.MinValue;
        var low = HostedCloseoutStoredStateFingerprint.Compute(17, [audit]);
        Equal(low, HostedCloseoutStoredStateFingerprint.ComputeSaved(Saved(17, [audit])));
        audit[0] = long.MaxValue;
        var high = HostedCloseoutStoredStateFingerprint.Compute(17, [audit]);
        Equal(high, HostedCloseoutStoredStateFingerprint.ComputeSaved(Saved(17, [audit])));
        Assert.NotEqual(low.Sha256, high.Sha256);
    }

    [Fact]
    public void Type_row_width_cell_and_total_row_bounds_refuse_before_ambiguous_hashing()
    {
        foreach (var index in new[] { -1, 0, 6, 12, 20, 21, 22, int.MaxValue })
            Assert.Throws<InvalidDataException>(() => HostedCloseoutStoredStateFingerprint.Schema(index));
        Assert.Throws<InvalidDataException>(() => HostedCloseoutStoredStateFingerprint.Compute(3, [Row(3)[..^1]]));
        Assert.Throws<InvalidDataException>(() => HostedCloseoutStoredStateFingerprint.Compute(3, [Row(3).Append((object?)1).ToArray()]));
        var row = Row(3);
        row[1] = new string('a', HostedCloseoutStoredStateFingerprint.MaximumCellBytes + 1);
        Assert.Throws<InvalidDataException>(() => HostedCloseoutStoredStateFingerprint.Compute(3, [row]));
        row[1] = new string('終', HostedCloseoutStoredStateFingerprint.MaximumCellBytes / 3 + 1);
        Assert.Throws<InvalidDataException>(() => HostedCloseoutStoredStateFingerprint.Compute(3, [row]));
        Assert.Throws<InvalidDataException>(() => HostedCloseoutStoredStateFingerprint.Compute(1, ManyRows()));
        static IEnumerable<IReadOnlyList<object?>> ManyRows()
        {
            for (var i = 0; i <= HostedCloseoutStoredStateFingerprint.MaximumRows; i++)
                yield return new object?[] { i.ToString(CultureInfo.InvariantCulture), "10.0" };
        }
    }

    [Fact]
    public void Schema_domains_separate_tables_even_for_empty_sets_and_never_return_raw_keys()
    {
        var hashes = Sets.Select(x => HostedCloseoutStoredStateFingerprint.Compute(x, [])).ToArray();
        Assert.Equal(Sets.Length, hashes.Select(x => x.SchemaSha256).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(Sets.Length, hashes.Select(x => x.Sha256).Distinct(StringComparer.Ordinal).Count());
        var row = Row(19);
        row[0] = "synthetic@example.invalid";
        var output = JsonSerializer.Serialize(HostedCloseoutStoredStateFingerprint.Compute(19, [row]));
        Assert.DoesNotContain("synthetic@example.invalid", output, StringComparison.Ordinal);
        Assert.DoesNotContain(Convert.ToBase64String((byte[])row[3]!), output, StringComparison.Ordinal);
    }

    private static object?[] Row(int index) => HostedCloseoutStoredStateFingerprint.Schema(index).Columns
        .Select((column, i) => Sample(column, i)).ToArray();

    private static object Sample(HostedCloseoutStoredStateColumn column, int ordinal) => column.SqlType switch
    {
        "nvarchar" => "synthetic-é-終-💠-" + ordinal.ToString(CultureInfo.InvariantCulture),
        "uniqueidentifier" => Guid.Parse("abcdefff-1234-5678-9abc-000000000001"),
        "datetimeoffset" => DateTimeOffset.ParseExact("2030-01-02T03:04:05.1234567+00:00", "O", CultureInfo.InvariantCulture),
        "varbinary" or "timestamp" => Enumerable.Range(0, column.ExactBytes!.Value).Select(x => (byte)(x + 1)).ToArray(),
        "int" => 17,
        "bigint" => 9007199254740993L,
        "bit" => true,
        _ => throw new InvalidOperationException()
    };

    private static object Change(object value) => value switch
    {
        string text => text + "x",
        Guid guid => Guid.Parse(guid.ToString("N")[..31] + "2"),
        DateTimeOffset date => date.AddTicks(1),
        byte[] bytes => bytes.Select((x, i) => i == 0 ? (byte)(x ^ 1) : x).ToArray(),
        int integer => integer + 1,
        long integer => integer + 1,
        bool bit => !bit,
        _ => throw new InvalidOperationException()
    };

    private static Type ClrType(string sqlType) => sqlType switch
    {
        "nvarchar" => typeof(string), "uniqueidentifier" => typeof(Guid), "datetimeoffset" => typeof(DateTimeOffset),
        "varbinary" or "timestamp" => typeof(byte[]), "int" => typeof(int), "bigint" => typeof(long), "bit" => typeof(bool),
        _ => throw new InvalidOperationException()
    };

    private static JsonElement Saved(int index, IReadOnlyList<object?[]> rows)
    {
        using var stream = new MemoryStream();
        using (var json = new Utf8JsonWriter(stream))
        {
            json.WriteStartObject();
            json.WriteNumber("Index", index);
            json.WriteStartArray("Columns");
            foreach (var column in HostedCloseoutStoredStateFingerprint.Schema(index).Columns)
            {
                json.WriteStartObject();
                json.WriteString("Name", column.Name);
                json.WriteString("SqlType", column.SqlType);
                json.WriteEndObject();
            }
            json.WriteEndArray();
            json.WriteStartArray("Rows");
            foreach (var row in rows)
            {
                json.WriteStartArray();
                foreach (var value in row)
                    switch (value)
                    {
                        case null or DBNull: json.WriteNullValue(); break;
                        case string text: json.WriteStringValue(text); break;
                        case Guid guid: json.WriteStringValue(guid); break;
                        case DateTimeOffset date: json.WriteStringValue(date.ToString("O", CultureInfo.InvariantCulture)); break;
                        case byte[] binary: json.WriteBase64StringValue(binary); break;
                        case int integer: json.WriteNumberValue(integer); break;
                        case long integer: json.WriteNumberValue(integer); break;
                        case bool bit: json.WriteBooleanValue(bit); break;
                        default: throw new InvalidOperationException();
                    }
                json.WriteEndArray();
            }
            json.WriteEndArray();
            json.WriteEndObject();
        }
        using var document = JsonDocument.Parse(stream.ToArray());
        return document.RootElement.Clone();
    }

    private static void Equal(HostedCloseoutStoredStateSetFingerprint expected, HostedCloseoutStoredStateSetFingerprint actual)
    {
        Assert.Equal(expected.Index, actual.Index);
        Assert.Equal(expected.Table, actual.Table);
        Assert.Equal(expected.SchemaSha256, actual.SchemaSha256);
        Assert.Equal(expected.Sha256, actual.Sha256);
        Assert.Equal(expected.Rows.ToArray(), actual.Rows.ToArray());
    }
}