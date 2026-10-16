import { test } from "node:test";
import assert from "node:assert/strict";
import { imageDimensions } from "../../src/QuillSign/wwwroot/js/signature-images.mjs";

const chunk = (type, data) => { const value = new Uint8Array(data.length + 12); new DataView(value.buffer).setUint32(0, data.length); value.set(new TextEncoder().encode(type), 4); value.set(data, 8); return value; };
function png(width = 32, height = 16, extra = []) {
    const header = new Uint8Array(13); const view = new DataView(header.buffer); view.setUint32(0, width); view.setUint32(4, height); header[8] = 8; header[9] = 6;
    return new Uint8Array([137,80,78,71,13,10,26,10,...chunk("IHDR", header),...extra,...chunk("IEND", [])]);
}
test("bounds static PNG header dimensions before decoding", () => assert.deepEqual(imageDimensions(png()), { width: 32, height: 16 }));
test("bounds baseline and progressive JPEG headers before decoding", () => {
    for (const marker of [192,194]) assert.deepEqual(imageDimensions(new Uint8Array([255,216,255,marker,0,8,8,0,16,0,32,3])), { width: 32, height: 16 });
});
for (const [width, height] of [[0,16],[32,0],[2049,16],[32,1025],[0xffffffff,16]])
    test(`rejects oversized/zero PNG ${width}x${height}`, () => assert.throws(() => imageDimensions(png(width, height))));
test("rejects animation controls even with a bounded PNG raster", () => {
    for (const type of ["acTL","fcTL","fdAT"]) assert.throws(() => imageDimensions(png(32,16,chunk(type, []))));
});
test("rejects unsupported formats, truncated PNGs and trailing bytes", () => {
    for (const bytes of [new Uint8Array([71,73,70,56,57,97]), png().slice(0,-1), new Uint8Array([...png(),1]), new Uint8Array([255,216,255,192,0,8,8])])
        assert.throws(() => imageDimensions(bytes));
});
test("rejects excess chunks and huge declared chunk lengths", () => {
    const chunks = Array.from({ length: 129 }, () => chunk("tEXt", [])).flatMap(value => [...value]); assert.throws(() => imageDimensions(png(32,16,chunks)));
    const bytes = png(); new DataView(bytes.buffer).setUint32(33, 0xffffffff); assert.throws(() => imageDimensions(bytes));
});
test("JPEG bounds and missing or unsupported frame cannot allocate a raster", () => {
    for (const bytes of [[255,216,255,192,0,8,8,0,16,8,1,3],[255,216,255,195,0,8,8,0,16,0,32,3],[255,216,255,218]])
        assert.throws(() => imageDimensions(new Uint8Array(bytes)));
});
