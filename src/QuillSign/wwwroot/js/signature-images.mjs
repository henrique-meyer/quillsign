function dimensions(width, height) {
    if (!width || !height || width > 2048 || height > 1024) throw new Error("Use images no larger than 2048 × 1024 pixels.");
    return { width, height };
}
// Inspect bounded source headers before asking the browser decoder to allocate a raster.
export function imageDimensions(bytes) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const at = (p, n) => { if (p + n > bytes.length) throw new Error("The image is truncated or invalid."); };
    if (bytes.length >= 24 && [137,80,78,71,13,10,26,10].every((n, i) => bytes[i] === n)) {
        at(8, 25); if (view.getUint32(8) !== 13 || String.fromCharCode(...bytes.slice(12,16)) !== "IHDR") throw new Error("Invalid PNG header.");
        const result = dimensions(view.getUint32(16), view.getUint32(20)); let p = 8, count = 0, ended = false;
        while (p < bytes.length) {
            at(p, 12); const length = view.getUint32(p); at(p, length + 12);
            const kind = String.fromCharCode(...bytes.slice(p + 4, p + 8));
            if (["acTL", "fcTL", "fdAT"].includes(kind)) throw new Error("Animated PNGs are unsupported. Choose a static image.");
            if (++count > 128) throw new Error("This PNG is too complex. Export a simpler image.");
            p += length + 12;
            if (kind === "IEND") { if (length || p !== bytes.length) throw new Error("Invalid PNG trailer."); ended = true; break; }
        }
        if (!ended) throw new Error("The PNG is incomplete."); return result;
    }
    if (bytes[0] === 255 && bytes[1] === 216) {
        let p = 2, count = 0;
        while (p < bytes.length && ++count < 256) {
            at(p, 2); if (bytes[p++] !== 255) throw new Error("Invalid JPEG marker.");
            while (bytes[p] === 255) p++; at(p, 1); const marker = bytes[p++];
            if (marker === 217 || marker === 218) break;
            if (marker === 1 || (marker >= 208 && marker <= 215)) continue;
            at(p, 2); const length = view.getUint16(p); if (length < 2) throw new Error("Invalid JPEG segment."); at(p, length);
            if ([192,193,194].includes(marker)) { if (length < 8) throw new Error("Invalid JPEG frame."); return dimensions(view.getUint16(p + 5), view.getUint16(p + 3)); }
            p += length;
        }
        throw new Error("This JPEG frame is unsupported or incomplete.");
    }
    throw new Error("Choose a static PNG or JPEG image.");
}
