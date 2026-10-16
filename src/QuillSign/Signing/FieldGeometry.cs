using QuillSign.Documents;

namespace QuillSign.Signing;

// Coordinates are fractions of the visible, rotated CropBox, measured from its top-left corner.
public static class FieldGeometry
{
    public static decimal Round(decimal value) => decimal.Round(value, 8, MidpointRounding.ToZero);
    public static bool InBounds(decimal x, decimal y, decimal width, decimal height) =>
        x is >= 0 and <= 1 && y is >= 0 and <= 1 && width is > 0 and <= 1 && height is > 0 and <= 1 &&
        width <= 1 - x && height <= 1 - y && Round(width) > 0 && Round(height) > 0;

    // PDF user-space rectangle (bottom-left origin, before /Rotate and /UserUnit).
    // UserUnit changes physical size, not the coordinates stored in PDF page content.
    public static (double X, double Y, double Width, double Height) ToPdfRectangle(PageGeometry page,
        decimal x, decimal y, decimal width, decimal height)
    {
        if (!InBounds(x, y, width, height)) throw new ArgumentOutOfRangeException(nameof(x));
        var box = page.CropBox;
        var w = box[2] - box[0]; var h = box[3] - box[1];
        var nx = (double)x; var ny = (double)y; var nw = (double)width; var nh = (double)height;
        return page.Rotation switch
        {
            0 => (box[0] + nx * w, box[1] + (1 - ny - nh) * h, nw * w, nh * h),
            90 => (box[0] + ny * w, box[1] + nx * h, nh * w, nw * h),
            180 => (box[0] + (1 - nx - nw) * w, box[1] + ny * h, nw * w, nh * h),
            270 => (box[0] + (1 - ny - nh) * w, box[1] + (1 - nx - nw) * h, nh * w, nw * h),
            _ => throw new ArgumentOutOfRangeException(nameof(page))
        };
    }
}
