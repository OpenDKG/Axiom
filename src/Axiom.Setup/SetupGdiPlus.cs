// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Axiom.Setup;

/// <summary>
/// Lightweight flat GDI+ helper for anti-aliased cards, gradients, vector icons, and
/// embedded PNG rendering in Axiom.Setup with zero extra framework dependencies.
/// </summary>
internal sealed class SetupGdiPlus : IDisposable
{
    public const int FontStyleRegular = 0;
    public const int FontStyleBold = 1;
    public const int AlignNear = 0;
    public const int AlignCenter = 1;
    public const int AlignFar = 2;
    public const int LinearGradientHorizontal = 0;
    public const int LinearGradientVertical = 1;

    private readonly nint _token;
    private readonly bool _initialized;

    public SetupGdiPlus()
    {
        var input = new GdiplusStartupInput { GdiplusVersion = 1 };
        _initialized = GdiplusStartup(out _token, in input, nint.Zero) == 0;
    }

    public bool IsAvailable => _initialized;

    public static uint Argb(byte a, byte r, byte g, byte b) =>
        ((uint)a << 24) | ((uint)r << 16) | ((uint)g << 8) | b;

    public static uint Rgb(byte r, byte g, byte b) => Argb(255, r, g, b);

    public nint LoadEmbeddedLogo()
    {
        if (!_initialized)
        {
            return nint.Zero;
        }

        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("Axiom.Setup.Logo.png");
        if (stream is null)
        {
            return nint.Zero;
        }

        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        var bytes = ms.ToArray();
        nint comStream = SHCreateMemStream(bytes, (uint)bytes.Length);
        if (comStream == nint.Zero)
        {
            return nint.Zero;
        }

        try
        {
            return GdipLoadImageFromStream(comStream, out nint image) == 0 ? image : nint.Zero;
        }
        finally
        {
            _ = Marshal.Release(comStream);
        }
    }

    public static nint CreateGraphics(nint hdc)
    {
        if (GdipCreateFromHDC(hdc, out nint g) != 0)
        {
            return nint.Zero;
        }

        _ = GdipSetSmoothingMode(g, 4);        // SmoothingModeAntiAlias
        _ = GdipSetPixelOffsetMode(g, 2);      // PixelOffsetModeHighQuality
        _ = GdipSetTextRenderingHint(g, 5);    // ClearTypeGridFit
        _ = GdipSetInterpolationMode(g, 7);    // HighQualityBicubic
        return g;
    }

    public static nint CreateFont(string familyName, float px, int style = FontStyleRegular)
    {
        if (GdipCreateFontFamilyFromName(familyName, nint.Zero, out nint family) != 0)
        {
            return nint.Zero;
        }

        try
        {
            return GdipCreateFont(family, px, style, 2 /* Pixel */, out nint font) == 0 ? font : nint.Zero;
        }
        finally
        {
            _ = GdipDeleteFontFamily(family);
        }
    }

    public static nint CreateStringFormat(int align = AlignNear, int lineAlign = AlignNear, bool noWrap = false)
    {
        if (GdipCreateStringFormat(0, 0, out nint fmt) != 0)
        {
            return nint.Zero;
        }

        _ = GdipSetStringFormatAlign(fmt, align);
        _ = GdipSetStringFormatLineAlign(fmt, lineAlign);
        _ = GdipSetStringFormatTrimming(fmt, 3 /* EllipsisCharacter */);
        if (noWrap)
        {
            _ = GdipSetStringFormatFlags(fmt, 0x1000 /* NoWrap */);
        }

        return fmt;
    }

    public static nint CreateRoundedRectPath(float x, float y, float w, float h, float radius)
    {
        _ = GdipCreatePath(0, out nint path);
        if (radius <= 0.5f)
        {
            _ = GdipAddPathLine(path, x, y, x + w, y);
            _ = GdipAddPathLine(path, x + w, y, x + w, y + h);
            _ = GdipAddPathLine(path, x + w, y + h, x, y + h);
            _ = GdipClosePathFigure(path);
            return path;
        }

        float d = Math.Min(radius * 2f, Math.Min(w, h));
        _ = GdipAddPathArc(path, x, y, d, d, 180f, 90f);
        _ = GdipAddPathArc(path, x + w - d, y, d, d, 270f, 90f);
        _ = GdipAddPathArc(path, x + w - d, y + h - d, d, d, 0f, 90f);
        _ = GdipAddPathArc(path, x, y + h - d, d, d, 90f, 90f);
        _ = GdipClosePathFigure(path);
        return path;
    }

    public static void FillRoundedRect(nint g, float x, float y, float w, float h, float r, uint argb)
    {
        nint path = CreateRoundedRectPath(x, y, w, h, r);
        _ = GdipCreateSolidFill(argb, out nint brush);
        _ = GdipFillPath(g, brush, path);
        _ = GdipDeleteBrush(brush);
        _ = GdipDeletePath(path);
    }

    public static void FillRoundedRectGradient(
        nint g, float x, float y, float w, float h, float r, uint color1, uint color2, int mode = LinearGradientVertical)
    {
        nint path = CreateRoundedRectPath(x, y, w, h, r);
        var p1 = new GpPointF(x, y);
        var p2 = mode == LinearGradientHorizontal
            ? new GpPointF(x + Math.Max(1f, w), y)
            : new GpPointF(x, y + Math.Max(1f, h));
        _ = GdipCreateLineBrush(in p1, in p2, color1, color2, 3 /* TileFlipXY */, out nint brush);
        _ = GdipFillPath(g, brush, path);
        _ = GdipDeleteBrush(brush);
        _ = GdipDeletePath(path);
    }

    public static void DrawRoundedRect(nint g, float x, float y, float w, float h, float r, uint argb, float strokeWidth = 1f)
    {
        nint path = CreateRoundedRectPath(x, y, w, h, r);
        _ = GdipCreatePen1(argb, strokeWidth, 2 /* Pixel */, out nint pen);
        _ = GdipDrawPath(g, pen, path);
        _ = GdipDeletePen(pen);
        _ = GdipDeletePath(path);
    }

    public static void FillRectGradient(
        nint g, float x, float y, float w, float h, uint color1, uint color2, int mode = LinearGradientVertical)
    {
        var p1 = new GpPointF(x, y);
        var p2 = mode == LinearGradientHorizontal
            ? new GpPointF(x + Math.Max(1f, w), y)
            : new GpPointF(x, y + Math.Max(1f, h));
        _ = GdipCreateLineBrush(in p1, in p2, color1, color2, 3 /* TileFlipXY */, out nint brush);
        _ = GdipFillRectangle(g, brush, x, y, w, h);
        _ = GdipDeleteBrush(brush);
    }

    public static void FillRect(nint g, float x, float y, float w, float h, uint argb)
    {
        _ = GdipCreateSolidFill(argb, out nint brush);
        _ = GdipFillRectangle(g, brush, x, y, w, h);
        _ = GdipDeleteBrush(brush);
    }

    public static void DrawLine(nint g, float x1, float y1, float x2, float y2, uint argb, float width = 1f)
    {
        _ = GdipCreatePen1(argb, width, 2 /* Pixel */, out nint pen);
        _ = GdipDrawLine(g, pen, x1, y1, x2, y2);
        _ = GdipDeletePen(pen);
    }

    public static void FillEllipse(nint g, float x, float y, float w, float h, uint argb)
    {
        _ = GdipCreateSolidFill(argb, out nint brush);
        _ = GdipFillEllipse(g, brush, x, y, w, h);
        _ = GdipDeleteBrush(brush);
    }

    public static void DrawEllipse(nint g, float x, float y, float w, float h, uint argb, float strokeWidth = 1.5f)
    {
        _ = GdipCreatePen1(argb, strokeWidth, 2 /* Pixel */, out nint pen);
        _ = GdipDrawEllipse(g, pen, x, y, w, h);
        _ = GdipDeletePen(pen);
    }

    public static void DrawCheckmark(nint g, float x, float y, float size, uint argb, float strokeWidth = 1.8f)
    {
        _ = GdipCreatePen1(argb, strokeWidth, 2 /* Pixel */, out nint pen);
        _ = GdipSetPenStartCap(pen, 2 /* Round */);
        _ = GdipSetPenEndCap(pen, 2 /* Round */);
        _ = GdipSetPenLineJoin(pen, 2 /* Round */);
        _ = GdipCreatePath(0, out nint path);
        _ = GdipAddPathLine(path, x + size * 0.18f, y + size * 0.54f, x + size * 0.42f, y + size * 0.77f);
        _ = GdipAddPathLine(path, x + size * 0.42f, y + size * 0.77f, x + size * 0.84f, y + size * 0.25f);
        _ = GdipDrawPath(g, pen, path);
        _ = GdipDeletePath(path);
        _ = GdipDeletePen(pen);
    }

    public static void DrawText(
        nint g, string text, nint font, float x, float y, float w, float h, uint argb, nint format)
    {
        if (string.IsNullOrEmpty(text) || font == nint.Zero)
        {
            return;
        }

        _ = GdipCreateSolidFill(argb, out nint brush);
        var rect = new GpRectF(x, y, Math.Max(1f, w), Math.Max(1f, h));
        _ = GdipDrawString(g, text, text.Length, font, in rect, format, brush);
        _ = GdipDeleteBrush(brush);
    }

    public static void DrawImage(nint g, nint image, float x, float y, float w, float h)
    {
        if (image != nint.Zero)
        {
            _ = GdipDrawImageRect(g, image, x, y, w, h);
        }
    }

    public static void SetClip(nint g, float x, float y, float w, float h) =>
        _ = GdipSetClipRect(g, x, y, w, h, 0 /* CombineModeReplace */);

    public static void ResetClip(nint g) => _ = GdipResetClip(g);

    public static void DisposeGraphics(nint g)
    {
        if (g != nint.Zero)
        {
            _ = GdipDeleteGraphics(g);
        }
    }

    public static void DisposeFont(ref nint font)
    {
        if (font != nint.Zero)
        {
            _ = GdipDeleteFont(font);
            font = nint.Zero;
        }
    }

    public static void DisposeFormat(ref nint format)
    {
        if (format != nint.Zero)
        {
            _ = GdipDeleteStringFormat(format);
            format = nint.Zero;
        }
    }

    public static void DisposeImage(ref nint image)
    {
        if (image != nint.Zero)
        {
            _ = GdipDisposeImage(image);
            image = nint.Zero;
        }
    }

    public void Dispose()
    {
        if (_initialized)
        {
            GdiplusShutdown(_token);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public readonly struct GpPointF(float x, float y)
    {
        public readonly float X = x;
        public readonly float Y = y;
    }

    [StructLayout(LayoutKind.Sequential)]
    public readonly struct GpRectF(float x, float y, float width, float height)
    {
        public readonly float X = x;
        public readonly float Y = y;
        public readonly float Width = width;
        public readonly float Height = height;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct GdiplusStartupInput
    {
        public uint GdiplusVersion;
        public nint DebugEventCallback;
        [MarshalAs(UnmanagedType.Bool)] public bool SuppressBackgroundThread;
        [MarshalAs(UnmanagedType.Bool)] public bool SuppressExternalCodecs;
    }

    [DllImport("shlwapi.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern nint SHCreateMemStream(byte[] pInit, uint cbInit);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdiplusStartup(out nint token, in GdiplusStartupInput input, nint output);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern void GdiplusShutdown(nint token);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipCreateFromHDC(nint hdc, out nint graphics);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipDeleteGraphics(nint graphics);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipSetSmoothingMode(nint graphics, int smoothingMode);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipSetPixelOffsetMode(nint graphics, int pixelOffsetMode);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipSetTextRenderingHint(nint graphics, int mode);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipSetInterpolationMode(nint graphics, int interpolationMode);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipCreateSolidFill(uint color, out nint brush);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipDeleteBrush(nint brush);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipCreateLineBrush(
        in GpPointF point1, in GpPointF point2, uint color1, uint color2, int wrapMode, out nint lineGradient);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipCreatePen1(uint color, float width, int unit, out nint pen);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipDeletePen(nint pen);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipSetPenStartCap(nint pen, int startCap);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipSetPenEndCap(nint pen, int endCap);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipSetPenLineJoin(nint pen, int lineJoin);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipCreatePath(int brushMode, out nint path);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipDeletePath(nint path);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipAddPathArc(
        nint path, float x, float y, float width, float height, float startAngle, float sweepAngle);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipAddPathLine(nint path, float x1, float y1, float x2, float y2);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipClosePathFigure(nint path);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipFillPath(nint graphics, nint brush, nint path);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipDrawPath(nint graphics, nint pen, nint path);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipFillRectangle(nint graphics, nint brush, float x, float y, float width, float height);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipDrawLine(nint graphics, nint pen, float x1, float y1, float x2, float y2);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipFillEllipse(nint graphics, nint brush, float x, float y, float width, float height);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipDrawEllipse(nint graphics, nint pen, float x, float y, float width, float height);

    [DllImport("gdiplus.dll", CharSet = CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipCreateFontFamilyFromName(string name, nint fontCollection, out nint fontFamily);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipDeleteFontFamily(nint fontFamily);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipCreateFont(nint fontFamily, float emSize, int style, int unit, out nint font);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipDeleteFont(nint font);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipCreateStringFormat(int formatAttributes, ushort language, out nint format);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipSetStringFormatAlign(nint format, int align);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipSetStringFormatLineAlign(nint format, int align);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipSetStringFormatTrimming(nint format, int trimming);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipSetStringFormatFlags(nint format, int flags);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipDeleteStringFormat(nint format);

    [DllImport("gdiplus.dll", CharSet = CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipDrawString(
        nint graphics, string str, int length, nint font, in GpRectF layoutRect, nint stringFormat, nint brush);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipLoadImageFromStream(nint stream, out nint image);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipDrawImageRect(nint graphics, nint image, float x, float y, float width, float height);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipDisposeImage(nint image);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipSetClipRect(nint graphics, float x, float y, float width, float height, int combineMode);

    [DllImport("gdiplus.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GdipResetClip(nint graphics);
}
