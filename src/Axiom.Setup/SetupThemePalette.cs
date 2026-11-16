// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;

namespace Axiom.Setup;

/// <summary>
/// Maps Axiom's active UiTheme (from ThemeSettingsStore) onto matching GDI+ and Win32 colors
/// so Axiom Setup shares the exact palette, contrast, and 6 px geometry of the desktop app.
/// </summary>
internal sealed record SetupThemePalette(
    bool IsDark,
    uint BgTop,
    uint BgBottom,
    uint HeaderTop,
    uint HeaderBottom,
    uint FooterBg,
    uint Surface,
    uint SurfaceHover,
    uint CardActiveTop,
    uint CardActiveBottom,
    uint CardActiveHighlight,
    uint Border,
    uint BorderStrong,
    uint Accent,
    uint AccentHover,
    uint AccentPressed,
    uint AccentContrast,
    uint PillFill,
    uint PillBorder,
    uint PillText,
    uint BtnBg,
    uint BtnHover,
    uint BtnPressed,
    uint BtnDisabledBg,
    uint DangerBg,
    uint DangerHover,
    uint DangerBorder,
    uint DangerText,
    uint TextPrimary,
    uint TextSecondary,
    uint TextMuted,
    uint WarnBg,
    uint WarnBorder,
    uint WarnAccent,
    uint WarnText,
    uint SuccessBg,
    uint SuccessBorder,
    uint SuccessAccent,
    uint SuccessText,
    uint ErrorBg,
    uint ErrorBorder,
    uint ErrorAccent,
    uint ErrorText,
    int EditBgGdi,
    int EditTextGdi,
    int DwmCaptionGdi,
    int DwmBorderGdi)
{
    public static SetupThemePalette LoadCurrent() => ForTheme(ThemeSettingsStore.Load());

    public static SetupThemePalette ForTheme(UiTheme theme) => theme switch
    {
        UiTheme.Dark => CreateDark(),
        UiTheme.DarkMidnight => CreateDarkMidnight(),
        UiTheme.Light => CreateLight(),
        UiTheme.GlassLight => CreateGlassLight(),
        UiTheme.LightWarm => CreateLightWarm(),
        _ => CreateGlassDark(),
    };

    private static SetupThemePalette CreateGlassDark() => new(
        IsDark: true,
        BgTop: SetupGdiPlus.Rgb(11, 15, 23),
        BgBottom: SetupGdiPlus.Rgb(7, 10, 16),
        HeaderTop: SetupGdiPlus.Rgb(15, 20, 30),
        HeaderBottom: SetupGdiPlus.Rgb(10, 14, 21),
        FooterBg: SetupGdiPlus.Rgb(9, 13, 20),
        Surface: SetupGdiPlus.Rgb(23, 29, 40),
        SurfaceHover: SetupGdiPlus.Rgb(31, 39, 53),
        CardActiveTop: SetupGdiPlus.Rgb(34, 42, 56),
        CardActiveBottom: SetupGdiPlus.Rgb(23, 29, 40),
        CardActiveHighlight: SetupGdiPlus.Argb(115, 255, 255, 255),
        Border: SetupGdiPlus.Rgb(39, 49, 65),
        BorderStrong: SetupGdiPlus.Rgb(78, 92, 114),
        Accent: SetupGdiPlus.Rgb(226, 232, 240),        // #E2E8F0 brushed silver chrome
        AccentHover: SetupGdiPlus.Rgb(255, 255, 255),
        AccentPressed: SetupGdiPlus.Rgb(203, 213, 225),
        AccentContrast: SetupGdiPlus.Rgb(15, 23, 42),   // #0F172A
        PillFill: SetupGdiPlus.Rgb(28, 35, 48),
        PillBorder: SetupGdiPlus.Rgb(72, 85, 106),
        PillText: SetupGdiPlus.Rgb(226, 232, 240),
        BtnBg: SetupGdiPlus.Rgb(30, 38, 52),
        BtnHover: SetupGdiPlus.Rgb(43, 54, 72),
        BtnPressed: SetupGdiPlus.Rgb(22, 28, 39),
        BtnDisabledBg: SetupGdiPlus.Rgb(21, 27, 38),
        DangerBg: SetupGdiPlus.Rgb(127, 29, 29),
        DangerHover: SetupGdiPlus.Rgb(153, 27, 27),
        DangerBorder: SetupGdiPlus.Rgb(248, 113, 113),
        DangerText: SetupGdiPlus.Rgb(255, 255, 255),
        TextPrimary: SetupGdiPlus.Rgb(255, 255, 255),
        TextSecondary: SetupGdiPlus.Rgb(226, 232, 240),
        TextMuted: SetupGdiPlus.Rgb(160, 174, 192),
        WarnBg: SetupGdiPlus.Rgb(26, 21, 15),
        WarnBorder: SetupGdiPlus.Rgb(146, 64, 14),
        WarnAccent: SetupGdiPlus.Rgb(251, 191, 36),
        WarnText: SetupGdiPlus.Rgb(251, 191, 36),
        SuccessBg: SetupGdiPlus.Rgb(16, 28, 25),
        SuccessBorder: SetupGdiPlus.Rgb(22, 101, 52),
        SuccessAccent: SetupGdiPlus.Rgb(74, 222, 128),
        SuccessText: SetupGdiPlus.Rgb(134, 239, 172),
        ErrorBg: SetupGdiPlus.Rgb(34, 16, 20),
        ErrorBorder: SetupGdiPlus.Rgb(153, 27, 27),
        ErrorAccent: SetupGdiPlus.Rgb(251, 113, 133),
        ErrorText: SetupGdiPlus.Rgb(254, 205, 211),
        EditBgGdi: GdiRgb(11, 15, 23),
        EditTextGdi: GdiRgb(226, 232, 240),
        DwmCaptionGdi: GdiRgb(15, 20, 30),
        DwmBorderGdi: GdiRgb(39, 49, 65));

    private static SetupThemePalette CreateDark() => CreateGlassDark() with
    {
        BgTop = SetupGdiPlus.Rgb(20, 27, 38),           // #141B26
        BgBottom = SetupGdiPlus.Rgb(17, 23, 33),        // #111721
        HeaderTop = SetupGdiPlus.Rgb(24, 32, 45),       // #18202D
        HeaderBottom = SetupGdiPlus.Rgb(21, 28, 39),    // #151C27
        FooterBg = SetupGdiPlus.Rgb(18, 24, 34),        // #121822
        Surface = SetupGdiPlus.Rgb(37, 47, 62),
        SurfaceHover = SetupGdiPlus.Rgb(49, 61, 80),
        CardActiveTop = SetupGdiPlus.Rgb(53, 66, 85),    // #354255
        CardActiveBottom = SetupGdiPlus.Rgb(40, 50, 66), // #283242
        Border = SetupGdiPlus.Rgb(43, 53, 69),          // #2B3545
        BorderStrong = SetupGdiPlus.Rgb(77, 91, 114),   // #4D5B72
        EditBgGdi = GdiRgb(24, 32, 44),                 // #18202C
        DwmCaptionGdi = GdiRgb(24, 32, 45),
        DwmBorderGdi = GdiRgb(43, 53, 69),
    };

    private static SetupThemePalette CreateDarkMidnight() => new(
        IsDark: true,
        BgTop: SetupGdiPlus.Rgb(14, 20, 36),            // #0E1424
        BgBottom: SetupGdiPlus.Rgb(12, 17, 31),         // #0C111F
        HeaderTop: SetupGdiPlus.Rgb(18, 25, 45),        // #12192D
        HeaderBottom: SetupGdiPlus.Rgb(14, 20, 36),     // #0E1424
        FooterBg: SetupGdiPlus.Rgb(12, 17, 31),
        Surface: SetupGdiPlus.Rgb(26, 36, 61),
        SurfaceHover: SetupGdiPlus.Rgb(36, 49, 82),
        CardActiveTop: SetupGdiPlus.Rgb(38, 51, 87),    // #263357
        CardActiveBottom: SetupGdiPlus.Rgb(26, 36, 61),
        CardActiveHighlight: SetupGdiPlus.Argb(120, 199, 210, 254),
        Border: SetupGdiPlus.Rgb(38, 51, 82),           // #263352
        BorderStrong: SetupGdiPlus.Rgb(71, 91, 140),    // #475B8C
        Accent: SetupGdiPlus.Rgb(165, 180, 252),        // #A5B4FC periwinkle-platinum
        AccentHover: SetupGdiPlus.Rgb(199, 210, 254),   // #C7D2FE
        AccentPressed: SetupGdiPlus.Rgb(129, 140, 248),
        AccentContrast: SetupGdiPlus.Rgb(11, 15, 36),   // #0B0F24
        PillFill: SetupGdiPlus.Rgb(37, 49, 86),         // #253156
        PillBorder: SetupGdiPlus.Rgb(71, 91, 140),
        PillText: SetupGdiPlus.Rgb(199, 210, 254),
        BtnBg: SetupGdiPlus.Rgb(33, 44, 74),            // #212C4A
        BtnHover: SetupGdiPlus.Rgb(44, 58, 97),         // #2C3A61
        BtnPressed: SetupGdiPlus.Rgb(23, 32, 56),
        BtnDisabledBg: SetupGdiPlus.Rgb(22, 30, 52),
        DangerBg: SetupGdiPlus.Rgb(127, 29, 29),
        DangerHover: SetupGdiPlus.Rgb(153, 27, 27),
        DangerBorder: SetupGdiPlus.Rgb(251, 113, 133),
        DangerText: SetupGdiPlus.Rgb(255, 255, 255),
        TextPrimary: SetupGdiPlus.Rgb(248, 250, 252),   // #F8FAFC
        TextSecondary: SetupGdiPlus.Rgb(203, 213, 225), // #CBD5E1
        TextMuted: SetupGdiPlus.Rgb(138, 154, 192),     // #8A9AC0
        WarnBg: SetupGdiPlus.Rgb(28, 22, 18),
        WarnBorder: SetupGdiPlus.Rgb(146, 64, 14),
        WarnAccent: SetupGdiPlus.Rgb(251, 191, 36),
        WarnText: SetupGdiPlus.Rgb(251, 191, 36),
        SuccessBg: SetupGdiPlus.Rgb(14, 30, 30),
        SuccessBorder: SetupGdiPlus.Rgb(17, 94, 89),
        SuccessAccent: SetupGdiPlus.Rgb(52, 211, 153),
        SuccessText: SetupGdiPlus.Rgb(110, 231, 183),
        ErrorBg: SetupGdiPlus.Rgb(36, 15, 24),
        ErrorBorder: SetupGdiPlus.Rgb(153, 27, 27),
        ErrorAccent: SetupGdiPlus.Rgb(251, 113, 133),
        ErrorText: SetupGdiPlus.Rgb(254, 205, 211),
        EditBgGdi: GdiRgb(17, 24, 43),                  // #11182B
        EditTextGdi: GdiRgb(248, 250, 252),
        DwmCaptionGdi: GdiRgb(18, 25, 45),
        DwmBorderGdi: GdiRgb(38, 51, 82));

    private static SetupThemePalette CreateLight() => new(
        IsDark: false,
        BgTop: SetupGdiPlus.Rgb(230, 236, 244),         // #E6ECF4
        BgBottom: SetupGdiPlus.Rgb(215, 224, 236),      // #D7E0EC
        HeaderTop: SetupGdiPlus.Rgb(233, 239, 246),     // #E9EFF6
        HeaderBottom: SetupGdiPlus.Rgb(227, 234, 242),  // #E3EAF2
        FooterBg: SetupGdiPlus.Rgb(222, 229, 239),      // #DEE5EF
        Surface: SetupGdiPlus.Rgb(244, 247, 252),
        SurfaceHover: SetupGdiPlus.Rgb(252, 253, 255),
        CardActiveTop: SetupGdiPlus.Rgb(255, 255, 255),
        CardActiveBottom: SetupGdiPlus.Rgb(240, 244, 250),
        CardActiveHighlight: SetupGdiPlus.Rgb(255, 255, 255),
        Border: SetupGdiPlus.Rgb(207, 216, 229),        // #CFD8E5
        BorderStrong: SetupGdiPlus.Rgb(140, 155, 176),  // #8C9BB0
        Accent: SetupGdiPlus.Rgb(43, 49, 58),           // #2B313A graphite accent
        AccentHover: SetupGdiPlus.Rgb(21, 25, 32),      // #151920
        AccentPressed: SetupGdiPlus.Rgb(68, 76, 89),
        AccentContrast: SetupGdiPlus.Rgb(255, 255, 255),
        PillFill: SetupGdiPlus.Rgb(215, 224, 236),      // #D7E0EC
        PillBorder: SetupGdiPlus.Rgb(140, 155, 176),
        PillText: SetupGdiPlus.Rgb(30, 41, 59),
        BtnBg: SetupGdiPlus.Rgb(238, 242, 248),         // #EEF2F8
        BtnHover: SetupGdiPlus.Rgb(255, 255, 255),
        BtnPressed: SetupGdiPlus.Rgb(215, 224, 236),
        BtnDisabledBg: SetupGdiPlus.Rgb(226, 232, 240),
        DangerBg: SetupGdiPlus.Rgb(220, 38, 38),
        DangerHover: SetupGdiPlus.Rgb(185, 28, 28),
        DangerBorder: SetupGdiPlus.Rgb(185, 28, 28),
        DangerText: SetupGdiPlus.Rgb(255, 255, 255),
        TextPrimary: SetupGdiPlus.Rgb(15, 23, 42),      // #0F172A
        TextSecondary: SetupGdiPlus.Rgb(30, 41, 59),    // #1E293B
        TextMuted: SetupGdiPlus.Rgb(71, 85, 105),       // #475569
        WarnBg: SetupGdiPlus.Rgb(254, 243, 199),
        WarnBorder: SetupGdiPlus.Rgb(217, 119, 6),
        WarnAccent: SetupGdiPlus.Rgb(180, 83, 9),       // #B45309
        WarnText: SetupGdiPlus.Rgb(146, 64, 14),
        SuccessBg: SetupGdiPlus.Rgb(220, 252, 231),
        SuccessBorder: SetupGdiPlus.Rgb(22, 163, 74),
        SuccessAccent: SetupGdiPlus.Rgb(21, 128, 61),
        SuccessText: SetupGdiPlus.Rgb(20, 83, 45),
        ErrorBg: SetupGdiPlus.Rgb(254, 226, 226),
        ErrorBorder: SetupGdiPlus.Rgb(220, 38, 38),
        ErrorAccent: SetupGdiPlus.Rgb(220, 38, 38),
        ErrorText: SetupGdiPlus.Rgb(153, 27, 27),
        EditBgGdi: GdiRgb(248, 250, 253),
        EditTextGdi: GdiRgb(15, 23, 42),
        DwmCaptionGdi: GdiRgb(233, 239, 246),
        DwmBorderGdi: GdiRgb(207, 216, 229));

    private static SetupThemePalette CreateGlassLight() => CreateLight() with
    {
        BgTop = SetupGdiPlus.Rgb(236, 241, 247),
        BgBottom = SetupGdiPlus.Rgb(223, 231, 241),
        HeaderTop = SetupGdiPlus.Rgb(241, 245, 250),
        HeaderBottom = SetupGdiPlus.Rgb(234, 239, 246),
        FooterBg = SetupGdiPlus.Rgb(232, 238, 245),
        Surface = SetupGdiPlus.Rgb(248, 250, 253),
        Border = SetupGdiPlus.Rgb(198, 209, 223),
        DwmCaptionGdi = GdiRgb(241, 245, 250),
        DwmBorderGdi = GdiRgb(198, 209, 223),
    };

    private static SetupThemePalette CreateLightWarm() => CreateLight() with
    {
        BgTop = SetupGdiPlus.Rgb(241, 237, 231),        // #F1EDE7
        BgBottom = SetupGdiPlus.Rgb(227, 220, 211),     // #E3DCD3
        HeaderTop = SetupGdiPlus.Rgb(243, 239, 233),    // #F3EFE9
        HeaderBottom = SetupGdiPlus.Rgb(237, 232, 225), // #EDE8E1
        FooterBg = SetupGdiPlus.Rgb(230, 224, 215),      // #E6E0D7
        Surface = SetupGdiPlus.Rgb(250, 248, 245),      // #FAF8F5
        SurfaceHover = SetupGdiPlus.Rgb(255, 255, 255),
        CardActiveTop = SetupGdiPlus.Rgb(255, 255, 255),
        CardActiveBottom = SetupGdiPlus.Rgb(244, 240, 234),
        Border = SetupGdiPlus.Rgb(221, 213, 202),       // #DDD5CA
        BorderStrong = SetupGdiPlus.Rgb(163, 150, 134), // #A39686
        Accent = SetupGdiPlus.Rgb(68, 60, 53),          // #443C35 obsidian-bronze
        AccentHover = SetupGdiPlus.Rgb(41, 35, 30),      // #29231E
        AccentPressed = SetupGdiPlus.Rgb(88, 78, 69),
        AccentContrast = SetupGdiPlus.Rgb(250, 248, 245),
        PillFill = SetupGdiPlus.Rgb(227, 221, 212),      // #E3DDD4
        PillBorder = SetupGdiPlus.Rgb(163, 150, 134),
        PillText = SetupGdiPlus.Rgb(41, 35, 30),
        BtnBg = SetupGdiPlus.Rgb(244, 240, 234),         // #F4F0EA
        BtnPressed = SetupGdiPlus.Rgb(227, 221, 212),
        BtnDisabledBg = SetupGdiPlus.Rgb(232, 225, 216),
        TextPrimary = SetupGdiPlus.Rgb(30, 27, 24),      // #1E1B18
        TextSecondary = SetupGdiPlus.Rgb(71, 64, 57),    // #474039
        TextMuted = SetupGdiPlus.Rgb(107, 98, 88),       // #6B6258
        EditBgGdi = GdiRgb(250, 248, 245),
        EditTextGdi = GdiRgb(30, 27, 24),
        DwmCaptionGdi = GdiRgb(243, 239, 233),
        DwmBorderGdi = GdiRgb(221, 213, 202),
    };

    private static int GdiRgb(int r, int g, int b) => r | (g << 8) | (b << 16);
}
