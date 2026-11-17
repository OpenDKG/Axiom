// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Axiom.Setup;

/// <summary>
/// Modern dark-titanium Win32 + GDI+ setup window for Axiom. Zero heavy UI framework bloat
/// while providing side-by-side build cards, crisp custom controls, live progress, automatic
/// post-install/update launch and clean self-exit.
/// </summary>
internal sealed class SetupNativeWindow : IDisposable
{
    private const string WindowClassName = "AxiomSetupModernWindow";
    private const int LogicalWidth = 820;
    private const int LogicalHeight = 690;

    private const uint WmCreate = 0x0001;
    private const uint WmDestroy = 0x0002;
    private const uint WmSize = 0x0005;
    private const uint WmPaint = 0x000F;
    private const uint WmClose = 0x0010;
    private const uint WmEraseBkgnd = 0x0014;
    private const uint WmSetFont = 0x0030;
    private const uint WmSetCursor = 0x0020;
    private const uint WmSetIcon = 0x0080;
    private const uint WmKeyDown = 0x0100;
    private const uint WmTimer = 0x0113;
    private const uint WmCtlColorEdit = 0x0133;
    private const uint WmCtlColorStatic = 0x0138;
    private const uint WmMouseMove = 0x0200;
    private const uint WmLButtonDown = 0x0201;
    private const uint WmLButtonUp = 0x0202;
    private const uint WmMouseLeave = 0x02A3;
    private const uint WmPrintClient = 0x0318;
    private const uint WmAppLog = 0x8001;
    private const uint WmAppDone = 0x8002;

    private const uint WsOverlapped = 0x00000000;
    private const uint WsCaption = 0x00C00000;
    private const uint WsSysMenu = 0x00080000;
    private const uint WsMinimizeBox = 0x00020000;
    private const uint WsVisible = 0x10000000;
    private const uint WsChild = 0x40000000;
    private const uint WsVScroll = 0x00200000;
    private const uint EsMultiline = 0x0004;
    private const uint EsAutoVScroll = 0x0040;
    private const uint EsReadOnly = 0x0800;

    private const uint EmSetSel = 0x00B1;
    private const uint EmReplaceSel = 0x00C2;
    private const uint EmScrollCaret = 0x00B7;

    private const uint MbOk = 0x00000000;
    private const uint MbYesNo = 0x00000004;
    private const uint MbIconError = 0x00000010;
    private const uint MbIconQuestion = 0x00000020;
    private const uint MbIconWarning = 0x00000030;
    private const uint MbIconInformation = 0x00000040;
    private const int IdYes = 6;

    private const int DwmwaUseImmersiveDarkMode = 20;
    private const int DwmwaWindowCornerPreference = 33;
    private const int DwmwaBorderColor = 34;
    private const int DwmwaCaptionColor = 35;
    private const uint SpiGetWorkArea = 0x0030;
    private const nuint AnimTimerId = 1;

    private const int IdScopeEdit = 201;
    private const int IdLogEdit = 202;

    private enum ViewMode
    {
        Configure,
        Scope,
        Progress,
    }

    private enum HitId
    {
        None = 0,
        CardComplete,
        CardPartial,
        WriteScopeLink,
        ShortcutCheck,
        LaunchCheck,
        AgreeRow,
        BackFromScopeBtn,
        OpenAxiomBtn,
        RepairBtn,
        UninstallBtn,
        ViewScopeBtn,
        BackAfterErrorBtn,
        InstallBtn,
        CloseBtn,
    }

    private sealed record HitZone(HitId Id, RECT Bounds, bool Enabled = true);

    private readonly SetupOptions _initialOptions;
    private SetupThemePalette _palette;
    private readonly SetupGdiPlus _gdip = new();
    private readonly ConcurrentQueue<string> _logQueue = new();
    private readonly List<HitZone> _hitZones = [];
    private readonly Stopwatch _opClock = new();

    private WndProcDelegate? _wndProc;
    private nint _hwnd;
    private nint _hScopeEdit;
    private nint _hLogEdit;
    private nint _brushEdit;
    private nint _editFont;
    private nint _logoImage;

    // GDI+ cached fonts & string formats
    private nint _gpTitle;
    private nint _gpSubtitle;
    private nint _gpSection;
    private nint _gpCardTitle;
    private nint _gpBodyBold;
    private nint _gpBody;
    private nint _gpSmall;
    private nint _gpBadge;
    private nint _gpMono;
    private nint _fmtNear;
    private nint _fmtNearCenter;
    private nint _fmtCenter;
    private nint _fmtFarCenter;

    // Backbuffer for flicker-free rendering
    private nint _backDc;
    private nint _backBitmap;
    private nint _backOldBitmap;
    private int _backWidth;
    private int _backHeight;

    private double _scale = 1.0;
    private ViewMode _mode = ViewMode.Configure;
    private bool _completeMode;
    private bool _createShortcut;
    private bool _startAfterInstall;
    private bool _acceptRisk;
    private bool _installing;
    private bool _lastOperationWasUninstall;
    private bool _lastOperationWasRepair;
    private ExistingInstallationInfo _existing = new(false, null, null, null);
    private SetupInstallResult? _installResult;
    private string _currentStepText = "Preparing installation...";
    private string _appVersionText;
    private HitId _hoverId = HitId.None;
    private HitId _pressedId = HitId.None;
    private bool _trackingMouse;
    private int _animPhase;
    private int _clientW;
    private int _clientH;

    public SetupNativeWindow(SetupOptions options)
    {
        _initialOptions = options;
        _palette = SetupThemePalette.LoadCurrent();
        _completeMode = options.CompleteInstallation;
        _createShortcut = options.CreateShortcut;
        _startAfterInstall = options.StartAfterInstall;
        _acceptRisk = options.AcceptRisk;
        _appVersionText = ReadSetupVersion();
    }

    public int Run()
    {
        NativeMethods.InitCommonControlsEx(new INITCOMMONCONTROLSEX
        {
            dwSize = (uint)Marshal.SizeOf<INITCOMMONCONTROLSEX>(),
            dwICC = 0x00004000,
        });

        _brushEdit = NativeMethods.CreateSolidBrush(_palette.EditBgGdi);
        _logoImage = _gdip.LoadEmbeddedLogo();

        _wndProc = WindowProc;
        nint hInstance = NativeMethods.GetModuleHandle(null);
        nint hIcon = NativeMethods.LoadIcon(hInstance, new nint(32512));

        var wc = new WNDCLASSEXW
        {
            cbSize = (uint)Marshal.SizeOf<WNDCLASSEXW>(),
            lpfnWndProc = Marshal.GetFunctionPointerForDelegate(_wndProc),
            hInstance = hInstance,
            hIcon = hIcon,
            hIconSm = hIcon,
            hCursor = NativeMethods.LoadCursor(nint.Zero, 32512),
            hbrBackground = nint.Zero,
            lpszClassName = WindowClassName,
        };

        if (NativeMethods.RegisterClassEx(ref wc) == 0)
        {
            return 1;
        }

        uint sysDpi = NativeMethods.GetDpiForSystem();
        _scale = Math.Max(1.0, sysDpi / 96.0);
        int width = S(LogicalWidth);
        int height = S(LogicalHeight);

        NativeMethods.SystemParametersInfo(SpiGetWorkArea, 0, out RECT workArea, 0);
        int maxH = Math.Max(560, workArea.Bottom - workArea.Top - 24);
        if (height > maxH)
        {
            height = maxH;
        }

        int x = workArea.Left + Math.Max(0, (workArea.Right - workArea.Left - width) / 2);
        int y = workArea.Top + Math.Max(0, (workArea.Bottom - workArea.Top - height) / 2);

        _hwnd = NativeMethods.CreateWindowEx(
            0,
            WindowClassName,
            "Axiom Setup",
            WsOverlapped | WsCaption | WsSysMenu | WsMinimizeBox,
            x,
            y,
            width,
            height,
            nint.Zero,
            nint.Zero,
            hInstance,
            nint.Zero);

        if (_hwnd == nint.Zero)
        {
            return 1;
        }

        if (hIcon != nint.Zero)
        {
            _ = NativeMethods.SendMessage(_hwnd, WmSetIcon, 1, hIcon);
            _ = NativeMethods.SendMessage(_hwnd, WmSetIcon, 0, hIcon);
        }

        ApplyDwmStyling();
        _ = NativeMethods.ShowWindow(_hwnd, 5 /* SW_SHOW */);
        _ = NativeMethods.UpdateWindow(_hwnd);

        MSG msg = default;
        while (NativeMethods.GetMessage(out msg, nint.Zero, 0, 0) > 0)
        {
            _ = NativeMethods.TranslateMessage(in msg);
            _ = NativeMethods.DispatchMessage(in msg);
        }

        return (int)msg.wParam;
    }

    public void Dispose()
    {
        ReleaseBackBuffer();
        SetupGdiPlus.DisposeFont(ref _gpTitle);
        SetupGdiPlus.DisposeFont(ref _gpSubtitle);
        SetupGdiPlus.DisposeFont(ref _gpSection);
        SetupGdiPlus.DisposeFont(ref _gpCardTitle);
        SetupGdiPlus.DisposeFont(ref _gpBodyBold);
        SetupGdiPlus.DisposeFont(ref _gpBody);
        SetupGdiPlus.DisposeFont(ref _gpSmall);
        SetupGdiPlus.DisposeFont(ref _gpBadge);
        SetupGdiPlus.DisposeFont(ref _gpMono);
        SetupGdiPlus.DisposeFormat(ref _fmtNear);
        SetupGdiPlus.DisposeFormat(ref _fmtNearCenter);
        SetupGdiPlus.DisposeFormat(ref _fmtCenter);
        SetupGdiPlus.DisposeFormat(ref _fmtFarCenter);
        SetupGdiPlus.DisposeImage(ref _logoImage);
        DeleteGdiObject(ref _brushEdit);
        DeleteGdiObject(ref _editFont);
        _gdip.Dispose();
    }

    private void ApplyDwmStyling()
    {
        int dark = _palette.IsDark ? 1 : 0;
        _ = NativeMethods.DwmSetWindowAttribute(_hwnd, DwmwaUseImmersiveDarkMode, ref dark, sizeof(int));

        int corner = 2; // DWMWCP_ROUND
        _ = NativeMethods.DwmSetWindowAttribute(_hwnd, DwmwaWindowCornerPreference, ref corner, sizeof(int));

        int captionColor = _palette.DwmCaptionGdi;
        _ = NativeMethods.DwmSetWindowAttribute(_hwnd, DwmwaCaptionColor, ref captionColor, sizeof(int));

        int borderColor = _palette.DwmBorderGdi;
        _ = NativeMethods.DwmSetWindowAttribute(_hwnd, DwmwaBorderColor, ref borderColor, sizeof(int));
    }

    private nint WindowProc(nint hwnd, uint msg, nint wParam, nint lParam)
    {
        switch (msg)
        {
            case WmCreate:
                _hwnd = hwnd;
                CreateResources();
                CreateChildEditors();
                RefreshExistingState();
                SyncChildVisibility();
                return nint.Zero;

            case WmSize:
                UpdateClientSize();
                PositionChildEditors();
                return nint.Zero;

            case WmEraseBkgnd:
                return 1;

            case WmPaint:
                RenderPaint(hwnd);
                return nint.Zero;

            case WmPrintClient:
                RenderToDc(wParam);
                return nint.Zero;

            case WmCtlColorEdit:
            case WmCtlColorStatic:
                if (lParam == _hLogEdit || lParam == _hScopeEdit)
                {
                    _ = NativeMethods.SetTextColor(wParam, _palette.EditTextGdi);
                    _ = NativeMethods.SetBkColor(wParam, _palette.EditBgGdi);
                    return _brushEdit;
                }
                return NativeMethods.DefWindowProc(hwnd, msg, wParam, lParam);

            case WmMouseMove:
                HandleMouseMove(lParam);
                return nint.Zero;

            case WmMouseLeave:
                _trackingMouse = false;
                if (_hoverId != HitId.None || _pressedId != HitId.None)
                {
                    _hoverId = HitId.None;
                    _pressedId = HitId.None;
                    InvalidateWindow();
                }
                return nint.Zero;

            case WmLButtonDown:
                HandleLButtonDown(lParam);
                return nint.Zero;

            case WmLButtonUp:
                HandleLButtonUp(lParam);
                return nint.Zero;

            case WmSetCursor:
                if ((int)(lParam & 0xFFFF) == 1 && _hoverId != HitId.None)
                {
                    _ = NativeMethods.SetCursor(NativeMethods.LoadCursor(nint.Zero, 32649 /* IDC_HAND */));
                    return 1;
                }
                return NativeMethods.DefWindowProc(hwnd, msg, wParam, lParam);

            case WmKeyDown:
                HandleKeyDown((int)wParam);
                return nint.Zero;

            case WmTimer:
                if ((nuint)wParam == AnimTimerId && _installing)
                {
                    _animPhase = (_animPhase + 7) % 1000;
                    InvalidateWindow();
                }
                return nint.Zero;

            case WmAppLog:
                DrainLogQueue();
                return nint.Zero;

            case WmAppDone:
                FinishOperation();
                return nint.Zero;

            case WmClose:
                if (_installing)
                {
                    return nint.Zero;
                }
                _ = NativeMethods.DestroyWindow(hwnd);
                return nint.Zero;

            case WmDestroy:
                _ = NativeMethods.KillTimer(hwnd, AnimTimerId);
                NativeMethods.PostQuitMessage(0);
                return nint.Zero;

            default:
                return NativeMethods.DefWindowProc(hwnd, msg, wParam, lParam);
        }
    }

    private void CreateResources()
    {
        UpdateClientSize();
        _editFont = NativeMethods.CreateFont(
            -S(11), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, "Consolas");

        _gpTitle = SetupGdiPlus.CreateFont("Segoe UI", S(20), SetupGdiPlus.FontStyleBold);
        _gpSubtitle = SetupGdiPlus.CreateFont("Segoe UI", S(12.5f));
        _gpSection = SetupGdiPlus.CreateFont("Segoe UI", S(10.5f), SetupGdiPlus.FontStyleBold);
        _gpCardTitle = SetupGdiPlus.CreateFont("Segoe UI", S(15), SetupGdiPlus.FontStyleBold);
        _gpBodyBold = SetupGdiPlus.CreateFont("Segoe UI", S(12.5f), SetupGdiPlus.FontStyleBold);
        _gpBody = SetupGdiPlus.CreateFont("Segoe UI", S(12.5f));
        _gpSmall = SetupGdiPlus.CreateFont("Segoe UI", S(11));
        _gpBadge = SetupGdiPlus.CreateFont("Segoe UI", S(9.5f), SetupGdiPlus.FontStyleBold);
        _gpMono = SetupGdiPlus.CreateFont("Consolas", S(11.5f));

        _fmtNear = SetupGdiPlus.CreateStringFormat(SetupGdiPlus.AlignNear, SetupGdiPlus.AlignNear);
        _fmtNearCenter = SetupGdiPlus.CreateStringFormat(SetupGdiPlus.AlignNear, SetupGdiPlus.AlignCenter, noWrap: true);
        _fmtCenter = SetupGdiPlus.CreateStringFormat(SetupGdiPlus.AlignCenter, SetupGdiPlus.AlignCenter, noWrap: true);
        _fmtFarCenter = SetupGdiPlus.CreateStringFormat(SetupGdiPlus.AlignFar, SetupGdiPlus.AlignCenter, noWrap: true);
    }

    private void CreateChildEditors()
    {
        _hScopeEdit = NativeMethods.CreateWindowEx(
            0, "EDIT", WriteScopeText,
            WsChild | WsVScroll | EsMultiline | EsReadOnly | EsAutoVScroll,
            0, 0, 100, 100, _hwnd, IdScopeEdit, nint.Zero, nint.Zero);
        _ = NativeMethods.SendMessage(_hScopeEdit, WmSetFont, _editFont, 1);
        TryApplyDarkScrollbar(_hScopeEdit);

        _hLogEdit = NativeMethods.CreateWindowEx(
            0, "EDIT", "",
            WsChild | WsVScroll | EsMultiline | EsReadOnly | EsAutoVScroll,
            0, 0, 100, 100, _hwnd, IdLogEdit, nint.Zero, nint.Zero);
        _ = NativeMethods.SendMessage(_hLogEdit, WmSetFont, _editFont, 1);
        TryApplyDarkScrollbar(_hLogEdit);

        PositionChildEditors();
    }

    private void UpdateClientSize()
    {
        _ = NativeMethods.GetClientRect(_hwnd, out RECT client);
        _clientW = Math.Max(S(640), client.Right - client.Left);
        _clientH = Math.Max(S(500), client.Bottom - client.Top);
    }

    private void PositionChildEditors()
    {
        int pad = S(28);
        int innerW = _clientW - (pad * 2);
        int footerTop = _clientH - S(72);

        if (_hScopeEdit != nint.Zero)
        {
            int sx = pad + S(14);
            int sy = S(162);
            int sw = innerW - S(28);
            int sh = Math.Max(S(140), footerTop - sy - S(22));
            _ = NativeMethods.MoveWindow(_hScopeEdit, sx, sy, sw, sh, true);
        }

        if (_hLogEdit != nint.Zero)
        {
            int lx = pad + S(14);
            int ly = S(254);
            int lw = innerW - S(28);
            int lh = Math.Max(S(140), footerTop - ly - S(22));
            _ = NativeMethods.MoveWindow(_hLogEdit, lx, ly, lw, lh, true);
        }
    }

    private void SyncChildVisibility()
    {
        _ = NativeMethods.ShowWindow(_hScopeEdit, _mode == ViewMode.Scope ? 5 /* SW_SHOW */ : 0 /* SW_HIDE */);
        _ = NativeMethods.ShowWindow(_hLogEdit, _mode == ViewMode.Progress ? 5 : 0);
    }

    private void RefreshExistingState()
    {
        _existing = SetupInstaller.DetectExistingInstallation(_initialOptions.InstallDir);
    }

    private void RenderPaint(nint hwnd)
    {
        nint hdc = NativeMethods.BeginPaint(hwnd, out PAINTSTRUCT ps);
        try
        {
            RenderToDc(hdc);
        }
        finally
        {
            _ = NativeMethods.EndPaint(hwnd, ref ps);
        }
    }

    private void RenderToDc(nint hdc)
    {
        EnsureBackBuffer(_clientW, _clientH);
        nint g = SetupGdiPlus.CreateGraphics(_backDc);
        try
        {
            _hitZones.Clear();
            DrawScene(g);
        }
        finally
        {
            SetupGdiPlus.DisposeGraphics(g);
        }

        _ = NativeMethods.BitBlt(hdc, 0, 0, _clientW, _clientH, _backDc, 0, 0, 0x00CC0020 /* SRCCOPY */);
    }

    private void EnsureBackBuffer(int width, int height)
    {
        if (_backDc != nint.Zero && _backWidth == width && _backHeight == height)
        {
            return;
        }

        ReleaseBackBuffer();
        nint screenDc = NativeMethods.GetDC(_hwnd);
        try
        {
            _backDc = NativeMethods.CreateCompatibleDC(screenDc);
            _backBitmap = NativeMethods.CreateCompatibleBitmap(screenDc, width, height);
            _backOldBitmap = NativeMethods.SelectObject(_backDc, _backBitmap);
        }
        finally
        {
            _ = NativeMethods.ReleaseDC(_hwnd, screenDc);
        }

        _backWidth = width;
        _backHeight = height;
    }

    private void ReleaseBackBuffer()
    {
        if (_backDc != nint.Zero)
        {
            if (_backOldBitmap != nint.Zero)
            {
                _ = NativeMethods.SelectObject(_backDc, _backOldBitmap);
                _backOldBitmap = nint.Zero;
            }
            if (_backBitmap != nint.Zero)
            {
                _ = NativeMethods.DeleteObject(_backBitmap);
                _backBitmap = nint.Zero;
            }
            _ = NativeMethods.DeleteDC(_backDc);
            _backDc = nint.Zero;
        }

        _backWidth = 0;
        _backHeight = 0;
    }

    private void DrawScene(nint g)
    {
        int w = _clientW;
        int h = _clientH;
        int pad = S(28);
        int innerW = w - (pad * 2);
        int footerTop = h - S(72);

        // Background canvas matching active Axiom theme
        SetupGdiPlus.FillRectGradient(g, 0, 0, w, h, _palette.BgTop, _palette.BgBottom);

        // Hero top header strip
        int headerH = S(96);
        SetupGdiPlus.FillRectGradient(g, 0, 0, w, headerH, _palette.HeaderTop, _palette.HeaderBottom);
        SetupGdiPlus.DrawLine(g, 0, headerH, w, headerH, _palette.Border, 1f);

        // Logo shield (always backed on dark titanium tile on Light themes like AgentsView LogoBackground)
        int logoSize = S(50);
        int logoX = pad;
        int logoY = (headerH - logoSize) / 2;
        uint logoBadgeBg = _palette.IsDark ? _palette.Surface : SetupGdiPlus.Rgb(28, 35, 48);
        uint logoBadgeBorder = _palette.IsDark ? _palette.BorderStrong : SetupGdiPlus.Rgb(58, 70, 89);
        SetupGdiPlus.FillRoundedRect(
            g, logoX - S(4), logoY - S(4), logoSize + S(8), logoSize + S(8), S(8), logoBadgeBg);
        SetupGdiPlus.DrawRoundedRect(
            g, logoX - S(4), logoY - S(4), logoSize + S(8), logoSize + S(8), S(8), logoBadgeBorder, 1f);
        SetupGdiPlus.DrawImage(g, _logoImage, logoX, logoY, logoSize, logoSize);

        // Title + Version pill
        int titleX = logoX + logoSize + S(18);
        int titleY = S(20);
        SetupGdiPlus.DrawText(g, "Axiom Setup", _gpTitle, titleX, titleY, S(180), S(28), _palette.TextPrimary, _fmtNearCenter);

        string pillText = _existing.Exists ? $"UPDATE · v{_appVersionText}" : $"INSTALL · v{_appVersionText}";
        int pillX = titleX + S(138);
        int pillW = _existing.Exists ? S(132) : S(126);
        DrawPillBadge(g, pillX, titleY + S(3), pillW, S(22), pillText, _palette.PillFill, _palette.PillBorder, _palette.PillText);

        // Header subtitle
        string subtitle = _mode == ViewMode.Progress
            ? (_installing
                ? "Please wait while Axiom Setup completes the requested steps."
                : _installResult is { Success: true }
                    ? "Operation completed."
                    : "Review the status and installation log below.")
            : _existing.Exists
                ? $"Existing Axiom v{_existing.Version ?? "installed"} found. Updating in place preserves your settings and data."
                : "Local-first Windows firewall, Privacy Shield DNS, and AI agent protection.";
        SetupGdiPlus.DrawText(g, subtitle, _gpSubtitle, titleX, titleY + S(32), w - titleX - pad, S(22), _palette.TextSecondary, _fmtNearCenter);

        // Body content per mode
        switch (_mode)
        {
            case ViewMode.Configure:
                DrawConfigureBody(g, pad, innerW, footerTop);
                break;

            case ViewMode.Scope:
                DrawScopeBody(g, pad, innerW, footerTop);
                break;

            case ViewMode.Progress:
                DrawProgressBody(g, pad, innerW, footerTop);
                break;
        }

        // Footer bar
        DrawFooter(g, pad, innerW, footerTop, h);
    }

    private void DrawConfigureBody(nint g, int pad, int innerW, int footerTop)
    {
        int y = S(112);
        SetupGdiPlus.DrawText(g, "CHOOSE INSTALLATION MODE", _gpSection, pad, y, innerW, S(16), _palette.TextMuted, _fmtNearCenter);
        y += S(22);

        // Side-by-side cards (responsive height, unified CornerRadius = 6)
        int gap = S(16);
        int cardW = (innerW - gap) / 2;
        int optH = S(74);
        int riskH = S(100);
        int cardH = Math.Clamp(footerTop - y - optH - riskH - S(38), S(196), S(234));

        var leftBounds = new RECT { Left = pad, Top = y, Right = pad + cardW, Bottom = y + cardH };
        var rightBounds = new RECT { Left = pad + cardW + gap, Top = y, Right = pad + innerW, Bottom = y + cardH };

        DrawModeCard(
            g, leftBounds, HitId.CardComplete,
            selected: _completeMode,
            title: "Complete Protection",
            subtitle: "Full firewall, DNS privacy & AI agent shield",
            badgeText: "RECOMMENDED",
            badgeFill: _palette.PillFill,
            badgeBorder: _completeMode ? _palette.Accent : _palette.BorderStrong,
            badgeFg: _palette.PillText,
            bullets:
            [
                "Axiom Shield — service + ask policy (1 UAC)",
                "Privacy Shield — DNS blocker (53 + DoH 443)",
                "Blackbox + DKG — node, 11 hooks, shared indicators",
                "Background — autostart & tray protection",
            ],
            footerMeta: "10–20 min full setup",
            showWriteScopeLink: true);

        DrawModeCard(
            g, rightBounds, HitId.CardPartial,
            selected: !_completeMode,
            title: "Core / Partial Build",
            subtitle: "Lightweight desktop monitor & history only",
            badgeText: "NO ADMIN",
            badgeFill: _palette.BtnBg,
            badgeBorder: _palette.Border,
            badgeFg: _palette.TextSecondary,
            bullets:
            [
                "Live Monitor — real-time sockets & app rates",
                "Local History — per-user timeline & events",
                "Zero Elevation — no admin UAC prompt",
                "Modular — enable Shield, DNS or AI anytime",
            ],
            footerMeta: "< 10 sec setup",
            showWriteScopeLink: false);

        y += cardH + S(14);

        // Compact Path & Toggles strip (CornerRadius = 6)
        SetupGdiPlus.FillRoundedRect(g, pad, y, innerW, optH, S(6), _palette.Surface);
        SetupGdiPlus.DrawRoundedRect(g, pad, y, innerW, optH, S(6), _palette.Border, 1f);

        int ox = pad + S(16);
        SetupGdiPlus.DrawText(g, "Install path:", _gpSmall, ox, y + S(11), S(82), S(18), _palette.TextMuted, _fmtNearCenter);
        SetupGdiPlus.DrawText(g, _initialOptions.InstallDir, _gpMono, ox + S(82), y + S(11), innerW - S(110), S(18), _palette.TextPrimary, _fmtNearCenter);

        SetupGdiPlus.DrawLine(g, ox, y + S(36), pad + innerW - S(16), y + S(36), _palette.Border, 1f);

        int halfW = (innerW - S(32)) / 2;
        DrawCheckRow(g, HitId.ShortcutCheck, ox, y + S(42), halfW - S(8), S(24), _createShortcut, "Create Start Menu shortcut");
        DrawCheckRow(g, HitId.LaunchCheck, ox + halfW, y + S(42), halfW, S(24), _startAfterInstall, "Launch Axiom automatically after finish");

        y += optH + S(12);

        // Risk acceptance card (CornerRadius = 6)
        riskH = Math.Max(S(88), footerTop - y - S(12));
        uint riskBg = _acceptRisk ? _palette.SuccessBg : _palette.WarnBg;
        uint riskBorder = _acceptRisk ? _palette.SuccessBorder : _palette.WarnBorder;
        uint riskBar = _acceptRisk ? _palette.SuccessAccent : _palette.WarnAccent;
        uint riskTitleColor = _acceptRisk ? _palette.SuccessText : _palette.WarnText;

        SetupGdiPlus.FillRoundedRect(g, pad, y, innerW, riskH, S(6), riskBg);
        SetupGdiPlus.DrawRoundedRect(g, pad, y, innerW, riskH, S(6), riskBorder, 1f);
        SetupGdiPlus.FillRoundedRect(g, pad + S(4), y + S(8), S(3), riskH - S(16), S(1.5f), riskBar);

        int rx = pad + S(18);
        int rw = innerW - S(32);
        SetupGdiPlus.DrawText(
            g,
            "Development build notice — use at your own risk",
            _gpBodyBold, rx, y + S(9), rw, S(18), riskTitleColor, _fmtNearCenter);

        SetupGdiPlus.DrawText(
            g,
            "Firewall, DNS and agent hook changes can affect network connectivity or block files/tools. Rely on backups and test in a VM where possible.",
            _gpSmall, rx, y + S(29), rw, S(30), _palette.TextSecondary, _fmtNear);

        DrawCheckRow(
            g, HitId.AgreeRow, rx, y + riskH - S(30), rw, S(24),
            _acceptRisk,
            "I understand these risks and accept using Axiom at my own risk.");
    }

    private void DrawModeCard(
        nint g,
        RECT bounds,
        HitId hitId,
        bool selected,
        string title,
        string subtitle,
        string badgeText,
        uint badgeFill,
        uint badgeBorder,
        uint badgeFg,
        string[] bullets,
        string footerMeta,
        bool showWriteScopeLink)
    {
        float x = bounds.Left;
        float y = bounds.Top;
        float w = bounds.Right - bounds.Left;
        float h = bounds.Bottom - bounds.Top;
        bool hovered = _hoverId == hitId;

        if (selected)
        {
            SetupGdiPlus.FillRoundedRectGradient(g, x, y, w, h, S(6), _palette.CardActiveTop, _palette.CardActiveBottom);
            SetupGdiPlus.DrawRoundedRect(g, x, y, w, h, S(6), _palette.Accent, 1.5f);
            SetupGdiPlus.DrawLine(g, x + S(10), y + 1, x + w - S(10), y + 1, _palette.CardActiveHighlight, 1f);
        }
        else
        {
            SetupGdiPlus.FillRoundedRect(g, x, y, w, h, S(6), hovered ? _palette.SurfaceHover : _palette.Surface);
            SetupGdiPlus.DrawRoundedRect(g, x, y, w, h, S(6), hovered ? _palette.BorderStrong : _palette.Border, 1f);
        }

        // Radio indicator ring using Axiom.Accent
        float radioX = x + S(16);
        float radioY = y + S(18);
        float radioD = S(18);
        if (selected)
        {
            SetupGdiPlus.DrawEllipse(g, radioX, radioY, radioD, radioD, _palette.Accent, 1.8f);
            float dot = S(8);
            SetupGdiPlus.FillEllipse(g, radioX + (radioD - dot) / 2f, radioY + (radioD - dot) / 2f, dot, dot, _palette.Accent);
        }
        else
        {
            SetupGdiPlus.DrawEllipse(g, radioX, radioY, radioD, radioD, _palette.TextMuted, 1.4f);
        }

        // Badge top-right
        int badgeW = showWriteScopeLink ? S(98) : S(72);
        DrawPillBadge(g, (int)(x + w - badgeW - S(14)), (int)(y + S(16)), badgeW, S(20), badgeText, badgeFill, badgeBorder, badgeFg);

        // Title & Subtitle
        float textX = radioX + radioD + S(10);
        float titleMaxW = (x + w - badgeW - S(20)) - textX;
        SetupGdiPlus.DrawText(g, title, _gpCardTitle, textX, y + S(14), titleMaxW, S(22), _palette.TextPrimary, _fmtNearCenter);
        SetupGdiPlus.DrawText(g, subtitle, _gpSmall, x + S(16), y + S(44), w - S(32), S(18), _palette.TextSecondary, _fmtNearCenter);

        // Divider
        SetupGdiPlus.DrawLine(g, x + S(16), y + S(68), x + w - S(16), y + S(68), _palette.Border, 1f);

        // Bullets
        float by = y + S(78);
        uint checkColor = selected ? _palette.Accent : _palette.TextMuted;
        uint bulletTextColor = selected ? _palette.TextPrimary : _palette.TextSecondary;
        int bulletStep = h < S(218) ? S(23) : S(26);
        foreach (string line in bullets)
        {
            SetupGdiPlus.DrawCheckmark(g, x + S(16), by + S(2), S(13), checkColor, 1.7f);
            SetupGdiPlus.DrawText(g, line, _gpSmall, x + S(35), by, w - S(48), S(20), bulletTextColor, _fmtNearCenter);
            by += bulletStep;
        }

        // Card bottom footer meta
        SetupGdiPlus.DrawLine(g, x + S(16), y + h - S(38), x + w - S(16), y + h - S(38), _palette.Border, 1f);
        SetupGdiPlus.DrawText(g, footerMeta, _gpSmall, x + S(16), y + h - S(31), S(140), S(22), _palette.TextMuted, _fmtNearCenter);

        _hitZones.Add(new HitZone(hitId, bounds));

        if (showWriteScopeLink)
        {
            int linkW = S(132);
            int linkH = S(22);
            var linkRect = new RECT
            {
                Left = (int)(x + w - linkW - S(14)),
                Top = (int)(y + h - S(31)),
                Right = (int)(x + w - S(14)),
                Bottom = (int)(y + h - S(9)),
            };
            bool linkHover = _hoverId == HitId.WriteScopeLink;
            SetupGdiPlus.DrawText(
                g,
                "View write scope ▸",
                _gpSmall,
                linkRect.Left,
                linkRect.Top,
                linkW,
                linkH,
                linkHover ? _palette.AccentHover : _palette.Accent,
                _fmtFarCenter);
            _hitZones.Add(new HitZone(HitId.WriteScopeLink, linkRect));
        }
    }

    private void DrawCheckRow(
        nint g, HitId id, int x, int y, int w, int h, bool isChecked, string label)
    {
        bool hovered = _hoverId == id;
        int box = S(16);
        int boxY = y + ((h - box) / 2);

        if (isChecked)
        {
            SetupGdiPlus.FillRoundedRect(g, x, boxY, box, box, S(4), _palette.Accent);
            SetupGdiPlus.DrawRoundedRect(g, x, boxY, box, box, S(4), _palette.AccentHover, 1f);
            SetupGdiPlus.DrawCheckmark(g, x + S(2), boxY + S(2), box - S(4), _palette.AccentContrast, 1.9f);
        }
        else
        {
            SetupGdiPlus.FillRoundedRect(g, x, boxY, box, box, S(4), _palette.FooterBg);
            SetupGdiPlus.DrawRoundedRect(g, x, boxY, box, box, S(4), hovered ? _palette.Accent : _palette.BorderStrong, 1.3f);
        }

        SetupGdiPlus.DrawText(
            g, label, _gpBody, x + box + S(9), y, w - box - S(12), h,
            hovered ? _palette.TextPrimary : _palette.TextSecondary,
            _fmtNearCenter);

        _hitZones.Add(new HitZone(id, new RECT { Left = x, Top = y, Right = x + w, Bottom = y + h }));
    }

    private void DrawScopeBody(nint g, int pad, int innerW, int footerTop)
    {
        int y = S(114);
        SetupGdiPlus.DrawText(
            g,
            "Write scope — files, services & registry entries for Complete Protection",
            _gpBodyBold, pad, y, innerW - S(150), S(24), _palette.TextPrimary, _fmtNearCenter);

        var backRect = new RECT { Left = pad + innerW - S(136), Top = y - S(2), Right = pad + innerW, Bottom = y + S(28) };
        DrawButton(g, HitId.BackFromScopeBtn, backRect, "← Back to setup", primary: false, danger: false, enabled: true);

        y += S(38);
        int boxH = Math.Max(S(160), footerTop - y - S(14));
        uint editBgArgb = _palette.IsDark ? _palette.FooterBg : _palette.Surface;
        SetupGdiPlus.FillRoundedRect(g, pad, y, innerW, boxH, S(6), editBgArgb);
        SetupGdiPlus.DrawRoundedRect(g, pad, y, innerW, boxH, S(6), _palette.Border, 1f);
    }

    private void DrawProgressBody(nint g, int pad, int innerW, int footerTop)
    {
        int y = S(114);
        int statusH = S(102);

        bool failed = !_installing && _installResult is { Success: false };
        bool succeeded = !_installing && _installResult is { Success: true };

        uint cardBorder = failed ? _palette.ErrorBorder : succeeded ? _palette.SuccessBorder : _palette.Border;
        SetupGdiPlus.FillRoundedRect(g, pad, y, innerW, statusH, S(6), _palette.Surface);
        SetupGdiPlus.DrawRoundedRect(g, pad, y, innerW, statusH, S(6), cardBorder, 1f);

        int cx = pad + S(18);
        int cw = innerW - S(36);

        string opTitle = _lastOperationWasUninstall
            ? (_installing ? "Uninstalling Axiom..." : failed ? "Uninstall failed" : "Uninstall completed")
            : _lastOperationWasRepair
                ? (_installing ? "Repairing Axiom..." : failed ? "Repair failed" : "Repair completed")
                : _existing.Exists
                    ? (_installing ? "Updating Axiom..." : failed ? "Update failed" : "Axiom updated")
                    : (_installing ? "Installing Axiom..." : failed ? "Installation failed" : "Axiom installed");

        uint titleColor = failed ? _palette.ErrorText : succeeded ? _palette.SuccessText : _palette.TextPrimary;
        SetupGdiPlus.DrawText(g, opTitle, _gpCardTitle, cx, y + S(14), cw - S(90), S(24), titleColor, _fmtNearCenter);

        var elapsed = _opClock.Elapsed;
        string clockText = string.Create(CultureInfo.InvariantCulture, $"{elapsed:mm\\:ss}");
        SetupGdiPlus.DrawText(g, clockText, _gpMono, pad + innerW - S(86), y + S(16), S(68), S(20), _palette.TextSecondary, _fmtFarCenter);

        string stepDisplay = failed
            ? (_installResult?.Message ?? "Installation failed.")
            : _currentStepText;
        SetupGdiPlus.DrawText(
            g, stepDisplay, _gpSmall, cx, y + S(42), cw, S(20),
            failed ? _palette.ErrorText : _palette.TextSecondary,
            _fmtNearCenter);

        // Progress bar track
        int barY = y + S(72);
        int barH = S(10);
        SetupGdiPlus.FillRoundedRect(g, cx, barY, cw, barH, S(5), _palette.Border);

        if (failed)
        {
            SetupGdiPlus.FillRoundedRect(g, cx, barY, cw, barH, S(5), _palette.ErrorAccent);
        }
        else if (succeeded)
        {
            SetupGdiPlus.FillRoundedRectGradient(
                g, cx, barY, cw, barH, S(5), _palette.SuccessAccent, _palette.SuccessText, SetupGdiPlus.LinearGradientHorizontal);
        }
        else
        {
            // Smooth indeterminate silver-titanium sweep matching theme accent
            float segW = Math.Max(S(110), cw * 0.34f);
            float travel = cw + segW;
            float t = _animPhase / 1000f;
            float segX = cx - segW + (t * travel);
            SetupGdiPlus.SetClip(g, cx, barY, cw, barH);
            SetupGdiPlus.FillRoundedRectGradient(
                g, segX, barY, segW, barH, S(5), _palette.AccentPressed, _palette.AccentHover, SetupGdiPlus.LinearGradientHorizontal);
            SetupGdiPlus.ResetClip(g);
        }

        // Log area frame
        int logTop = y + statusH + S(12);
        int logBoxH = Math.Max(S(160), footerTop - logTop - S(14));
        uint logBg = _palette.IsDark ? _palette.FooterBg : _palette.Surface;
        SetupGdiPlus.FillRoundedRect(g, pad, logTop, innerW, logBoxH, S(6), logBg);
        SetupGdiPlus.DrawRoundedRect(g, pad, logTop, innerW, logBoxH, S(6), _palette.Border, 1f);
        SetupGdiPlus.DrawText(g, "INSTALLATION LOG", _gpBadge, pad + S(14), logTop + S(7), S(160), S(14), _palette.TextMuted, _fmtNearCenter);
    }

    private void DrawFooter(nint g, int pad, int innerW, int footerTop, int h)
    {
        SetupGdiPlus.FillRect(g, 0, footerTop, _clientW, h - footerTop, _palette.FooterBg);
        SetupGdiPlus.DrawLine(g, 0, footerTop, _clientW, footerTop, _palette.Border, 1f);

        int btnH = S(36);
        int btnY = footerTop + ((h - footerTop - btnH) / 2);

        if (_mode == ViewMode.Progress)
        {
            if (_installing)
            {
                SetupGdiPlus.DrawText(
                    g, "Do not turn off your computer while Axiom files are being written.",
                    _gpSmall, pad, btnY, innerW - S(130), btnH, _palette.TextMuted, _fmtNearCenter);

                var cancelRect = new RECT { Left = pad + innerW - S(110), Top = btnY, Right = pad + innerW, Bottom = btnY + btnH };
                DrawButton(g, HitId.CloseBtn, cancelRect, "Cancel", primary: false, danger: false, enabled: false);
                return;
            }

            if (_installResult is { Success: false })
            {
                var backRect = new RECT { Left = pad, Top = btnY, Right = pad + S(134), Bottom = btnY + btnH };
                DrawButton(g, HitId.BackAfterErrorBtn, backRect, "← Back to setup", primary: false, danger: false, enabled: true);
            }

            var closeRect = new RECT { Left = pad + innerW - S(112), Top = btnY, Right = pad + innerW, Bottom = btnY + btnH };
            DrawButton(g, HitId.CloseBtn, closeRect, "Close", primary: true, danger: false, enabled: true);
            return;
        }

        // Left footer controls on Configure / Scope modes
        if (_existing.Exists)
        {
            int bx = pad;
            if (_existing.DesktopPath is not null)
            {
                var openRect = new RECT { Left = bx, Top = btnY, Right = bx + S(104), Bottom = btnY + btnH };
                DrawButton(g, HitId.OpenAxiomBtn, openRect, "Open Axiom", primary: false, danger: false, enabled: true);
                bx += S(112);
            }

            var repairRect = new RECT { Left = bx, Top = btnY, Right = bx + S(84), Bottom = btnY + btnH };
            DrawButton(g, HitId.RepairBtn, repairRect, "Repair", primary: false, danger: false, enabled: true);
            bx += S(92);

            var uninstallRect = new RECT { Left = bx, Top = btnY, Right = bx + S(92), Bottom = btnY + btnH };
            DrawButton(g, HitId.UninstallBtn, uninstallRect, "Uninstall", primary: false, danger: true, enabled: true);
        }
        else if (_mode == ViewMode.Configure)
        {
            var scopeBtnRect = new RECT { Left = pad, Top = btnY, Right = pad + S(132), Bottom = btnY + btnH };
            DrawButton(g, HitId.ViewScopeBtn, scopeBtnRect, "System paths", primary: false, danger: false, enabled: true);
        }

        // Right footer CTAs
        int cancelW = S(100);
        int installW = S(156);
        var rightCancelRect = new RECT { Left = pad + innerW - cancelW, Top = btnY, Right = pad + innerW, Bottom = btnY + btnH };
        var rightInstallRect = new RECT
        {
            Left = rightCancelRect.Left - S(10) - installW,
            Top = btnY,
            Right = rightCancelRect.Left - S(10),
            Bottom = btnY + btnH,
        };

        DrawButton(g, HitId.CloseBtn, rightCancelRect, "Cancel", primary: false, danger: false, enabled: true);

        string installLabel = _existing.Exists ? "Update Axiom" : "Install Axiom";
        DrawButton(g, HitId.InstallBtn, rightInstallRect, installLabel, primary: true, danger: false, enabled: _acceptRisk);
    }

    private void DrawPillBadge(
        nint g, int x, int y, int w, int h, string text, uint fill, uint border, uint fg)
    {
        SetupGdiPlus.FillRoundedRect(g, x, y, w, h, h / 2f, fill);
        SetupGdiPlus.DrawRoundedRect(g, x, y, w, h, h / 2f, border, 1f);
        SetupGdiPlus.DrawText(g, text, _gpBadge, x, y, w, h, fg, _fmtCenter);
    }

    private void DrawButton(
        nint g, HitId id, RECT bounds, string caption, bool primary, bool danger, bool enabled)
    {
        float x = bounds.Left;
        float y = bounds.Top;
        float w = bounds.Right - bounds.Left;
        float h = bounds.Bottom - bounds.Top;

        bool hovered = enabled && _hoverId == id;
        bool pressed = enabled && _pressedId == id;

        if (!enabled)
        {
            SetupGdiPlus.FillRoundedRect(g, x, y, w, h, S(6), _palette.BtnDisabledBg);
            SetupGdiPlus.DrawRoundedRect(g, x, y, w, h, S(6), _palette.Border, 1f);
            SetupGdiPlus.DrawText(g, caption, _gpBodyBold, x, y, w, h, _palette.TextMuted, _fmtCenter);
            return;
        }

        if (primary)
        {
            uint fill = pressed ? _palette.AccentPressed : hovered ? _palette.AccentHover : _palette.Accent;
            SetupGdiPlus.FillRoundedRect(g, x, y, w, h, S(6), fill);
            SetupGdiPlus.DrawRoundedRect(g, x, y, w, h, S(6), _palette.AccentHover, 1f);
            SetupGdiPlus.DrawText(g, caption, _gpBodyBold, x, y, w, h, _palette.AccentContrast, _fmtCenter);
        }
        else if (danger)
        {
            uint bg = pressed ? _palette.DangerBg : hovered ? _palette.DangerHover : _palette.BtnBg;
            uint border = hovered ? _palette.DangerBorder : _palette.DangerBg;
            uint fg = hovered ? _palette.DangerText : _palette.ErrorAccent;
            SetupGdiPlus.FillRoundedRect(g, x, y, w, h, S(6), bg);
            SetupGdiPlus.DrawRoundedRect(g, x, y, w, h, S(6), border, 1f);
            SetupGdiPlus.DrawText(g, caption, _gpBody, x, y, w, h, fg, _fmtCenter);
        }
        else
        {
            uint bg = pressed ? _palette.BtnPressed : hovered ? _palette.BtnHover : _palette.BtnBg;
            uint border = hovered ? _palette.BorderStrong : _palette.Border;
            SetupGdiPlus.FillRoundedRect(g, x, y, w, h, S(6), bg);
            SetupGdiPlus.DrawRoundedRect(g, x, y, w, h, S(6), border, 1f);
            SetupGdiPlus.DrawText(g, caption, _gpBody, x, y, w, h, _palette.TextPrimary, _fmtCenter);
        }

        _hitZones.Add(new HitZone(id, bounds));
    }

    private HitId HitTest(int x, int y)
    {
        for (int i = _hitZones.Count - 1; i >= 0; i--)
        {
            var zone = _hitZones[i];
            if (!zone.Enabled)
            {
                continue;
            }

            if (x >= zone.Bounds.Left && x < zone.Bounds.Right &&
                y >= zone.Bounds.Top && y < zone.Bounds.Bottom)
            {
                return zone.Id;
            }
        }

        return HitId.None;
    }

    private void HandleMouseMove(nint lParam)
    {
        if (!_trackingMouse)
        {
            var tme = new TRACKMOUSEEVENT
            {
                cbSize = (uint)Marshal.SizeOf<TRACKMOUSEEVENT>(),
                dwFlags = 0x00000002, // TME_LEAVE
                hwndTrack = _hwnd,
            };
            _ = NativeMethods.TrackMouseEvent(ref tme);
            _trackingMouse = true;
        }

        int x = unchecked((short)(lParam & 0xFFFF));
        int y = unchecked((short)((lParam >> 16) & 0xFFFF));
        var hit = HitTest(x, y);
        if (hit != _hoverId)
        {
            _hoverId = hit;
            InvalidateWindow();
        }
    }

    private void HandleLButtonDown(nint lParam)
    {
        int x = unchecked((short)(lParam & 0xFFFF));
        int y = unchecked((short)((lParam >> 16) & 0xFFFF));
        _pressedId = HitTest(x, y);
        if (_pressedId != HitId.None)
        {
            _ = NativeMethods.SetCapture(_hwnd);
            InvalidateWindow();
        }
    }

    private void HandleLButtonUp(nint lParam)
    {
        if (NativeMethods.GetCapture() == _hwnd)
        {
            _ = NativeMethods.ReleaseCapture();
        }

        int x = unchecked((short)(lParam & 0xFFFF));
        int y = unchecked((short)((lParam >> 16) & 0xFFFF));
        HitId released = HitTest(x, y);
        HitId wasPressed = _pressedId;
        _pressedId = HitId.None;
        InvalidateWindow();

        if (released != HitId.None && released == wasPressed)
        {
            InvokeHitAction(released);
        }
    }

    private void HandleKeyDown(int vk)
    {
        const int VkReturn = 0x0D;
        const int VkEscape = 0x1B;
        const int VkSpace = 0x20;
        const int VkLeft = 0x25;
        const int VkRight = 0x27;

        if (vk == VkEscape && !_installing)
        {
            if (_mode == ViewMode.Scope || (_mode == ViewMode.Progress && _installResult is { Success: false }))
            {
                _mode = ViewMode.Configure;
                SyncChildVisibility();
                InvalidateWindow();
                return;
            }
            _ = NativeMethods.PostMessage(_hwnd, WmClose, 0, 0);
            return;
        }

        if (_mode != ViewMode.Configure || _installing)
        {
            return;
        }

        if (vk == VkLeft)
        {
            _completeMode = true;
            InvalidateWindow();
        }
        else if (vk == VkRight)
        {
            _completeMode = false;
            InvalidateWindow();
        }
        else if (vk == VkSpace)
        {
            _acceptRisk = !_acceptRisk;
            InvalidateWindow();
        }
        else if (vk == VkReturn && _acceptRisk)
        {
            StartInstall(isRepair: false);
        }
    }

    private void InvokeHitAction(HitId id)
    {
        switch (id)
        {
            case HitId.CardComplete:
                _completeMode = true;
                InvalidateWindow();
                break;

            case HitId.CardPartial:
                _completeMode = false;
                InvalidateWindow();
                break;

            case HitId.WriteScopeLink:
            case HitId.ViewScopeBtn:
                _mode = ViewMode.Scope;
                SyncChildVisibility();
                InvalidateWindow();
                break;

            case HitId.BackFromScopeBtn:
            case HitId.BackAfterErrorBtn:
                _mode = ViewMode.Configure;
                SyncChildVisibility();
                InvalidateWindow();
                break;

            case HitId.ShortcutCheck:
                _createShortcut = !_createShortcut;
                InvalidateWindow();
                break;

            case HitId.LaunchCheck:
                _startAfterInstall = !_startAfterInstall;
                InvalidateWindow();
                break;

            case HitId.AgreeRow:
                _acceptRisk = !_acceptRisk;
                InvalidateWindow();
                break;

            case HitId.OpenAxiomBtn:
                LaunchInstalledAxiom();
                break;

            case HitId.RepairBtn:
                int repairAns = NativeMethods.MessageBox(
                    _hwnd,
                    $"Repair Axiom at {_initialOptions.InstallDir} using {(_completeMode ? "Complete Protection" : "Core / Partial Build")} mode?",
                    "Axiom Setup — Repair",
                    MbYesNo | MbIconQuestion);
                if (repairAns == IdYes)
                {
                    StartInstall(isRepair: true);
                }
                break;

            case HitId.UninstallBtn:
                int unAns = NativeMethods.MessageBox(
                    _hwnd,
                    $"Uninstall Axiom from {_initialOptions.InstallDir}?\n\nThis removes the installed application binaries, Start Menu shortcut, autostart entry and Windows service registration.",
                    "Axiom Setup — Uninstall",
                    MbYesNo | MbIconWarning);
                if (unAns == IdYes)
                {
                    if (!EnsureAxiomClosedForSetup("uninstall"))
                    {
                        return;
                    }

                    StartUninstall();
                }
                break;

            case HitId.InstallBtn:
                if (_acceptRisk)
                {
                    StartInstall(isRepair: false);
                }
                break;

            case HitId.CloseBtn:
                if (!_installing)
                {
                    _ = NativeMethods.PostMessage(_hwnd, WmClose, 0, 0);
                }
                break;
        }
    }

    private bool EnsureAxiomClosedForSetup(string actionLabel, bool autoClose = false)
    {
        var running = Process.GetProcessesByName("Axiom.Desktop")
            .Concat(Process.GetProcessesByName("Netpetra.Desktop"))
            .ToArray();
        if (running.Length == 0)
        {
            return true;
        }

        try
        {
            if (!autoClose)
            {
                int ans = NativeMethods.MessageBox(
                    _hwnd,
                    $"Axiom is currently running.\n\nClose Axiom now so Setup can {actionLabel}?",
                    "Axiom Setup",
                    MbYesNo | MbIconQuestion);
                if (ans != IdYes)
                {
                    return false;
                }
            }

            foreach (var proc in running)
            {
                try
                {
                    if (!proc.HasExited)
                    {
                        _ = proc.CloseMainWindow();
                        if (!proc.WaitForExit(2000))
                        {
                            proc.Kill(entireProcessTree: true);
                            _ = proc.WaitForExit(2000);
                        }
                    }
                }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
                {
                }
            }

            Thread.Sleep(250);
            return true;
        }
        finally
        {
            foreach (var proc in running)
            {
                proc.Dispose();
            }
        }
    }

    private void StartInstall(bool isRepair)
    {
        if (_installing || (!isRepair && !_acceptRisk))
        {
            return;
        }

        var isUpdate = !isRepair && _existing.Exists;
        if (!EnsureAxiomClosedForSetup(
            isRepair ? "repair" : isUpdate ? "update" : "install",
            autoClose: true))
        {
            return;
        }

        _lastOperationWasUninstall = false;
        _lastOperationWasRepair = isRepair;
        _installResult = null;
        _currentStepText = _existing.Exists
            ? "Preparing in-place update..."
            : "Extracting installation payload...";

        BeginProgressMode();

        var options = _initialOptions with
        {
            CreateShortcut = _createShortcut,
            StartAfterInstall = !isRepair || _startAfterInstall,
            CompleteInstallation = _completeMode,
        };

        var progress = new NativeLogProgress(message =>
        {
            _logQueue.Enqueue(message);
            _ = NativeMethods.PostMessage(_hwnd, WmAppLog, 0, 0);
        });

        _ = Task.Run(async () =>
        {
            _installResult = await SetupInstaller
                .InstallAsync(options, progress, CancellationToken.None)
                .ConfigureAwait(false);
            _ = NativeMethods.PostMessage(_hwnd, WmAppDone, 0, 0);
        });
    }

    private void StartUninstall()
    {
        if (_installing)
        {
            return;
        }

        _lastOperationWasUninstall = true;
        _lastOperationWasRepair = false;
        _installResult = null;
        _currentStepText = "Stopping services and removing Axiom...";

        BeginProgressMode();

        var progress = new NativeLogProgress(message =>
        {
            _logQueue.Enqueue(message);
            _ = NativeMethods.PostMessage(_hwnd, WmAppLog, 0, 0);
        });

        _ = Task.Run(async () =>
        {
            _installResult = await SetupInstaller
                .UninstallAsync(_initialOptions, progress, CancellationToken.None)
                .ConfigureAwait(false);
            _ = NativeMethods.PostMessage(_hwnd, WmAppDone, 0, 0);
        });
    }

    private void BeginProgressMode()
    {
        _installing = true;
        _hoverId = HitId.None;
        _pressedId = HitId.None;
        _mode = ViewMode.Progress;
        SyncChildVisibility();
        _ = NativeMethods.SetWindowText(_hLogEdit, string.Empty);
        _opClock.Restart();
        _ = NativeMethods.SetTimer(_hwnd, AnimTimerId, 33, nint.Zero);
        InvalidateWindow();
    }

    private void DrainLogQueue()
    {
        if (!_logQueue.TryDequeue(out var first))
        {
            return;
        }

        var lines = new List<string> { first };
        while (_logQueue.TryDequeue(out var next))
        {
            lines.Add(next);
        }

        string latest = lines[^1];
        if (latest.StartsWith('[') && latest.IndexOf(']') is int bracket && bracket > 0 && bracket + 2 < latest.Length)
        {
            latest = latest[(bracket + 2)..];
        }
        _currentStepText = latest;

        string text = string.Join("\r\n", lines) + "\r\n";
        _ = NativeMethods.SendMessage(_hLogEdit, EmSetSel, -1, -1);
        _ = NativeMethods.SendMessageText(_hLogEdit, EmReplaceSel, 0, text);
        _ = NativeMethods.SendMessage(_hLogEdit, EmScrollCaret, 0, 0);
        InvalidateWindow();
    }

    private void FinishOperation()
    {
        DrainLogQueue();
        _installing = false;
        _opClock.Stop();
        _ = NativeMethods.KillTimer(_hwnd, AnimTimerId);

        var result = _installResult;
        RefreshExistingState();

        if (_lastOperationWasUninstall)
        {
            InvalidateWindow();
            if (result is { Success: true })
            {
                string body = string.IsNullOrWhiteSpace(result.Warning)
                    ? result.Message
                    : $"{result.Message}\n\n{result.Warning}";
                _ = NativeMethods.MessageBox(_hwnd, body, "Axiom Setup", MbOk | (string.IsNullOrWhiteSpace(result.Warning) ? MbIconInformation : MbIconWarning));
            }
            else
            {
                _ = NativeMethods.MessageBox(_hwnd, result?.Message ?? "Uninstall failed.", "Axiom Setup failed", MbOk | MbIconError);
            }
            return;
        }

        if (result is { Success: true })
        {
            _currentStepText = "Completed.";
            InvalidateWindow();

            // Fresh Install & Update/Upgrade: SetupInstaller launches Axiom when StartAfterInstall
            // is enabled; close the installer automatically so user transitions straight into Axiom.
            if (!_lastOperationWasRepair)
            {
                _ = NativeMethods.PostMessage(_hwnd, WmClose, 0, 0);
                return;
            }

            if (_startAfterInstall)
            {
                _ = NativeMethods.PostMessage(_hwnd, WmClose, 0, 0);
                return;
            }

            _ = NativeMethods.MessageBox(_hwnd, result.Message, "Axiom Setup", MbOk | MbIconInformation);
            return;
        }

        _currentStepText = result?.Message ?? "Operation failed.";
        InvalidateWindow();
    }

    private void LaunchInstalledAxiom()
    {
        string desktopTarget = Path.Combine(_initialOptions.InstallDir, "Axiom.Desktop.exe");
        if (!File.Exists(desktopTarget))
        {
            _ = NativeMethods.MessageBox(_hwnd, "Axiom.Desktop.exe was not found in the install directory.", "Axiom Setup", MbOk | MbIconError);
            return;
        }

        try
        {
            _ = Process.Start(new ProcessStartInfo(desktopTarget)
            {
                UseShellExecute = true,
                WorkingDirectory = _initialOptions.InstallDir,
            });
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            _ = NativeMethods.MessageBox(_hwnd, "Could not launch Axiom: " + exception.Message, "Axiom Setup", MbOk | MbIconError);
        }
    }

    private void InvalidateWindow()
    {
        if (_hwnd != nint.Zero)
        {
            _ = NativeMethods.InvalidateRect(_hwnd, nint.Zero, false);
        }
    }

    private static string ReadSetupVersion()
    {
        var attr = typeof(SetupNativeWindow).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(attr))
        {
            int plus = attr.IndexOf('+');
            return plus > 0 ? attr[..plus] : attr;
        }

        return typeof(SetupNativeWindow).Assembly.GetName().Version?.ToString(3) ?? "0.59.0";
    }

    private void TryApplyDarkScrollbar(nint hCtrl)
    {
        if (hCtrl == nint.Zero)
        {
            return;
        }

        try
        {
            _ = NativeMethods.SetWindowTheme(hCtrl, _palette.IsDark ? "DarkMode_Explorer" : "Explorer", null);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
        }
    }

    private int S(double logicalPx) => (int)Math.Round(logicalPx * _scale);

    private static int GdiRgb(int r, int g, int b) => r | (g << 8) | (b << 16);

    private static void DeleteGdiObject(ref nint handle)
    {
        if (handle != nint.Zero)
        {
            _ = NativeMethods.DeleteObject(handle);
            handle = nint.Zero;
        }
    }

    private sealed class NativeLogProgress(Action<string> callback) : IProgress<string>
    {
        public void Report(string value) => callback(value);
    }

    private const string WriteScopeText =
        "%USERPROFILE%\\.config\\opencode\\plugins\\axiom-blackbox.ts\r\n" +
        "%LOCALAPPDATA%\\Axiom\\modules\\blackbox\\agent-blackbox\\axiom-guard-bridge.py\r\n" +
        "%USERPROFILE%\\.codex\\hooks.json (axiom-codex-hook.py entry only)\r\n" +
        "%LOCALAPPDATA%\\Axiom\\modules\\blackbox\\agent-blackbox\\axiom-codex-hook.py\r\n" +
        "%USERPROFILE%\\.claude\\settings.json (axiom-claude-hook.py PreToolUse entry only)\r\n" +
        "%LOCALAPPDATA%\\Axiom\\modules\\blackbox\\agent-blackbox\\axiom-claude-hook.py\r\n" +
        "%USERPROFILE%\\.cursor\\hooks.json (axiom-cursor-hook.py preToolUse entry only)\r\n" +
        "%LOCALAPPDATA%\\Axiom\\modules\\blackbox\\agent-blackbox\\axiom-cursor-hook.py\r\n" +
        "%USERPROFILE%\\.copilot\\hooks\\axiom.json\r\n" +
        "%LOCALAPPDATA%\\Axiom\\modules\\blackbox\\agent-blackbox\\axiom-copilot-hook.py\r\n" +
        "%USERPROFILE%\\.gemini\\settings.json (BeforeTool entry only)\r\n" +
        "%LOCALAPPDATA%\\Axiom\\modules\\blackbox\\agent-blackbox\\axiom-gemini-hook.py\r\n" +
        "%USERPROFILE%\\.codeium\\windsurf\\hooks.json (three Cascade pre-hooks only)\r\n" +
        "%LOCALAPPDATA%\\Axiom\\modules\\blackbox\\agent-blackbox\\axiom-windsurf-hook.py\r\n" +
        "%USERPROFILE%\\Documents\\Cline\\Hooks\\PreToolUse.py\r\n" +
        "%LOCALAPPDATA%\\Axiom\\modules\\blackbox, dkg and dkg-home\r\n" +
        "%USERPROFILE%\\.local\\bin\\blackbox.cmd\r\n" +
        "%USERPROFILE%\\.hermes\\config.yaml, .hermes\\blackbox and .hermes\\plugins\\blackbox\r\n" +
        "%LOCALAPPDATA%\\hermes\\config.yaml, plugins, blackbox, bin, installs, cache, logs, backups\r\n" +
        "%LOCALAPPDATA%\\Axiom\\notifications.txt, tray-notifications.txt, hide-background-windows.txt, startup.json and install-profile.json\r\n" +
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run: Axiom (start with Windows)\r\n" +
        "%ProgramData%\\Axiom\\protection.json (Axiom Shield consent/decisions)\r\n" +
        "%ProgramData%\\Axiom\\privacy-shield.json and privacy-shield-rules.json\r\n" +
        "Windows service: Axiom Service (LocalSystem)\r\n" +
        "Scheduled task: Agent Blackbox DKG node";

    private delegate nint WndProcDelegate(nint hwnd, uint msg, nint wParam, nint lParam);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WNDCLASSEXW
    {
        public uint cbSize;
        public uint style;
        public nint lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public nint hInstance;
        public nint hIcon;
        public nint hCursor;
        public nint hbrBackground;
        public string? lpszMenuName;
        public string lpszClassName;
        public nint hIconSm;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PAINTSTRUCT
    {
        public nint hdc;
        public int fErase;
        public RECT rcPaint;
        public int fRestore;
        public int fIncUpdate;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[]? rgbReserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MSG
    {
        public nint hwnd;
        public uint message;
        public nint wParam;
        public nint lParam;
        public uint time;
        public int ptX;
        public int ptY;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct INITCOMMONCONTROLSEX
    {
        public uint dwSize;
        public uint dwICC;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TRACKMOUSEEVENT
    {
        public uint cbSize;
        public uint dwFlags;
        public nint hwndTrack;
        public uint dwHoverTime;
    }

    private static class NativeMethods
    {
        [DllImport("comctl32.dll", SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool InitCommonControlsEx(in INITCOMMONCONTROLSEX iccex);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern nint GetModuleHandle(string? lpModuleName);

        [DllImport("user32.dll", EntryPoint = "RegisterClassExW", CharSet = CharSet.Unicode, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern ushort RegisterClassEx(ref WNDCLASSEXW lpwcx);

        [DllImport("user32.dll", EntryPoint = "CreateWindowExW", CharSet = CharSet.Unicode, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern nint CreateWindowEx(
            uint dwExStyle, string lpClassName, string lpWindowName, uint dwStyle,
            int x, int y, int nWidth, int nHeight,
            nint hWndParent, nint hMenu, nint hInstance, nint lpParam);

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool MoveWindow(
            nint hWnd, int X, int Y, int nWidth, int nHeight, [MarshalAs(UnmanagedType.Bool)] bool bRepaint);

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ShowWindow(nint hWnd, int nCmdShow);

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool UpdateWindow(nint hWnd);

        [DllImport("user32.dll", EntryPoint = "DefWindowProcW")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern nint DefWindowProc(nint hWnd, uint msg, nint wParam, nint lParam);

        [DllImport("user32.dll", EntryPoint = "GetMessageW")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern int GetMessage(out MSG lpMsg, nint hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool TranslateMessage(in MSG lpMsg);

        [DllImport("user32.dll", EntryPoint = "DispatchMessageW")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern nint DispatchMessage(in MSG lpMsg);

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern void PostQuitMessage(int nExitCode);

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DestroyWindow(nint hWnd);

        [DllImport("user32.dll", EntryPoint = "SendMessageW")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern nint SendMessage(nint hWnd, uint msg, nint wParam, nint lParam);

        [DllImport("user32.dll", EntryPoint = "SendMessageW", CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern nint SendMessageText(nint hWnd, uint msg, nint wParam, string lParam);

        [DllImport("user32.dll", EntryPoint = "PostMessageW")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool PostMessage(nint hWnd, uint msg, nint wParam, nint lParam);

        [DllImport("user32.dll", EntryPoint = "SetWindowTextW", CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetWindowText(nint hWnd, string lpString);

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool InvalidateRect(nint hWnd, nint lpRect, [MarshalAs(UnmanagedType.Bool)] bool bErase);

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetClientRect(nint hWnd, out RECT lpRect);

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern nint BeginPaint(nint hWnd, out PAINTSTRUCT lpPaint);

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EndPaint(nint hWnd, ref PAINTSTRUCT lpPaint);

        [DllImport("user32.dll", EntryPoint = "LoadCursorW")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern nint LoadCursor(nint hInstance, int lpCursorName);

        [DllImport("user32.dll", EntryPoint = "LoadIconW")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern nint LoadIcon(nint hInstance, nint lpIconName);

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern nint SetCursor(nint hCursor);

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool TrackMouseEvent(ref TRACKMOUSEEVENT lpEventTrack);

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern nint SetCapture(nint hWnd);

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern nint GetCapture();

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReleaseCapture();

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern nuint SetTimer(nint hWnd, nuint nIDEvent, uint uElapse, nint lpTimerFunc);

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool KillTimer(nint hWnd, nuint uIDEvent);

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern uint GetDpiForSystem();

        [DllImport("user32.dll", EntryPoint = "SystemParametersInfoW")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SystemParametersInfo(uint uiAction, uint uiParam, out RECT pvParam, uint fWinIni);

        [DllImport("user32.dll", EntryPoint = "MessageBoxW", CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern int MessageBox(nint hWnd, string lpText, string lpCaption, uint uType);

        [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern int SetWindowTheme(nint hwnd, string? pszSubAppName, string? pszSubIdList);

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern nint GetDC(nint hWnd);

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern int ReleaseDC(nint hWnd, nint hDC);

        [DllImport("gdi32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern nint CreateSolidBrush(int color);

        [DllImport("gdi32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern nint CreateCompatibleDC(nint hdc);

        [DllImport("gdi32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DeleteDC(nint hdc);

        [DllImport("gdi32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern nint CreateCompatibleBitmap(nint hdc, int cx, int cy);

        [DllImport("gdi32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern nint SelectObject(nint hdc, nint h);

        [DllImport("gdi32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DeleteObject(nint ho);

        [DllImport("gdi32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool BitBlt(
            nint hdc, int x, int y, int cx, int cy, nint hdcSrc, int x1, int y1, uint rop);

        [DllImport("gdi32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern int SetTextColor(nint hdc, int color);

        [DllImport("gdi32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern int SetBkColor(nint hdc, int color);

        [DllImport("gdi32.dll", EntryPoint = "CreateFontW", CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern nint CreateFont(
            int cHeight, int cWidth, int cEscapement, int cOrientation, int cWeight,
            uint bItalic, uint bUnderline, uint bStrikeOut, uint iCharSet,
            uint iOutPrecision, uint iClipPrecision, uint iQuality, uint iPitchAndFamily, string pszFaceName);

        [DllImport("dwmapi.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern int DwmSetWindowAttribute(nint hwnd, int dwAttribute, ref int pvAttribute, int cbAttribute);
    }
}
