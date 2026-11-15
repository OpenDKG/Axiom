// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Concurrent;
using System.Runtime.InteropServices;

namespace Axiom.Setup;

/// <summary>
/// Lightweight dark-mode Win32 setup window replacing WPF so the self-contained installer binary
/// ships without ~60 MB of WPF framework assemblies while preserving every option, risk notice,
/// write-scope list, and live installation log.
/// </summary>
internal sealed class SetupNativeWindow : IDisposable
{
    private const string WindowClassName = "AxiomSetupNativeWindow";
    private const int LogicalWidth = 656;
    private const int LogicalHeight = 840;

    private const uint WmCreate = 0x0001;
    private const uint WmDestroy = 0x0002;
    private const uint WmPaint = 0x000F;
    private const uint WmClose = 0x0010;
    private const uint WmSetFont = 0x0030;
    private const uint WmDrawItem = 0x002B;
    private const uint WmCommand = 0x0111;
    private const uint WmCtlColorEdit = 0x0133;
    private const uint WmCtlColorBtn = 0x0135;
    private const uint WmCtlColorStatic = 0x0138;
    private const uint WmAppLog = 0x8001;
    private const uint WmAppDone = 0x8002;

    private const uint WsOverlapped = 0x00000000;
    private const uint WsCaption = 0x00C00000;
    private const uint WsSysMenu = 0x00080000;
    private const uint WsMinimizeBox = 0x00020000;
    private const uint WsVisible = 0x10000000;
    private const uint WsChild = 0x40000000;
    private const uint WsTabStop = 0x00010000;
    private const uint WsVScroll = 0x00200000;
    private const uint WsBorder = 0x00800000;
    private const uint WsDisabled = 0x08000000;

    private const uint BsAutoCheckBox = 0x00000003;
    private const uint BsRadioButton = 0x00000004;
    private const uint BsOwnerDraw = 0x0000000B;
    private const uint SsNotify = 0x00000100;
    private const uint EsMultiline = 0x0004;
    private const uint EsAutoVScroll = 0x0040;
    private const uint EsReadOnly = 0x0800;

    private const uint BmGetCheck = 0x00F0;
    private const uint BmSetCheck = 0x00F1;
    private const int BstUnchecked = 0;
    private const int BstChecked = 1;
    private const int BnClicked = 0;
    private const int StnClicked = 0;

    private const uint EmSetSel = 0x00B1;
    private const uint EmReplaceSel = 0x00C2;
    private const uint EmScrollCaret = 0x00B7;

    private const uint MbOk = 0x00000000;
    private const uint MbIconError = 0x00000010;
    private const uint MbIconWarning = 0x00000030;
    private const uint MbIconInformation = 0x00000040;

    private const int DwmwaUseImmersiveDarkMode = 20;
    private const uint SpiGetWorkArea = 0x0030;

    private const int IdAgreeCheck = 101;
    private const int IdAgreeLabel = 102;
    private const int IdShortcutCheck = 103;
    private const int IdShortcutLabel = 104;
    private const int IdLaunchCheck = 105;
    private const int IdLaunchLabel = 106;
    private const int IdCompleteRadio = 107;
    private const int IdCompleteLabel = 108;
    private const int IdPartialRadio = 109;
    private const int IdPartialLabel = 110;
    private const int IdScopeEdit = 111;
    private const int IdLogEdit = 112;
    private const int IdInstallBtn = 113;
    private const int IdCloseBtn = 114;

    private static readonly int ColorBg = Rgb(15, 20, 28);
    private static readonly int ColorCard = Rgb(23, 30, 41);
    private static readonly int ColorSurface = Rgb(17, 24, 34);
    private static readonly int ColorBorder = Rgb(44, 56, 74);
    private static readonly int ColorWarningBorder = Rgb(210, 153, 34);
    private static readonly int ColorWarningText = Rgb(238, 178, 56);
    private static readonly int ColorTextPrimary = Rgb(232, 238, 246);
    private static readonly int ColorTextSecondary = Rgb(164, 178, 198);
    private static readonly int ColorAccent = Rgb(47, 118, 210);
    private static readonly int ColorAccentPressed = Rgb(36, 94, 170);
    private static readonly int ColorBtnSurface = Rgb(33, 43, 58);
    private static readonly int ColorBtnPressed = Rgb(24, 32, 44);
    private static readonly int ColorDisabled = Rgb(26, 33, 44);
    private static readonly int ColorDisabledText = Rgb(104, 118, 138);

    private readonly SetupOptions _initialOptions;
    private readonly ConcurrentQueue<string> _logQueue = new();
    private readonly List<RECT> _cardRects = [];
    private RECT _warningCardRect;
    private readonly HashSet<nint> _cardLabelHandles = [];

    private WndProcDelegate? _wndProc;
    private nint _hwnd;
    private nint _hAgreeCheck;
    private nint _hShortcutCheck;
    private nint _hLaunchCheck;
    private nint _hCompleteRadio;
    private nint _hPartialRadio;
    private nint _hScopeEdit;
    private nint _hLogEdit;
    private nint _hInstallBtn;
    private nint _hCloseBtn;
    private nint _hWarningTitle;

    private nint _brushBg;
    private nint _brushCard;
    private nint _brushSurface;
    private nint _fontTitle;
    private nint _fontSection;
    private nint _fontBody;
    private nint _fontSmall;
    private nint _fontMono;

    private double _scale = 1.0;
    private bool _installing;
    private bool _completedSuccessfully;
    private SetupInstallResult? _installResult;
    private string _installButtonText = "Install Axiom";
    private string _closeButtonText = "Cancel";

    public SetupNativeWindow(SetupOptions options)
    {
        _initialOptions = options;
    }

    public int Run()
    {
        NativeMethods.InitCommonControlsEx(new INITCOMMONCONTROLSEX
        {
            dwSize = (uint)Marshal.SizeOf<INITCOMMONCONTROLSEX>(),
            dwICC = 0x00004000, // ICC_STANDARD_CLASSES
        });

        _brushBg = NativeMethods.CreateSolidBrush(ColorBg);
        _brushCard = NativeMethods.CreateSolidBrush(ColorCard);
        _brushSurface = NativeMethods.CreateSolidBrush(ColorSurface);

        _wndProc = WindowProc;
        var hInstance = NativeMethods.GetModuleHandle(null);
        var wc = new WNDCLASSEXW
        {
            cbSize = (uint)Marshal.SizeOf<WNDCLASSEXW>(),
            lpfnWndProc = Marshal.GetFunctionPointerForDelegate(_wndProc),
            hInstance = hInstance,
            hCursor = NativeMethods.LoadCursor(nint.Zero, 32512), // IDC_ARROW
            hbrBackground = _brushBg,
            lpszClassName = WindowClassName,
        };

        var atom = NativeMethods.RegisterClassEx(ref wc);
        if (atom == 0)
        {
            return 1;
        }

        uint sysDpi = NativeMethods.GetDpiForSystem();
        _scale = Math.Max(1.0, sysDpi / 96.0);
        int width = S(LogicalWidth);
        int height = S(LogicalHeight);

        NativeMethods.SystemParametersInfo(SpiGetWorkArea, 0, out RECT workArea, 0);
        int x = workArea.Left + Math.Max(0, (workArea.Right - workArea.Left - width) / 2);
        int y = workArea.Top + Math.Max(0, (workArea.Bottom - workArea.Top - height) / 2);
        if (height > workArea.Bottom - workArea.Top)
        {
            height = Math.Max(640, workArea.Bottom - workArea.Top - 24);
        }

        _hwnd = NativeMethods.CreateWindowEx(
            0,
            WindowClassName,
            "Axiom Setup",
            WsOverlapped | WsCaption | WsSysMenu | WsMinimizeBox | WsVisible,
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

        int dark = 1;
        _ = NativeMethods.DwmSetWindowAttribute(_hwnd, DwmwaUseImmersiveDarkMode, ref dark, sizeof(int));

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
        DeleteGdiObject(ref _brushBg);
        DeleteGdiObject(ref _brushCard);
        DeleteGdiObject(ref _brushSurface);
        DeleteGdiObject(ref _fontTitle);
        DeleteGdiObject(ref _fontSection);
        DeleteGdiObject(ref _fontBody);
        DeleteGdiObject(ref _fontSmall);
        DeleteGdiObject(ref _fontMono);
    }

    private nint WindowProc(nint hwnd, uint msg, nint wParam, nint lParam)
    {
        switch (msg)
        {
            case WmCreate:
                _hwnd = hwnd;
                CreateFonts();
                CreateLayout();
                return nint.Zero;

            case WmPaint:
                PaintCards(hwnd);
                return nint.Zero;

            case WmCtlColorStatic:
                return HandleStaticColor(wParam, lParam);

            case WmCtlColorEdit:
                _ = NativeMethods.SetTextColor(wParam, ColorTextPrimary);
                _ = NativeMethods.SetBkColor(wParam, ColorSurface);
                return _brushSurface;

            case WmCtlColorBtn:
                _ = NativeMethods.SetTextColor(wParam, ColorTextPrimary);
                _ = NativeMethods.SetBkColor(wParam, ColorCard);
                return _brushCard;

            case WmDrawItem:
                DrawOwnerButton(Marshal.PtrToStructure<DRAWITEMSTRUCT>(lParam));
                return 1;

            case WmCommand:
                HandleCommand(wParam);
                return nint.Zero;

            case WmAppLog:
                DrainLogQueue();
                return nint.Zero;

            case WmAppDone:
                FinishInstall();
                return nint.Zero;

            case WmClose:
                if (_installing)
                {
                    return nint.Zero;
                }

                NativeMethods.DestroyWindow(hwnd);
                return nint.Zero;

            case WmDestroy:
                NativeMethods.PostQuitMessage(0);
                return nint.Zero;

            default:
                return NativeMethods.DefWindowProc(hwnd, msg, wParam, lParam);
        }
    }

    private void CreateFonts()
    {
        _fontTitle = CreateFont("Segoe UI", 22, 600);
        _fontSection = CreateFont("Segoe UI", 14, 600);
        _fontBody = CreateFont("Segoe UI", 13, 400);
        _fontSmall = CreateFont("Segoe UI", 11, 400);
        _fontMono = CreateFont("Consolas", 11, 400);
    }

    private nint CreateFont(string name, int px, int weight) =>
        NativeMethods.CreateFont(
            -S(px), 0, 0, 0, weight, 0, 0, 0, 1, 0, 0, 5 /* CLEARTYPE_QUALITY */, 0, name);

    private void CreateLayout()
    {
        NativeMethods.GetClientRect(_hwnd, out RECT client);
        int cw = client.Right - client.Left;
        int ch = client.Bottom - client.Top;
        int pad = S(18);
        int innerW = cw - (pad * 2);
        int y = S(14);

        AddLabel(pad, y, innerW, S(28), "Axiom Setup", _fontTitle, onCard: false);
        y += S(30);
        AddLabel(
            pad, y, innerW, S(34),
            "Install Axiom for this Windows user. Partial installation needs no administrator rights. Complete installation uses one Windows elevation prompt to register the local service.",
            _fontSmall,
            onCard: false);
        y += S(40);

        // Card 1: Development build risk card
        int card1Top = y;
        int cy = card1Top + S(10);
        int cx = pad + S(12);
        int ciw = innerW - S(24);

        _hWarningTitle = AddLabel(cx, cy, ciw, S(18), "Development build - use at your own risk", _fontSection, onCard: true);
        cy += S(22);
        AddLabel(
            cx, cy, ciw, S(46),
            "Axiom is under active development and may contain defects, incomplete features or regressions. Firewall changes can interrupt connectivity, DNS changes can break name resolution, and agent hooks can block tools or files. Rely on backups and test in a VM where possible.",
            _fontSmall,
            onCard: true);
        cy += S(50);

        _hAgreeCheck = AddCheckBox(cx, cy, S(18), S(18), IdAgreeCheck, isChecked: false);
        AddClickableLabel(
            cx + S(22), cy + S(1), ciw - S(22), S(18), IdAgreeLabel,
            "I understand these risks and accept that I use Axiom at my own risk.",
            _fontBody);
        cy += S(28);
        _warningCardRect = new RECT { Left = pad, Top = card1Top, Right = cw - pad, Bottom = cy };
        y = cy + S(10);

        // Card 2: Location, options & installation type
        int card2Top = y;
        cy = card2Top + S(10);

        AddLabel(cx, cy, ciw, S(18), $"Install location: {_initialOptions.InstallDir}", _fontBody, onCard: true);
        cy += S(24);

        _hShortcutCheck = AddCheckBox(cx, cy, S(18), S(18), IdShortcutCheck, _initialOptions.CreateShortcut);
        AddClickableLabel(cx + S(22), cy + S(1), ciw / 2 - S(24), S(18), IdShortcutLabel, "Create a Start Menu shortcut", _fontBody);

        _hLaunchCheck = AddCheckBox(cx + ciw / 2, cy, S(18), S(18), IdLaunchCheck, _initialOptions.StartAfterInstall);
        AddClickableLabel(cx + ciw / 2 + S(22), cy + S(1), ciw / 2 - S(24), S(18), IdLaunchLabel, "Start Axiom after installation", _fontBody);
        cy += S(26);

        AddLabel(cx, cy, ciw, S(18), "Installation type", _fontSection, onCard: true);
        cy += S(22);

        _hCompleteRadio = AddRadioButton(cx, cy, S(18), S(18), IdCompleteRadio, _initialOptions.CompleteInstallation);
        AddClickableLabel(
            cx + S(22), cy + S(1), ciw - S(22), S(78), IdCompleteLabel,
            "Complete installation (recommended)\r\n" +
            "Registers the Axiom Windows service (one elevation prompt), enables Axiom Shield (ask policy), Privacy Shield resolver (port 53 + DoH 443), autostart, notifications, the verified Blackbox runtime, a local DKG node and coding-agent hooks. Expect 10-20 minutes and heavy disk use; each step is shown.",
            _fontSmall);
        cy += S(82);

        _hPartialRadio = AddRadioButton(cx, cy, S(18), S(18), IdPartialRadio, !_initialOptions.CompleteInstallation);
        AddClickableLabel(
            cx + S(22), cy + S(1), ciw - S(22), S(36), IdPartialLabel,
            "Partial installation\r\nInstalls only the desktop app, local history service and monitor. No admin prompt, firewall rules, DNS or hooks.",
            _fontSmall);
        cy += S(42);

        AddLabel(cx, cy, ciw, S(16), "Complete installation may write only:", _fontSmall, onCard: true);
        cy += S(18);

        _hScopeEdit = NativeMethods.CreateWindowEx(
            0, "EDIT", WriteScopeText,
            WsChild | WsVisible | WsBorder | WsVScroll | EsMultiline | EsReadOnly | EsAutoVScroll,
            cx, cy, ciw, S(92), _hwnd, IdScopeEdit, nint.Zero, nint.Zero);
        NativeMethods.SendMessage(_hScopeEdit, WmSetFont, _fontMono, 1);
        cy += S(100);

        _cardRects.Add(new RECT { Left = pad, Top = card2Top, Right = cw - pad, Bottom = cy });
        y = cy + S(10);

        // Card 3: Installation log (fills remaining space down to buttons)
        int btnH = S(34);
        int footerH = btnH + S(26);
        int card3Bottom = ch - footerH;
        int card3Top = y;
        cy = card3Top + S(10);

        AddLabel(cx, cy, ciw, S(18), "Installation log", _fontSection, onCard: true);
        cy += S(22);

        int logH = Math.Max(S(76), card3Bottom - cy - S(10));
        _hLogEdit = NativeMethods.CreateWindowEx(
            0, "EDIT", "",
            WsChild | WsVisible | WsBorder | WsVScroll | EsMultiline | EsReadOnly | EsAutoVScroll,
            cx, cy, ciw, logH, _hwnd, IdLogEdit, nint.Zero, nint.Zero);
        NativeMethods.SendMessage(_hLogEdit, WmSetFont, _fontMono, 1);
        _cardRects.Add(new RECT { Left = pad, Top = card3Top, Right = cw - pad, Bottom = card3Bottom });

        // Footer buttons
        int btnY = card3Bottom + S(12);
        int cancelW = S(108);
        int installW = S(148);
        int closeX = cw - pad - cancelW;
        int installX = closeX - S(10) - installW;

        _hInstallBtn = NativeMethods.CreateWindowEx(
            0, "BUTTON", _installButtonText,
            WsChild | WsVisible | WsTabStop | BsOwnerDraw | WsDisabled,
            installX, btnY, installW, btnH, _hwnd, IdInstallBtn, nint.Zero, nint.Zero);
        _hCloseBtn = NativeMethods.CreateWindowEx(
            0, "BUTTON", _closeButtonText,
            WsChild | WsVisible | WsTabStop | BsOwnerDraw,
            closeX, btnY, cancelW, btnH, _hwnd, IdCloseBtn, nint.Zero, nint.Zero);

        NativeMethods.SetFocus(_hAgreeCheck);
    }

    private nint AddLabel(int x, int y, int w, int h, string text, nint font, bool onCard)
    {
        nint label = NativeMethods.CreateWindowEx(
            0, "STATIC", text, WsChild | WsVisible, x, y, w, h, _hwnd, nint.Zero, nint.Zero, nint.Zero);
        NativeMethods.SendMessage(label, WmSetFont, font, 1);
        if (onCard)
        {
            _cardLabelHandles.Add(label);
        }

        return label;
    }

    private nint AddClickableLabel(int x, int y, int w, int h, int id, string text, nint font)
    {
        nint label = NativeMethods.CreateWindowEx(
            0, "STATIC", text, WsChild | WsVisible | SsNotify, x, y, w, h, _hwnd, id, nint.Zero, nint.Zero);
        NativeMethods.SendMessage(label, WmSetFont, font, 1);
        _cardLabelHandles.Add(label);
        return label;
    }

    private nint AddCheckBox(int x, int y, int w, int h, int id, bool isChecked)
    {
        nint box = NativeMethods.CreateWindowEx(
            0, "BUTTON", "", WsChild | WsVisible | WsTabStop | BsAutoCheckBox,
            x, y, w, h, _hwnd, id, nint.Zero, nint.Zero);
        NativeMethods.SendMessage(box, BmSetCheck, isChecked ? BstChecked : BstUnchecked, 0);
        return box;
    }

    private nint AddRadioButton(int x, int y, int w, int h, int id, bool isChecked)
    {
        nint radio = NativeMethods.CreateWindowEx(
            0, "BUTTON", "", WsChild | WsVisible | WsTabStop | BsRadioButton,
            x, y, w, h, _hwnd, id, nint.Zero, nint.Zero);
        NativeMethods.SendMessage(radio, BmSetCheck, isChecked ? BstChecked : BstUnchecked, 0);
        return radio;
    }

    private void PaintCards(nint hwnd)
    {
        nint hdc = NativeMethods.BeginPaint(hwnd, out PAINTSTRUCT ps);
        try
        {
            DrawCard(hdc, _warningCardRect, ColorWarningBorder);
            foreach (var rect in _cardRects)
            {
                DrawCard(hdc, rect, ColorBorder);
            }
        }
        finally
        {
            NativeMethods.EndPaint(hwnd, ref ps);
        }
    }

    private void DrawCard(nint hdc, RECT rect, int borderColor)
    {
        nint pen = NativeMethods.CreatePen(0 /* PS_SOLID */, 1, borderColor);
        nint oldPen = NativeMethods.SelectObject(hdc, pen);
        nint oldBrush = NativeMethods.SelectObject(hdc, _brushCard);
        NativeMethods.RoundRect(hdc, rect.Left, rect.Top, rect.Right, rect.Bottom, S(8), S(8));
        NativeMethods.SelectObject(hdc, oldBrush);
        NativeMethods.SelectObject(hdc, oldPen);
        NativeMethods.DeleteObject(pen);
    }

    private nint HandleStaticColor(nint hdc, nint hwndCtrl)
    {
        bool onCard = _cardLabelHandles.Contains(hwndCtrl);
        int textColor = hwndCtrl == _hWarningTitle
            ? ColorWarningText
            : onCard ? ColorTextPrimary : ColorTextSecondary;
        _ = NativeMethods.SetTextColor(hdc, textColor);
        _ = NativeMethods.SetBkColor(hdc, onCard ? ColorCard : ColorBg);
        return onCard ? _brushCard : _brushBg;
    }

    private void DrawOwnerButton(DRAWITEMSTRUCT dis)
    {
        bool isInstall = dis.CtlID == IdInstallBtn;
        bool disabled = (dis.itemState & 0x0004 /* ODS_DISABLED */) != 0;
        bool pressed = (dis.itemState & 0x0001 /* ODS_SELECTED */) != 0;

        int fillColor = disabled
            ? ColorDisabled
            : isInstall
                ? (pressed ? ColorAccentPressed : ColorAccent)
                : (pressed ? ColorBtnPressed : ColorBtnSurface);
        int borderColor = disabled ? ColorBorder : (isInstall ? ColorAccent : ColorBorder);
        int textColor = disabled ? ColorDisabledText : ColorTextPrimary;

        nint brush = NativeMethods.CreateSolidBrush(fillColor);
        nint pen = NativeMethods.CreatePen(0, 1, borderColor);
        nint oldBrush = NativeMethods.SelectObject(dis.hDC, brush);
        nint oldPen = NativeMethods.SelectObject(dis.hDC, pen);
        nint oldFont = NativeMethods.SelectObject(dis.hDC, _fontBody);

        NativeMethods.RoundRect(dis.hDC, dis.rcItem.Left, dis.rcItem.Top, dis.rcItem.Right, dis.rcItem.Bottom, S(6), S(6));
        _ = NativeMethods.SetBkMode(dis.hDC, 1 /* TRANSPARENT */);
        _ = NativeMethods.SetTextColor(dis.hDC, textColor);

        string caption = isInstall ? _installButtonText : _closeButtonText;
        RECT r = dis.rcItem;
        _ = NativeMethods.DrawText(dis.hDC, caption, caption.Length, ref r, 0x01 /* DT_CENTER */ | 0x04 /* DT_VCENTER */ | 0x20 /* DT_SINGLELINE */);

        NativeMethods.SelectObject(dis.hDC, oldFont);
        NativeMethods.SelectObject(dis.hDC, oldPen);
        NativeMethods.SelectObject(dis.hDC, oldBrush);
        NativeMethods.DeleteObject(pen);
        NativeMethods.DeleteObject(brush);
    }

    private void HandleCommand(nint wParam)
    {
        int id = unchecked((short)(wParam & 0xFFFF));
        int code = unchecked((short)((wParam >> 16) & 0xFFFF));

        if (id == IdAgreeLabel && code == StnClicked && !_installing)
        {
            ToggleCheck(_hAgreeCheck);
            UpdateInstallEnabled();
            return;
        }

        if (id == IdAgreeCheck && code == BnClicked && !_installing)
        {
            UpdateInstallEnabled();
            return;
        }

        if (id == IdShortcutLabel && code == StnClicked && !_installing)
        {
            ToggleCheck(_hShortcutCheck);
            return;
        }

        if (id == IdLaunchLabel && code == StnClicked && !_installing)
        {
            ToggleCheck(_hLaunchCheck);
            return;
        }

        if ((id == IdCompleteRadio || id == IdCompleteLabel) && !_installing)
        {
            SetInstallType(complete: true);
            return;
        }

        if ((id == IdPartialRadio || id == IdPartialLabel) && !_installing)
        {
            SetInstallType(complete: false);
            return;
        }

        if (id == IdInstallBtn && code == BnClicked)
        {
            StartInstall();
            return;
        }

        if (id == IdCloseBtn && code == BnClicked && !_installing)
        {
            NativeMethods.PostMessage(_hwnd, WmClose, 0, 0);
        }
    }

    private static void ToggleCheck(nint hBox)
    {
        bool checkedNow = IsChecked(hBox);
        NativeMethods.SendMessage(hBox, BmSetCheck, checkedNow ? BstUnchecked : BstChecked, 0);
    }

    private static bool IsChecked(nint hCtrl) =>
        NativeMethods.SendMessage(hCtrl, BmGetCheck, 0, 0) == BstChecked;

    private void SetInstallType(bool complete)
    {
        NativeMethods.SendMessage(_hCompleteRadio, BmSetCheck, complete ? BstChecked : BstUnchecked, 0);
        NativeMethods.SendMessage(_hPartialRadio, BmSetCheck, complete ? BstUnchecked : BstChecked, 0);
    }

    private void UpdateInstallEnabled()
    {
        bool canInstall = !_installing && !_completedSuccessfully && IsChecked(_hAgreeCheck);
        NativeMethods.EnableWindow(_hInstallBtn, canInstall);
        NativeMethods.InvalidateRect(_hInstallBtn, nint.Zero, true);
    }

    private void StartInstall()
    {
        if (_installing || !IsChecked(_hAgreeCheck))
        {
            return;
        }

        _installing = true;
        NativeMethods.EnableWindow(_hInstallBtn, false);
        NativeMethods.EnableWindow(_hAgreeCheck, false);
        NativeMethods.EnableWindow(_hShortcutCheck, false);
        NativeMethods.EnableWindow(_hLaunchCheck, false);
        NativeMethods.EnableWindow(_hCompleteRadio, false);
        NativeMethods.EnableWindow(_hPartialRadio, false);
        NativeMethods.EnableWindow(_hCloseBtn, false);
        NativeMethods.InvalidateRect(_hInstallBtn, nint.Zero, true);
        NativeMethods.InvalidateRect(_hCloseBtn, nint.Zero, true);
        NativeMethods.SetWindowText(_hLogEdit, string.Empty);

        var options = _initialOptions with
        {
            CreateShortcut = IsChecked(_hShortcutCheck),
            StartAfterInstall = IsChecked(_hLaunchCheck),
            CompleteInstallation = IsChecked(_hCompleteRadio),
        };

        var progress = new NativeLogProgress(message =>
        {
            _logQueue.Enqueue(message);
            NativeMethods.PostMessage(_hwnd, WmAppLog, 0, 0);
        });

        _ = Task.Run(async () =>
        {
            _installResult = await SetupInstaller
                .InstallAsync(options, progress, CancellationToken.None)
                .ConfigureAwait(false);
            NativeMethods.PostMessage(_hwnd, WmAppDone, 0, 0);
        });
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

        string text = string.Join("\r\n", lines) + "\r\n";
        NativeMethods.SendMessage(_hLogEdit, EmSetSel, -1, -1);
        NativeMethods.SendMessageText(_hLogEdit, EmReplaceSel, 0, text);
        NativeMethods.SendMessage(_hLogEdit, EmScrollCaret, 0, 0);
    }

    private void FinishInstall()
    {
        DrainLogQueue();
        _installing = false;
        var result = _installResult;
        bool startAfter = IsChecked(_hLaunchCheck);

        if (result is { Success: true })
        {
            _completedSuccessfully = true;
            _closeButtonText = "Close";
            NativeMethods.EnableWindow(_hCloseBtn, true);
            NativeMethods.InvalidateRect(_hCloseBtn, nint.Zero, true);

            if (result.Warning is { Length: > 0 } warning)
            {
                _ = NativeMethods.MessageBox(_hwnd, warning, "Axiom Setup", MbOk | MbIconWarning);
            }

            if (startAfter)
            {
                NativeMethods.PostMessage(_hwnd, WmClose, 0, 0);
                return;
            }

            _ = NativeMethods.MessageBox(_hwnd, result.Message, "Axiom Setup", MbOk | MbIconInformation);
        }
        else
        {
            NativeMethods.EnableWindow(_hAgreeCheck, true);
            NativeMethods.EnableWindow(_hShortcutCheck, true);
            NativeMethods.EnableWindow(_hLaunchCheck, true);
            NativeMethods.EnableWindow(_hCompleteRadio, true);
            NativeMethods.EnableWindow(_hPartialRadio, true);
            NativeMethods.EnableWindow(_hCloseBtn, true);
            UpdateInstallEnabled();
            NativeMethods.InvalidateRect(_hCloseBtn, nint.Zero, true);
            _ = NativeMethods.MessageBox(
                _hwnd,
                result?.Message ?? "Installation failed.",
                "Axiom Setup failed",
                MbOk | MbIconError);
        }
    }

    private int S(int logicalPx) => (int)Math.Round(logicalPx * _scale);

    private static int Rgb(int r, int g, int b) => r | (g << 8) | (b << 16);

    private static void DeleteGdiObject(ref nint handle)
    {
        if (handle != nint.Zero)
        {
            NativeMethods.DeleteObject(handle);
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
    private struct DRAWITEMSTRUCT
    {
        public uint CtlType;
        public uint CtlID;
        public uint itemID;
        public uint itemAction;
        public uint itemState;
        public nint hwndItem;
        public nint hDC;
        public RECT rcItem;
        public nint itemData;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct INITCOMMONCONTROLSEX
    {
        public uint dwSize;
        public uint dwICC;
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

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnableWindow(nint hWnd, [MarshalAs(UnmanagedType.Bool)] bool bEnable);

        [DllImport("user32.dll", EntryPoint = "SetWindowTextW", CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetWindowText(nint hWnd, string lpString);

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern nint SetFocus(nint hWnd);

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

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern uint GetDpiForSystem();

        [DllImport("user32.dll", EntryPoint = "SystemParametersInfoW")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SystemParametersInfo(uint uiAction, uint uiParam, out RECT pvParam, uint fWinIni);

        [DllImport("user32.dll", EntryPoint = "DrawTextW", CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern int DrawText(nint hdc, string lpchText, int cchText, ref RECT lprc, uint format);

        [DllImport("user32.dll", EntryPoint = "MessageBoxW", CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern int MessageBox(nint hWnd, string lpText, string lpCaption, uint uType);

        [DllImport("gdi32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern nint CreateSolidBrush(int color);

        [DllImport("gdi32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern nint CreatePen(int iStyle, int cWidth, int color);

        [DllImport("gdi32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern nint SelectObject(nint hdc, nint h);

        [DllImport("gdi32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DeleteObject(nint ho);

        [DllImport("gdi32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern int SetTextColor(nint hdc, int color);

        [DllImport("gdi32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern int SetBkColor(nint hdc, int color);

        [DllImport("gdi32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern int SetBkMode(nint hdc, int mode);

        [DllImport("gdi32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool RoundRect(nint hdc, int left, int top, int right, int bottom, int width, int height);

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
