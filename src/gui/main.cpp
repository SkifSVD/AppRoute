// approute-gui — главное окно AppRoute (issue #12).
//
// Список правил «программа → интерфейс», добавление, правка и удаление правил, выбор программы
// и интерфейса из подключённых адаптеров, запуск программы по правилу. Правила хранятся в том же
// config.json, что использует approute-config и approute-run.
//
// Вся логика — в core (Config, Launcher, NetAdapters); здесь только окна.
//
//   approute-gui [--config FILE]

#include "resource.h"

#include "core/Config.h"
#include "core/Launcher.h"
#include "core/NetAdapters.h"
#include "core/Util.h"

#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <uxtheme.h>

#include <algorithm>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using namespace approute;

namespace {

constexpr UINT_PTR kStatusTimer = 1;
constexpr UINT kStatusTimerMs = 3000;    // состояние интерфейсов меняется при (пере)подключении VPN
constexpr UINT kMsgDpiChanged = WM_APP + 1;

enum Column { ColProgram, ColAdapter, ColState, ColPolicy, ColPath, ColCount };

struct AppState {
    HINSTANCE instance = nullptr;
    HWND main = nullptr;
    HWND list = nullptr;
    std::wstring configPath;
    Config config;
    bool readOnly = false;               // конфиг не прочитан — не перезаписываем файл пользователя
    std::vector<NetAdapter> adapters;
    HIMAGELIST icons = nullptr;
    HICON bigIcon = nullptr;
    HICON smallIcon = nullptr;
};

AppState g;

// --- мелочи ---------------------------------------------------------------------------------

std::wstring WindowText(HWND h)
{
    const int n = GetWindowTextLengthW(h);
    std::wstring s(static_cast<size_t>(n) + 1, L'\0');
    GetWindowTextW(h, s.data(), n + 1);
    s.resize(static_cast<size_t>(n));
    return s;
}

std::wstring FileNameOf(std::wstring_view path)
{
    const auto pos = path.find_last_of(L"\\/");
    return std::wstring(pos == std::wstring_view::npos ? path : path.substr(pos + 1));
}

bool IsPath(std::wstring_view app)
{
    return app.find_first_of(L"\\/") != std::wstring_view::npos;
}

std::wstring Expand(const std::wstring& s)
{
    wchar_t out[MAX_PATH * 2] = {};
    const DWORD n = ExpandEnvironmentStringsW(s.c_str(), out, static_cast<DWORD>(std::size(out)));
    return n > 0 && n <= std::size(out) ? std::wstring(out) : s;
}

void SetStatus(const std::wstring& text)
{
    SetDlgItemTextW(g.main, IDC_STATUS, text.c_str());
}

int Message(HWND owner, const std::wstring& text, UINT flags)
{
    return MessageBoxW(owner, text.c_str(), L"AppRoute", flags);
}

// --- интерфейсы -----------------------------------------------------------------------------

void LoadAdapters()
{
    try {
        g.adapters = EnumerateAdapters();
    } catch (...) {
        g.adapters.clear();
    }
}

const NetAdapter* AdapterByGuid(const std::wstring& guid)
{
    return guid.empty() ? nullptr : FindAdapter(g.adapters, guid);
}

std::wstring FirstAddress(const NetAdapter& a, ADDRESS_FAMILY family)
{
    for (const auto& u : a.unicast) {
        if (u.address.si_family != family) {
            continue;
        }
        if (family == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&u.address.Ipv6.sin6_addr)) {
            continue;
        }
        return FormatAddress(u.address);
    }
    return {};
}

std::wstring AdapterState(const NetAdapter* a)
{
    if (!a) {
        return L"Нет в системе";
    }
    if (!a->IsUp()) {
        return L"Отключён";
    }
    if (FirstAddress(*a, AF_INET).empty() && FirstAddress(*a, AF_INET6).empty()) {
        return L"Нет адреса";
    }
    return L"Подключён";
}

std::wstring AdapterComboText(const NetAdapter& a)
{
    std::wstring s = a.alias;
    if (!a.description.empty() && a.description != a.alias) {
        s += L" — " + a.description;
    }
    if (!a.IsUp()) {
        s += L" (отключён)";
    }
    return s;
}

// Подключённые — сверху, затем по имени
std::vector<const NetAdapter*> SortedAdapters()
{
    std::vector<const NetAdapter*> out;
    for (const auto& a : g.adapters) {
        if (a.guid != GUID{}) {
            out.push_back(&a);
        }
    }
    std::stable_sort(out.begin(), out.end(), [](const NetAdapter* x, const NetAdapter* y) {
        if (x->IsUp() != y->IsUp()) {
            return x->IsUp();
        }
        return _wcsicmp(x->alias.c_str(), y->alias.c_str()) < 0;
    });
    return out;
}

const wchar_t* OnUnavailableText(OnUnavailable v)
{
    return v == OnUnavailable::Default ? L"Обычный маршрут" : L"Блокировать";
}

// --- значки программ ------------------------------------------------------------------------

void ResetIcons()
{
    const UINT dpi = GetDpiForWindow(g.main);
    const int cx = GetSystemMetricsForDpi(SM_CXSMICON, dpi);
    if (g.icons) {
        ImageList_Destroy(g.icons);
    }
    g.icons = ImageList_Create(cx, cx, ILC_COLOR32 | ILC_MASK, 8, 8);
    ListView_SetImageList(g.list, g.icons, LVSIL_SMALL);
}

int IconFor(const Rule& rule)
{
    const int cx = GetSystemMetricsForDpi(SM_CXSMICON, GetDpiForWindow(g.main));
    HICON icon = nullptr;
    if (IsPath(rule.app)) {
        const std::wstring path = Expand(rule.app);
        SHDefExtractIconW(path.c_str(), 0, 0, &icon, nullptr, static_cast<UINT>(cx));
    }
    if (!icon) {
        SHSTOCKICONINFO sii{};
        sii.cbSize = sizeof(sii);
        if (SUCCEEDED(SHGetStockIconInfo(SIID_APPLICATION, SHGSI_ICONLOCATION, &sii))) {
            SHDefExtractIconW(sii.szPath, sii.iIcon, 0, &icon, nullptr, static_cast<UINT>(cx));
        }
    }
    if (!icon) {
        return -1;
    }
    const int index = ImageList_AddIcon(g.icons, icon);
    DestroyIcon(icon);
    return index;
}

void SetWindowIcons()
{
    const UINT dpi = GetDpiForWindow(g.main);
    const auto load = [dpi](int metric) {
        const int cx = GetSystemMetricsForDpi(metric, dpi);
        return static_cast<HICON>(LoadImageW(g.instance, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON, cx, cx, 0));
    };
    HICON large = load(SM_CXICON);
    HICON little = load(SM_CXSMICON);
    SendMessageW(g.main, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(large));
    SendMessageW(g.main, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(little));
    if (g.bigIcon) {
        DestroyIcon(g.bigIcon);
    }
    if (g.smallIcon) {
        DestroyIcon(g.smallIcon);
    }
    g.bigIcon = large;
    g.smallIcon = little;
}

// --- список правил --------------------------------------------------------------------------

std::optional<size_t> SelectedRule()
{
    const int row = ListView_GetNextItem(g.list, -1, LVNI_SELECTED);
    if (row < 0) {
        return std::nullopt;
    }
    LVITEMW it{};
    it.mask = LVIF_PARAM;
    it.iItem = row;
    if (!ListView_GetItem(g.list, &it)) {
        return std::nullopt;
    }
    const auto index = static_cast<size_t>(it.lParam);
    return index < g.config.rules.size() ? std::optional(index) : std::nullopt;
}

void SetCell(int row, int column, const std::wstring& text)
{
    ListView_SetItemText(g.list, row, column, const_cast<wchar_t*>(text.c_str()));
}

// Колонки, зависящие от состояния интерфейса (обновляются по таймеру)
void UpdateRow(int row, const Rule& rule)
{
    const NetAdapter* a = AdapterByGuid(rule.adapter);
    SetCell(row, ColAdapter, a ? a->alias : rule.adapter);
    SetCell(row, ColState, AdapterState(a));
}

void UpdateButtons()
{
    const bool selected = SelectedRule().has_value();
    EnableWindow(GetDlgItem(g.main, IDC_ADD), !g.readOnly);
    EnableWindow(GetDlgItem(g.main, IDC_EDIT), selected && !g.readOnly);
    EnableWindow(GetDlgItem(g.main, IDC_REMOVE), selected && !g.readOnly);
    EnableWindow(GetDlgItem(g.main, IDC_LAUNCH), selected);
}

void FillList(std::optional<size_t> select)
{
    SendMessageW(g.list, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g.list);
    ResetIcons();
    for (size_t i = 0; i < g.config.rules.size(); ++i) {
        const Rule& r = g.config.rules[i];
        std::wstring name = FileNameOf(r.app);
        LVITEMW it{};
        it.mask = LVIF_TEXT | LVIF_PARAM | LVIF_IMAGE;
        it.iItem = static_cast<int>(i);
        it.lParam = static_cast<LPARAM>(i);
        it.pszText = name.data();
        it.iImage = IconFor(r);
        const int row = ListView_InsertItem(g.list, &it);
        UpdateRow(row, r);
        SetCell(row, ColPolicy, OnUnavailableText(r.onUnavailable));
        SetCell(row, ColPath, IsPath(r.app) ? r.app : L"(любой каталог)");
        if (select && *select == i) {
            ListView_SetItemState(g.list, row, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_EnsureVisible(g.list, row, FALSE);
        }
    }
    SendMessageW(g.list, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g.list, nullptr, TRUE);
    UpdateButtons();
}

void RefreshStates()
{
    LoadAdapters();
    const int rows = ListView_GetItemCount(g.list);
    for (int row = 0; row < rows; ++row) {
        LVITEMW it{};
        it.mask = LVIF_PARAM;
        it.iItem = row;
        if (ListView_GetItem(g.list, &it) && static_cast<size_t>(it.lParam) < g.config.rules.size()) {
            UpdateRow(row, g.config.rules[static_cast<size_t>(it.lParam)]);
        }
    }
}

std::wstring ConfigSummary()
{
    return std::format(L"Правил: {} · {}", g.config.rules.size(), g.configPath);
}

// Перечитать конфиг с диска (его могли изменить approute-config или другой экземпляр)
void Reload(bool showErrors)
{
    const auto keep = SelectedRule();
    LoadAdapters();
    std::wstring error;
    if (auto loaded = LoadConfig(g.configPath, &error)) {
        g.config = std::move(*loaded);
        g.readOnly = false;
        SetStatus(ConfigSummary());
    } else {
        g.config = {};
        g.readOnly = true;
        SetStatus(L"Конфиг не прочитан — правка отключена, файл не изменяется: " + error);
        if (showErrors) {
            Message(g.main, std::format(L"Не удалось прочитать {}:\n\n{}\n\nИсправьте файл или удалите его; "
                                        L"до этого правка правил отключена, чтобы не потерять ваши данные.",
                                        g.configPath, error),
                    MB_ICONWARNING);
        }
    }
    FillList(keep && *keep < g.config.rules.size() ? keep : std::nullopt);
}

bool Save(const std::wstring& done, std::optional<size_t> select)
{
    std::wstring error;
    if (!SaveConfig(g.configPath, g.config, &error)) {
        Message(g.main, L"Не удалось сохранить правила:\n\n" + error, MB_ICONERROR);
        Reload(false);
        return false;
    }
    FillList(select);
    SetStatus(done + L" · " + ConfigSummary());
    return true;
}

// --- диалог правила -------------------------------------------------------------------------

struct RuleDialog {
    Rule rule;
    std::optional<size_t> index;          // правка существующего правила
    std::vector<std::wstring> guids;      // GUID для каждого пункта списка интерфейсов
};

void FillCombo(HWND dlg, int id, std::initializer_list<const wchar_t*> items, int selected)
{
    HWND combo = GetDlgItem(dlg, id);
    for (const wchar_t* s : items) {
        SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(s));
    }
    SendMessageW(combo, CB_SETCURSEL, static_cast<WPARAM>(selected), 0);
}

int ComboSelection(HWND dlg, int id)
{
    return static_cast<int>(SendDlgItemMessageW(dlg, id, CB_GETCURSEL, 0, 0));
}

void UpdateAdapterInfo(HWND dlg, const RuleDialog& d)
{
    const int sel = ComboSelection(dlg, IDC_ADAPTER);
    std::wstring info;
    if (sel >= 0 && static_cast<size_t>(sel) < d.guids.size()) {
        if (const NetAdapter* a = AdapterByGuid(d.guids[static_cast<size_t>(sel)])) {
            const std::wstring v4 = FirstAddress(*a, AF_INET);
            const std::wstring v6 = FirstAddress(*a, AF_INET6);
            info = AdapterState(a);
            info += L" · IPv4: " + (v4.empty() ? std::wstring(L"нет") : v4);
            info += L" · IPv6: " + (v6.empty() ? std::wstring(L"нет") : v6);
        } else {
            info = L"Интерфейса сейчас нет — правило применится, когда он появится.";
        }
    }
    SetDlgItemTextW(dlg, IDC_ADAPTER_INFO, info.c_str());
}

void InitRuleDialog(HWND dlg, RuleDialog& d)
{
    SetWindowTextW(dlg, d.index ? L"Изменить правило" : L"Новое правило");
    SetDlgItemTextW(dlg, IDC_APP, d.rule.app.c_str());

    HWND combo = GetDlgItem(dlg, IDC_ADAPTER);
    int selected = -1;
    if (!d.rule.adapter.empty() && !AdapterByGuid(d.rule.adapter)) {
        // Интерфейс правила сейчас отсутствует (VPN не подключён) — сохраняем выбор
        const std::wstring text = L"Нет в системе: " + d.rule.adapter;
        SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(text.c_str()));
        d.guids.push_back(d.rule.adapter);
        selected = 0;
    }
    for (const NetAdapter* a : SortedAdapters()) {
        const std::wstring text = AdapterComboText(*a);
        SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(text.c_str()));
        d.guids.push_back(GuidToString(a->guid));
        if (EqualsIgnoreCase(d.guids.back(), d.rule.adapter)) {
            selected = static_cast<int>(d.guids.size() - 1);
        }
    }
    SendMessageW(combo, CB_SETCURSEL, static_cast<WPARAM>(selected), 0);

    FillCombo(dlg, IDC_ONUNAVAIL, {L"Блокировать соединения и DNS", L"Пустить маршрутом по умолчанию"},
              d.rule.onUnavailable == OnUnavailable::Default ? 1 : 0);
    FillCombo(dlg, IDC_DNS, {L"Через интерфейс правила", L"Системный резолвер"},
              d.rule.dns == DnsMode::System ? 1 : 0);
    FillCombo(dlg, IDC_IPV6, {L"Как при недоступном интерфейсе", L"Блокировать", L"Маршрутом по умолчанию"},
              d.rule.ipv6 == Ipv6Mode::Block ? 1 : d.rule.ipv6 == Ipv6Mode::Default ? 2 : 0);
    CheckDlgButton(dlg, IDC_CHILDREN, d.rule.includeChildren ? BST_CHECKED : BST_UNCHECKED);
    UpdateAdapterInfo(dlg, d);
}

void BrowseProgram(HWND dlg)
{
    std::wstring current = CleanAppPath(WindowText(GetDlgItem(dlg, IDC_APP)));
    std::vector<wchar_t> file(32768, L'\0');
    if (IsPath(current)) {
        current = Expand(current);
        current.copy(file.data(), std::min(current.size(), file.size() - 1));
    }
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = dlg;
    ofn.lpstrFilter = L"Программы (*.exe)\0*.exe\0Все файлы (*.*)\0*.*\0";
    ofn.lpstrFile = file.data();
    ofn.nMaxFile = static_cast<DWORD>(file.size());
    ofn.lpstrTitle = L"Программа для правила";
    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_NOCHANGEDIR |
                OFN_DONTADDTORECENT;
    if (GetOpenFileNameW(&ofn)) {
        SetDlgItemTextW(dlg, IDC_APP, file.data());
    }
}

// Собрать правило из полей; false — ошибка показана, диалог остаётся открытым
bool AcceptRule(HWND dlg, RuleDialog& d)
{
    Rule r = d.rule;
    r.app = CleanAppPath(WindowText(GetDlgItem(dlg, IDC_APP)));
    const int sel = ComboSelection(dlg, IDC_ADAPTER);
    r.adapter = sel >= 0 && static_cast<size_t>(sel) < d.guids.size() ? d.guids[static_cast<size_t>(sel)] : L"";
    r.onUnavailable = ComboSelection(dlg, IDC_ONUNAVAIL) == 1 ? OnUnavailable::Default : OnUnavailable::Block;
    r.dns = ComboSelection(dlg, IDC_DNS) == 1 ? DnsMode::System : DnsMode::Adapter;
    const int v6 = ComboSelection(dlg, IDC_IPV6);
    r.ipv6 = v6 == 1 ? Ipv6Mode::Block : v6 == 2 ? Ipv6Mode::Default : Ipv6Mode::Follow;
    r.includeChildren = IsDlgButtonChecked(dlg, IDC_CHILDREN) == BST_CHECKED;

    if (const auto error = ValidateRule(r)) {
        Message(dlg, *error, MB_ICONWARNING);
        SetFocus(GetDlgItem(dlg, r.app.empty() ? IDC_APP : IDC_ADAPTER));
        return false;
    }
    if (const auto dup = FindDuplicateRule(g.config, r.app, d.index)) {
        Message(dlg, std::format(L"Правило для «{}» уже есть. Измените его вместо создания нового.",
                                 g.config.rules[*dup].app),
                MB_ICONWARNING);
        return false;
    }
    if (IsPath(r.app) && GetFileAttributesW(Expand(r.app).c_str()) == INVALID_FILE_ATTRIBUTES &&
        Message(dlg, L"Файл программы не найден. Всё равно сохранить правило?", MB_ICONQUESTION | MB_YESNO) != IDYES) {
        return false;
    }
    d.rule = std::move(r);
    return true;
}

INT_PTR CALLBACK RuleDialogProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    auto* d = reinterpret_cast<RuleDialog*>(GetWindowLongPtrW(dlg, DWLP_USER));
    switch (msg) {
    case WM_INITDIALOG:
        SetWindowLongPtrW(dlg, DWLP_USER, lp);
        InitRuleDialog(dlg, *reinterpret_cast<RuleDialog*>(lp));
        return TRUE;
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_BROWSE:
            BrowseProgram(dlg);
            return TRUE;
        case IDC_ADAPTER:
            if (HIWORD(wp) == CBN_SELCHANGE && d) {
                UpdateAdapterInfo(dlg, *d);
            }
            return TRUE;
        case IDOK:
            if (d && AcceptRule(dlg, *d)) {
                EndDialog(dlg, IDOK);
            }
            return TRUE;
        case IDCANCEL:
            EndDialog(dlg, IDCANCEL);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

std::optional<Rule> EditRule(const Rule& initial, std::optional<size_t> index)
{
    LoadAdapters();
    RuleDialog d{initial, index, {}};
    if (DialogBoxParamW(g.instance, MAKEINTRESOURCEW(IDD_RULE), g.main, RuleDialogProc,
                        reinterpret_cast<LPARAM>(&d)) != IDOK) {
        return std::nullopt;
    }
    return d.rule;
}

// --- действия главного окна -----------------------------------------------------------------

void AddRule()
{
    if (g.readOnly) {
        return;
    }
    if (auto rule = EditRule(Rule{}, std::nullopt)) {
        g.config.rules.push_back(std::move(*rule));
        Save(L"Правило добавлено", g.config.rules.size() - 1);
    }
}

void EditSelected()
{
    const auto index = SelectedRule();
    if (!index || g.readOnly) {
        return;
    }
    if (auto rule = EditRule(g.config.rules[*index], index)) {
        g.config.rules[*index] = std::move(*rule);
        Save(L"Правило изменено", index);
    }
}

void RemoveSelected()
{
    const auto index = SelectedRule();
    if (!index || g.readOnly) {
        return;
    }
    const std::wstring app = g.config.rules[*index].app;
    std::wstring question = std::format(L"Удалить правило для «{}»?", FileNameOf(app));
    if (IsPath(app)) {
        question += L"\n\n" + app;
    }
    if (Message(g.main, question, MB_ICONQUESTION | MB_YESNO) != IDYES) {
        return;
    }
    g.config.rules.erase(g.config.rules.begin() + static_cast<std::ptrdiff_t>(*index));
    std::optional<size_t> next;
    if (!g.config.rules.empty()) {
        next = std::min(*index, g.config.rules.size() - 1);
    }
    Save(L"Правило удалено", next);
}

void LaunchSelected()
{
    const auto index = SelectedRule();
    if (!index) {
        return;
    }
    const Rule& rule = g.config.rules[*index];
    LaunchRequest request = RequestForRule(rule, CommandLineForApp(rule.app));
    request.inheritStdHandles = false;

    SetCursor(LoadCursorW(nullptr, IDC_WAIT));
    const LaunchResult result = LaunchWithRule(request);
    if (!result.Ok()) {
        Message(g.main, result.message, MB_ICONWARNING);
        SetStatus(L"Не запущено: " + result.message);
        return;
    }
    CloseHandle(result.process);
    const NetAdapter* a = AdapterByGuid(rule.adapter);
    SetStatus(std::format(L"Запущено: {} (PID {}{}) — трафик через «{}»", FileNameOf(result.image), result.pid,
                          result.is32Bit ? L", 32-бит" : L"", a ? a->alias : rule.adapter));
}

// --- раскладка главного окна ----------------------------------------------------------------

RECT DialogUnits(int left, int top, int right, int bottom)
{
    RECT r{left, top, right, bottom};
    MapDialogRect(g.main, &r);
    return r;
}

void Layout()
{
    RECT client{};
    GetClientRect(g.main, &client);
    const RECT u = DialogUnits(7, 4, 53, 14);    // поле, промежуток, ширина и высота кнопки
    const int margin = u.left;
    const int gap = u.top;
    const int bw = u.right;
    const int bh = u.bottom;
    const int statusH = DialogUnits(0, 0, 0, 10).bottom;

    const int buttonsX = client.right - margin - bw;
    const int listW = std::max(0, buttonsX - gap * 2 - margin);
    const int listH = std::max(0, static_cast<int>(client.bottom) - margin * 2 - statusH - gap);

    HDWP dwp = BeginDeferWindowPos(8);
    auto place = [&](int id, int x, int y, int w, int h) {
        dwp = DeferWindowPos(dwp, GetDlgItem(g.main, id), nullptr, x, y, w, h, SWP_NOZORDER | SWP_NOACTIVATE);
    };
    place(IDC_RULES, margin, margin, listW, listH);
    int y = margin;
    for (int id : {IDC_ADD, IDC_EDIT, IDC_REMOVE}) {
        place(id, buttonsX, y, bw, bh);
        y += bh + gap;
    }
    y += gap * 3;
    place(IDC_LAUNCH, buttonsX, y, bw, bh);
    y += bh + gap * 4;
    place(IDC_REFRESH, buttonsX, y, bw, bh);
    place(IDC_STATUS, margin, client.bottom - margin - statusH, std::max(0, static_cast<int>(client.right) - margin * 2), statusH);
    EndDeferWindowPos(dwp);

    // Колонки — пропорционально ширине списка
    RECT lc{};
    GetClientRect(g.list, &lc);
    const int w = std::max(0, static_cast<int>(lc.right) - GetSystemMetricsForDpi(SM_CXVSCROLL, GetDpiForWindow(g.main)));
    const int widths[ColCount] = {w * 17 / 100, w * 18 / 100, w * 13 / 100, w * 22 / 100, 0};
    int used = 0;
    for (int c = 0; c < ColPath; ++c) {
        ListView_SetColumnWidth(g.list, c, widths[c]);
        used += widths[c];
    }
    const int pathWidth = std::max(static_cast<int>(DialogUnits(0, 0, 60, 0).right), w - used);
    ListView_SetColumnWidth(g.list, ColPath, pathWidth);
}

void InitMain()
{
    g.list = GetDlgItem(g.main, IDC_RULES);
    SetWindowTheme(g.list, L"Explorer", nullptr);
    ListView_SetExtendedListViewStyle(g.list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);

    const wchar_t* titles[ColCount] = {L"Программа", L"Интерфейс", L"Состояние", L"Если недоступен", L"Путь"};
    for (int c = 0; c < ColCount; ++c) {
        LVCOLUMNW col{};
        col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_WIDTH;
        col.pszText = const_cast<wchar_t*>(titles[c]);
        col.iSubItem = c;
        col.cx = 100;
        ListView_InsertColumn(g.list, c, &col);
    }
    SetWindowIcons();
    Layout();
    Reload(true);
    SetTimer(g.main, kStatusTimer, kStatusTimerMs, nullptr);
}

INT_PTR CALLBACK MainDialogProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_INITDIALOG:
        g.main = dlg;
        InitMain();
        return TRUE;
    case WM_SIZE:
        Layout();
        return TRUE;
    case WM_GETMINMAXINFO: {
        if (g.main) {
            const RECT minClient = DialogUnits(0, 0, 300, 150);
            RECT r{0, 0, minClient.right, minClient.bottom};
            AdjustWindowRectExForDpi(&r, static_cast<DWORD>(GetWindowLongPtrW(dlg, GWL_STYLE)), FALSE,
                                     static_cast<DWORD>(GetWindowLongPtrW(dlg, GWL_EXSTYLE)), GetDpiForWindow(dlg));
            auto* info = reinterpret_cast<MINMAXINFO*>(lp);
            info->ptMinTrackSize = {r.right - r.left, r.bottom - r.top};
        }
        return TRUE;
    }
    case WM_DPICHANGED:
        // Размер и шрифты диалога пересчитывает система (PerMonitorV2); значки — после неё
        PostMessageW(dlg, kMsgDpiChanged, 0, 0);
        return FALSE;
    case kMsgDpiChanged:
        SetWindowIcons();
        FillList(SelectedRule());
        Layout();
        return TRUE;
    case WM_TIMER:
        if (wp == kStatusTimer) {
            RefreshStates();
        }
        return TRUE;
    case WM_NOTIFY: {
        const auto* hdr = reinterpret_cast<const NMHDR*>(lp);
        if (hdr->idFrom != IDC_RULES) {
            break;
        }
        switch (hdr->code) {
        case NM_DBLCLK:
            EditSelected();
            return TRUE;
        case LVN_ITEMCHANGED:
            UpdateButtons();
            return TRUE;
        case LVN_KEYDOWN:
            if (reinterpret_cast<const NMLVKEYDOWN*>(lp)->wVKey == VK_DELETE) {
                RemoveSelected();
            }
            return TRUE;
        }
        break;
    }
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_ADD:
            AddRule();
            return TRUE;
        case IDC_EDIT:
            EditSelected();
            return TRUE;
        case IDC_REMOVE:
            RemoveSelected();
            return TRUE;
        case IDC_LAUNCH:
            LaunchSelected();
            return TRUE;
        case IDC_REFRESH:
            Reload(true);
            return TRUE;
        case IDOK:   // Enter в списке — правка
            if (GetFocus() == g.list) {
                EditSelected();
            }
            return TRUE;
        case IDCANCEL:   // Esc не закрывает главное окно
            return TRUE;
        }
        break;
    case WM_CLOSE:
        DestroyWindow(dlg);
        return TRUE;
    case WM_DESTROY:
        KillTimer(dlg, kStatusTimer);
        PostQuitMessage(0);
        return TRUE;
    }
    return FALSE;
}

std::wstring ParseConfigArgument()
{
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    std::wstring path;
    for (int i = 1; argv && i + 1 < argc; ++i) {
        if (std::wstring_view(argv[i]) == L"--config") {
            path = argv[i + 1];
            break;
        }
    }
    if (argv) {
        LocalFree(argv);
    }
    return path.empty() ? DefaultConfigPath() : path;
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show)
{
    g.instance = instance;
    g.configPath = ParseConfigArgument();

    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icc);

    HWND main = CreateDialogParamW(instance, MAKEINTRESOURCEW(IDD_MAIN), nullptr, MainDialogProc, 0);
    if (!main) {
        MessageBoxW(nullptr, Win32ErrorMessage(GetLastError()).c_str(), L"AppRoute", MB_ICONERROR);
        return 1;
    }
    ShowWindow(main, show);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(main, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    if (g.icons) {
        ImageList_Destroy(g.icons);
    }
    return static_cast<int>(msg.wParam);
}
