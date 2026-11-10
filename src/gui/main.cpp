// approute-gui — главное окно AppRoute (issues #12, #13, #14, #15, #37).
//
// Список правил «программа → интерфейс», добавление, правка и удаление правил, выбор программы
// и интерфейса из подключённых адаптеров, запуск программы по правилу. Правила хранятся в том же
// config.json, что использует approute-config и approute-run.
//
// Вся логика — в core (Config, Launcher, NetAdapters); здесь только окна.
//
//   approute-gui [--config FILE]
//   approute-gui [--config FILE] --run PROGRAM [-- ARGS...]   — запуск по правилу без окна (ярлыки, #13)

#include "resource.h"

#include "core/Config.h"
#include "core/ConfigPolicy.h"
#include "core/ManagerPipe.h"
#include "core/InstalledApps.h"
#include "core/Launcher.h"
#include "core/NetAdapters.h"
#include "core/PrimarySwitch.h"
#include "core/RouteManager.h"
#include "core/Shortcuts.h"
#include "core/Util.h"

#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <uxtheme.h>

#include <algorithm>
#include <format>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using namespace approute;

namespace {

constexpr UINT_PTR kStatusTimer = 1;
constexpr UINT kStatusTimerMs = 3000;    // состояние интерфейсов меняется при (пере)подключении VPN
constexpr UINT kMsgDpiChanged = WM_APP + 1;
constexpr UINT kMsgTray = WM_APP + 3;
constexpr UINT kTrayId = 1;
const UINT kMsgTaskbarCreated = RegisterWindowMessageW(L"TaskbarCreated");

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
    std::vector<std::wstring> primaryGuids;   // пункты переключателя: "auto" или GUID
    bool trayAdded = false;
    bool trayHintShown = false;               // подсказка «AppRoute в области уведомлений»
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

// Имя интерфейса для показа: текущее, из истории (VPN не подключён) или GUID
std::wstring AdapterLabel(const std::wstring& guid)
{
    if (const NetAdapter* a = AdapterByGuid(guid)) {
        return a->alias;
    }
    if (const KnownAdapter* k = FindKnownAdapter(g.config, guid); k && !k->name.empty()) {
        return k->name;
    }
    return guid;
}

// Запомнить интерфейс правила в истории конфига (#37)
void RememberRuleAdapter(const Rule& rule)
{
    if (const NetAdapter* a = AdapterByGuid(rule.adapter)) {
        RememberAdapter(g.config, {rule.adapter, a->alias, a->description});
    } else if (const KnownAdapter* k = FindKnownAdapter(g.config, rule.adapter)) {
        RememberAdapter(g.config, KnownAdapter(*k));
    }
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
    SetCell(row, ColAdapter, AdapterLabel(rule.adapter));
    SetCell(row, ColState, AdapterState(a));
}

void UpdateButtons()
{
    const bool selected = SelectedRule().has_value();
    EnableWindow(GetDlgItem(g.main, IDC_ADD), !g.readOnly);
    EnableWindow(GetDlgItem(g.main, IDC_EDIT), selected && !g.readOnly);
    EnableWindow(GetDlgItem(g.main, IDC_REMOVE), selected && !g.readOnly);
    EnableWindow(GetDlgItem(g.main, IDC_LAUNCH), selected);
    EnableWindow(GetDlgItem(g.main, IDC_SHORTCUT), selected);
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

void FillPrimaryCombo();

void RefreshStates()
{
    LoadAdapters();
    FillPrimaryCombo();
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
    FillPrimaryCombo();
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
        const std::wstring text = AdapterLabel(d.rule.adapter) + L" (сейчас нет в системе)";
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
    // Интерфейсы из истории, которых сейчас нет (отключённый VPN)
    for (const KnownAdapter& k : g.config.knownAdapters) {
        if (AdapterByGuid(k.id) || EqualsIgnoreCase(k.id, d.rule.adapter)) {
            continue;
        }
        const std::wstring text = (k.name.empty() ? k.id : k.name) + L" (сейчас нет в системе)";
        SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(text.c_str()));
        d.guids.push_back(k.id);
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
    ofn.lpstrFilter = L"Программы и ярлыки (*.exe; *.lnk)\0*.exe;*.lnk\0Все файлы (*.*)\0*.*\0";
    ofn.lpstrFile = file.data();
    ofn.nMaxFile = static_cast<DWORD>(file.size());
    ofn.lpstrTitle = L"Программа или ярлык для правила";
    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_NOCHANGEDIR |
                OFN_DONTADDTORECENT | OFN_NODEREFERENCELINKS;
    if (!GetOpenFileNameW(&ofn)) {
        return;
    }
    std::wstring error;
    if (const auto program = ProgramFromFile(file.data(), &error)) {
        SetDlgItemTextW(dlg, IDC_APP, program->c_str());
    } else {
        Message(dlg, error, MB_ICONWARNING);
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

// --- мастер «Новое правило» (#37) -----------------------------------------------------------
//
// Три шага: программа (из установленных или файл/ярлык) → интерфейс (подключённые и из
// истории) → что делать, если интерфейс недоступен. Остальное — значения по умолчанию.

constexpr UINT kMsgAppsLoaded = WM_APP + 2;

struct LoadedApp {
    InstalledApp app;
    int icon = -1;     // индекс в системном списке значков
};

struct Wizard {
    Rule rule;
    HWND sheet = nullptr;
    std::vector<LoadedApp> apps;
    bool appsLoaded = false;
    std::vector<std::wstring> adapterGuids;   // lParam строк списка интерфейсов
    bool finished = false;
};

int SystemIconIndex(const std::wstring& path)
{
    SHFILEINFOW sfi{};
    return SHGetFileInfoW(path.c_str(), 0, &sfi, sizeof(sfi), SHGFI_SYSICONINDEX | SHGFI_SMALLICON)
               ? sfi.iIcon : -1;
}

HIMAGELIST SystemSmallIcons()
{
    SHFILEINFOW sfi{};
    return reinterpret_cast<HIMAGELIST>(SHGetFileInfoW(L".exe", FILE_ATTRIBUTE_NORMAL, &sfi, sizeof(sfi),
                                                       SHGFI_SYSICONINDEX | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES));
}

// Список программ собирается в фоне: сотни ярлыков и значков — заметная пауза
void LoadAppsAsync(HWND page)
{
    std::thread([page] {
        CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        auto* result = new std::vector<LoadedApp>();
        for (auto& app : EnumerateInstalledApps()) {
            const int icon = SystemIconIndex(app.path);
            result->push_back({std::move(app), icon});
        }
        CoUninitialize();
        if (!PostMessageW(page, kMsgAppsLoaded, 0, reinterpret_cast<LPARAM>(result))) {
            delete result;   // мастер уже закрыт
        }
    }).detach();
}


// Многострочная подпись: строки разбиваются по пробелам заранее, по ширине элемента. DrawText
// в некоторых сборках Windows 11 переносит кириллицу посреди слова («траф|ик»).
void WrapLabel(HWND dlg, int id)
{
    HWND label = GetDlgItem(dlg, id);
    const std::wstring text = WindowText(label);
    RECT rc{};
    GetClientRect(label, &rc);
    HDC dc = GetDC(label);
    const HGDIOBJ old = SelectObject(dc, reinterpret_cast<HGDIOBJ>(SendMessageW(label, WM_GETFONT, 0, 0)));
    const auto fits = [&](const std::wstring& s) {
        SIZE size{};
        GetTextExtentPoint32W(dc, s.c_str(), static_cast<int>(s.size()), &size);
        return size.cx <= rc.right - 2;
    };
    std::wstring out;
    std::wstring line;
    size_t pos = 0;
    while (pos <= text.size()) {
        const size_t end = std::min(text.find(L' ', pos), text.size());
        const std::wstring word = text.substr(pos, end - pos);
        const std::wstring candidate = line.empty() ? word : line + L" " + word;
        if (!line.empty() && !fits(candidate)) {
            out += line + L"\n";
            line = word;
        } else {
            line = candidate;
        }
        pos = end + 1;
    }
    out += line;
    SelectObject(dc, old);
    ReleaseDC(label, dc);
    SetWindowTextW(label, out.c_str());
}

Wizard* PageWizard(HWND page)
{
    return reinterpret_cast<Wizard*>(GetWindowLongPtrW(page, DWLP_USER));
}

Wizard* InitPage(HWND page, LPARAM lp)
{
    auto* w = reinterpret_cast<Wizard*>(reinterpret_cast<const PROPSHEETPAGEW*>(lp)->lParam);
    SetWindowLongPtrW(page, DWLP_USER, reinterpret_cast<LONG_PTR>(w));
    w->sheet = GetParent(page);   // окно мастера (в Aero Wizard — внутреннее, не верхнего уровня)
    return w;
}

void SetupWizardList(HWND list, std::initializer_list<std::pair<const wchar_t*, int>> columns)
{
    SetWindowTheme(list, L"Explorer", nullptr);
    ListView_SetExtendedListViewStyle(list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
    RECT rc{};
    GetClientRect(list, &rc);
    const int width = rc.right - GetSystemMetricsForDpi(SM_CXVSCROLL, GetDpiForWindow(list));
    int c = 0;
    for (const auto& [title, percent] : columns) {
        LVCOLUMNW col{};
        col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_WIDTH;
        col.pszText = const_cast<wchar_t*>(title);
        col.iSubItem = c;
        col.cx = width * percent / 100;
        ListView_InsertColumn(list, c++, &col);
    }
}

int SelectedParam(HWND list)
{
    const int row = ListView_GetNextItem(list, -1, LVNI_SELECTED);
    if (row < 0) {
        return -1;
    }
    LVITEMW it{};
    it.mask = LVIF_PARAM;
    it.iItem = row;
    return ListView_GetItem(list, &it) ? static_cast<int>(it.lParam) : -1;
}

// Результат уведомления мастера (PSN_*): 0 — продолжить, -1 — остаться на странице
void NotifyResult(HWND page, LONG_PTR result)
{
    SetWindowLongPtrW(page, DWLP_MSGRESULT, result);
}

void StayOnPage(HWND page)
{
    NotifyResult(page, -1);
}

// Шаг 1: программа

void FillApps(HWND page, Wizard& w)
{
    HWND list = GetDlgItem(page, IDC_WAPP_LIST);
    const std::wstring query = WindowText(GetDlgItem(page, IDC_WAPP_SEARCH));
    SendMessageW(list, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(list);
    int row = 0;
    for (size_t i = 0; i < w.apps.size(); ++i) {
        const LoadedApp& a = w.apps[i];
        if (!MatchesAppFilter(a.app, query)) {
            continue;
        }
        LVITEMW it{};
        it.mask = LVIF_TEXT | LVIF_PARAM | LVIF_IMAGE;
        it.iItem = row;
        it.lParam = static_cast<LPARAM>(i);
        it.pszText = const_cast<wchar_t*>(a.app.name.c_str());
        it.iImage = a.icon;
        const int inserted = ListView_InsertItem(list, &it);
        ListView_SetItemText(list, inserted, 1, const_cast<wchar_t*>(a.app.path.c_str()));
        if (EqualsIgnoreCase(a.app.path, w.rule.app)) {
            ListView_SetItemState(list, inserted, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_EnsureVisible(list, inserted, FALSE);
        }
        ++row;
    }
    SendMessageW(list, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(list, nullptr, TRUE);
}

void UpdateAppStep(HWND page, Wizard& w)
{
    std::wstring chosen;
    if (!w.rule.app.empty()) {
        chosen = L"Выбрано: " + w.rule.app;
    } else if (!w.appsLoaded) {
        chosen = L"Загружается список программ…";
    } else if (w.apps.empty()) {
        chosen = L"Установленные программы не найдены — укажите файл программы или ярлык.";
    }
    SetDlgItemTextW(page, IDC_WAPP_CHOSEN, chosen.c_str());
    PropSheet_SetWizButtons(w.sheet, w.rule.app.empty() ? 0 : PSWIZB_NEXT);
}

void BrowseForApp(HWND page, Wizard& w)
{
    std::vector<wchar_t> file(32768, L'\0');
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = page;
    ofn.lpstrFilter = L"Программы и ярлыки (*.exe; *.lnk)\0*.exe;*.lnk\0Все файлы (*.*)\0*.*\0";
    ofn.lpstrFile = file.data();
    ofn.nMaxFile = static_cast<DWORD>(file.size());
    ofn.lpstrTitle = L"Программа или ярлык для правила";
    // Ярлык разбираем сами: так работают и «объявленные» ярлыки установщика MSI
    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_NOCHANGEDIR |
                OFN_DONTADDTORECENT | OFN_NODEREFERENCELINKS;
    if (!GetOpenFileNameW(&ofn)) {
        return;
    }
    std::wstring error;
    const auto program = ProgramFromFile(file.data(), &error);
    if (!program) {
        Message(page, error, MB_ICONWARNING);
        return;
    }
    const bool listed = std::any_of(w.apps.begin(), w.apps.end(),
                                    [&](const LoadedApp& a) { return EqualsIgnoreCase(a.app.path, *program); });
    if (!listed) {
        std::wstring name = FileNameOf(*program);
        w.apps.insert(w.apps.begin(), {{name, *program}, SystemIconIndex(*program)});
    }
    w.rule.app = *program;
    SetDlgItemTextW(page, IDC_WAPP_SEARCH, L"");   // показать выбранную в полном списке
    FillApps(page, w);
    UpdateAppStep(page, w);
}

INT_PTR CALLBACK WizardAppPage(HWND page, UINT msg, WPARAM wp, LPARAM lp)
{
    Wizard* w = PageWizard(page);
    switch (msg) {
    case WM_INITDIALOG: {
        w = InitPage(page, lp);
        HWND list = GetDlgItem(page, IDC_WAPP_LIST);
        SetupWizardList(list, {{L"Программа", 40}, {L"Расположение", 60}});
        ListView_SetImageList(list, SystemSmallIcons(), LVSIL_SMALL);
        SendDlgItemMessageW(page, IDC_WAPP_SEARCH, EM_SETCUEBANNER, TRUE,
                            reinterpret_cast<LPARAM>(L"Поиск среди установленных программ"));
        LoadAppsAsync(page);
        return TRUE;
    }
    case kMsgAppsLoaded: {
        std::unique_ptr<std::vector<LoadedApp>> loaded(reinterpret_cast<std::vector<LoadedApp>*>(lp));
        for (auto& a : *loaded) {   // выбранная через «Указать файл…» остаётся
            const bool listed = std::any_of(w->apps.begin(), w->apps.end(), [&](const LoadedApp& x) {
                return EqualsIgnoreCase(x.app.path, a.app.path);
            });
            if (!listed) {
                w->apps.push_back(std::move(a));
            }
        }
        w->appsLoaded = true;
        FillApps(page, *w);
        UpdateAppStep(page, *w);
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDC_WAPP_SEARCH && HIWORD(wp) == EN_CHANGE && w) {
            FillApps(page, *w);
            return TRUE;
        }
        if (LOWORD(wp) == IDC_WAPP_BROWSE && w) {
            BrowseForApp(page, *w);
            return TRUE;
        }
        break;
    case WM_NOTIFY: {
        const auto* hdr = reinterpret_cast<const NMHDR*>(lp);
        if (!w) {
            break;
        }
        if (hdr->idFrom == IDC_WAPP_LIST && hdr->code == LVN_ITEMCHANGED) {
            const auto* change = reinterpret_cast<const NMLISTVIEW*>(lp);
            if ((change->uNewState & LVIS_SELECTED) && !(change->uOldState & LVIS_SELECTED)) {
                const int index = static_cast<int>(change->lParam);
                if (index >= 0 && static_cast<size_t>(index) < w->apps.size()) {
                    w->rule.app = w->apps[static_cast<size_t>(index)].app.path;
                    UpdateAppStep(page, *w);
                }
            }
            return TRUE;
        }
        if (hdr->idFrom == IDC_WAPP_LIST && hdr->code == NM_DBLCLK && !w->rule.app.empty()) {
            PropSheet_PressButton(w->sheet, PSBTN_NEXT);
            return TRUE;
        }
        switch (hdr->code) {
        case PSN_SETACTIVE:
            UpdateAppStep(page, *w);
            NotifyResult(page, 0);
            return TRUE;
        case PSN_WIZNEXT:
            NotifyResult(page, 0);
            if (const auto dup = FindDuplicateRule(g.config, w->rule.app)) {
                Message(page, std::format(L"Правило для «{}» уже есть. Чтобы поменять интерфейс, выберите его "
                                          L"в списке правил и нажмите «Изменить…».",
                                          FileNameOf(g.config.rules[*dup].app)),
                        MB_ICONINFORMATION);
                StayOnPage(page);
            }
            return TRUE;
        }
        break;
    }
    }
    return FALSE;
}

// Шаг 2: интерфейс

enum AdapterGroup { GroupUp = 1, GroupDown, GroupKnown };

void AddGroup(HWND list, int id, const wchar_t* title)
{
    LVGROUP group{};
    group.cbSize = sizeof(group);
    group.mask = LVGF_HEADER | LVGF_GROUPID;
    group.pszHeader = const_cast<wchar_t*>(title);
    group.iGroupId = id;
    ListView_InsertGroup(list, -1, &group);
}

void AddAdapterRow(HWND list, Wizard& w, int group, const std::wstring& guid, const std::wstring& name,
                   const std::wstring& state, const std::wstring& address, const std::wstring& description)
{
    w.adapterGuids.push_back(guid);
    LVITEMW it{};
    it.mask = LVIF_TEXT | LVIF_PARAM | LVIF_GROUPID;
    it.iItem = static_cast<int>(w.adapterGuids.size());
    it.lParam = static_cast<LPARAM>(w.adapterGuids.size() - 1);
    it.iGroupId = group;
    it.pszText = const_cast<wchar_t*>(name.c_str());
    const int row = ListView_InsertItem(list, &it);
    ListView_SetItemText(list, row, 1, const_cast<wchar_t*>(state.c_str()));
    ListView_SetItemText(list, row, 2, const_cast<wchar_t*>(address.c_str()));
    ListView_SetItemText(list, row, 3, const_cast<wchar_t*>(description.c_str()));
    if (EqualsIgnoreCase(guid, w.rule.adapter)) {
        ListView_SetItemState(list, row, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(list, row, FALSE);
    }
}

void FillAdapters(HWND page, Wizard& w)
{
    LoadAdapters();
    HWND list = GetDlgItem(page, IDC_WIF_LIST);
    if (w.rule.adapter.empty()) {
        // Последний выбранный раньше интерфейс, если он сейчас есть в системе
        for (const KnownAdapter& k : g.config.knownAdapters) {
            if (AdapterByGuid(k.id)) {
                w.rule.adapter = k.id;
                break;
            }
        }
    }
    SendMessageW(list, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(list);
    ListView_RemoveAllGroups(list);
    w.adapterGuids.clear();
    AddGroup(list, GroupUp, L"Подключены");
    AddGroup(list, GroupDown, L"Не подключены");
    AddGroup(list, GroupKnown, L"Использовались раньше, сейчас нет в системе");
    for (const NetAdapter* a : SortedAdapters()) {
        std::wstring address;   // у отключённых — только автоматический 169.254.x.x, он не нужен
        if (a->IsUp()) {
            address = FirstAddress(*a, AF_INET);
            if (address.empty()) {
                address = FirstAddress(*a, AF_INET6);
            }
        }
        AddAdapterRow(list, w, a->IsUp() ? GroupUp : GroupDown, GuidToString(a->guid), a->alias, AdapterState(a),
                      address, a->description);
    }
    for (const KnownAdapter& k : g.config.knownAdapters) {
        if (!AdapterByGuid(k.id)) {
            AddAdapterRow(list, w, GroupKnown, k.id, k.name.empty() ? k.id : k.name, AdapterState(nullptr), L"",
                          k.description);
        }
    }
    SendMessageW(list, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(list, nullptr, TRUE);
}

void UpdateAdapterStep(HWND page, Wizard& w)
{
    std::wstring info;
    if (!w.rule.adapter.empty()) {
        if (const NetAdapter* a = AdapterByGuid(w.rule.adapter)) {
            const std::wstring v4 = FirstAddress(*a, AF_INET);
            const std::wstring v6 = FirstAddress(*a, AF_INET6);
            info = std::format(L"{} · IPv4: {} · IPv6: {}", AdapterState(a), v4.empty() ? L"нет" : v4,
                               v6.empty() ? L"нет" : v6);
        } else {
            info = L"Сейчас его нет в системе — правило заработает, когда он появится.";
        }
    }
    SetDlgItemTextW(page, IDC_WIF_INFO, info.c_str());
    PropSheet_SetWizButtons(w.sheet, PSWIZB_BACK | (w.rule.adapter.empty() ? 0 : PSWIZB_NEXT));
}

INT_PTR CALLBACK WizardAdapterPage(HWND page, UINT msg, WPARAM, LPARAM lp)
{
    Wizard* w = PageWizard(page);
    switch (msg) {
    case WM_INITDIALOG: {
        InitPage(page, lp);
        HWND list = GetDlgItem(page, IDC_WIF_LIST);
        SetupWizardList(list, {{L"Интерфейс", 28}, {L"Состояние", 18}, {L"Адрес", 20}, {L"Описание", 34}});
        ListView_EnableGroupView(list, TRUE);
        WrapLabel(page, IDC_WIF_HINT);
        return TRUE;
    }
    case WM_NOTIFY: {
        const auto* hdr = reinterpret_cast<const NMHDR*>(lp);
        if (!w) {
            break;
        }
        if (hdr->idFrom == IDC_WIF_LIST && hdr->code == LVN_ITEMCHANGED) {
            const auto* change = reinterpret_cast<const NMLISTVIEW*>(lp);
            if ((change->uNewState & LVIS_SELECTED) && !(change->uOldState & LVIS_SELECTED)) {
                const auto index = static_cast<size_t>(change->lParam);
                if (index < w->adapterGuids.size()) {
                    w->rule.adapter = w->adapterGuids[index];
                    UpdateAdapterStep(page, *w);
                }
            }
            return TRUE;
        }
        if (hdr->idFrom == IDC_WIF_LIST && hdr->code == NM_DBLCLK && !w->rule.adapter.empty()) {
            PropSheet_PressButton(w->sheet, PSBTN_NEXT);
            return TRUE;
        }
        if (hdr->code == PSN_SETACTIVE) {
            FillAdapters(page, *w);
            UpdateAdapterStep(page, *w);
            NotifyResult(page, 0);
            return TRUE;
        }
        break;
    }
    }
    return FALSE;
}

// Шаг 3: если интерфейс недоступен

INT_PTR CALLBACK WizardPolicyPage(HWND page, UINT msg, WPARAM, LPARAM lp)
{
    Wizard* w = PageWizard(page);
    switch (msg) {
    case WM_INITDIALOG:
        InitPage(page, lp);
        for (int id : {IDC_WPOL_BLOCK_TEXT, IDC_WPOL_DEFAULT_TEXT, IDC_WPOL_MORE}) {
            WrapLabel(page, id);
        }
        return TRUE;
    case WM_NOTIFY: {
        const auto* hdr = reinterpret_cast<const NMHDR*>(lp);
        if (!w) {
            break;
        }
        switch (hdr->code) {
        case PSN_SETACTIVE: {
            const bool block = w->rule.onUnavailable == OnUnavailable::Block;
            CheckRadioButton(page, IDC_WPOL_BLOCK, IDC_WPOL_DEFAULT, block ? IDC_WPOL_BLOCK : IDC_WPOL_DEFAULT);
            const std::wstring summary = std::format(L"Программа: {}\nИнтерфейс: {}", FileNameOf(w->rule.app),
                                                     AdapterLabel(w->rule.adapter));
            SetDlgItemTextW(page, IDC_WPOL_SUMMARY, summary.c_str());
            PropSheet_SetWizButtons(w->sheet, PSWIZB_BACK | PSWIZB_FINISH);
            NotifyResult(page, 0);
            return TRUE;
        }
        case PSN_WIZFINISH:
            w->rule.onUnavailable = IsDlgButtonChecked(page, IDC_WPOL_DEFAULT) == BST_CHECKED
                                        ? OnUnavailable::Default : OnUnavailable::Block;
            w->finished = true;
            NotifyResult(page, 0);
            return TRUE;
        }
        break;
    }
    }
    return FALSE;
}

std::optional<Rule> RunAddWizard()
{
    Wizard w;
    struct PageDef { int dialog; DLGPROC proc; const wchar_t* title; };
    const PageDef defs[] = {
        {IDD_WIZ_APP, WizardAppPage, L"Какую программу направить через интерфейс?"},
        {IDD_WIZ_ADAPTER, WizardAdapterPage, L"Через какой интерфейс ей ходить в сеть?"},
        {IDD_WIZ_POLICY, WizardPolicyPage, L"Что делать, если интерфейс недоступен?"},
    };
    HPROPSHEETPAGE pages[std::size(defs)] = {};
    for (size_t i = 0; i < std::size(defs); ++i) {
        PROPSHEETPAGEW p{};
        p.dwSize = sizeof(p);
        p.dwFlags = PSP_USEHEADERTITLE;
        p.hInstance = g.instance;
        p.pszTemplate = MAKEINTRESOURCEW(defs[i].dialog);
        p.pfnDlgProc = defs[i].proc;
        p.pszHeaderTitle = defs[i].title;
        p.lParam = reinterpret_cast<LPARAM>(&w);
        pages[i] = CreatePropertySheetPageW(&p);
    }
    PROPSHEETHEADERW h{};
    h.dwSize = sizeof(h);
    h.dwFlags = PSH_WIZARD | PSH_AEROWIZARD | PSH_USEICONID;
    h.hwndParent = g.main;
    h.hInstance = g.instance;
    h.pszIcon = MAKEINTRESOURCEW(IDI_APP);
    h.pszCaption = L"Новое правило";
    h.nPages = static_cast<UINT>(std::size(pages));
    h.phpage = pages;
    PropertySheetW(&h);
    return w.finished ? std::optional(w.rule) : std::nullopt;
}

// --- глобальный переключатель основного интерфейса (#14) ------------------------------------
//
// «Весь трафик через …»: меняет "primary" в конфиге; менеджер маршрутов (approute-routes watch)
// подхватывает его на лету. Правила приложений работают независимо от выбора.

std::vector<NET_LUID> InternetRoutes()
{
    try {
        return InterfacesWithInternetRoute();
    } catch (...) {
        return {};
    }
}
std::wstring PrimaryLabel(const std::wstring& guid)
{
    if (guid == L"auto") {
        return L"Автоматически — основное физическое подключение";
    }
    std::wstring label = AdapterLabel(guid);
    const NetAdapter* a = AdapterByGuid(guid);
    if (!a) {
        label += L" (сейчас нет в системе)";
    } else if (!a->IsUp()) {
        label += L" (отключён)";
    } else {
        const auto routed = InternetRoutes();
        if (std::none_of(routed.begin(), routed.end(), [&](NET_LUID l) { return SameLuid(l, a->luid); })) {
            label += L" (нет выхода в интернет)";
        }
    }
    return label;
}


// Пункты: «автоматически», подключённые интерфейсы с выходом в интернет (у корпоративного VPN с
// раздельным туннелем или виртуального коммутатора его нет — «весь трафик» через них не пустить)
// и выбранный сейчас, даже если он недоступен
std::vector<std::wstring> PrimaryCandidates()
{
    const auto routed = InternetRoutes();
    std::vector<std::wstring> out = {L"auto"};
    for (const NetAdapter* a : SortedAdapters()) {
        const bool internet = std::any_of(routed.begin(), routed.end(), [&](NET_LUID l) { return SameLuid(l, a->luid); });
        if (a->IsUp() && internet) {
            out.push_back(GuidToString(a->guid));
        }
    }
    const std::wstring& current = g.config.primary;
    if (current != L"auto" && std::none_of(out.begin(), out.end(), [&](const std::wstring& s) {
            return EqualsIgnoreCase(s, current);
        })) {
        out.push_back(current);
    }
    return out;
}

int PrimaryIndex()
{
    for (size_t i = 0; i < g.primaryGuids.size(); ++i) {
        if (EqualsIgnoreCase(g.primaryGuids[i], g.config.primary)) {
            return static_cast<int>(i);
        }
    }
    return 0;
}

void UpdatePrimaryState()
{
    std::wstring state;
    std::optional<NET_LUID> detected;
    try {
        detected = DetectPrimaryInterface();
    } catch (...) {
    }
    const auto name = [](std::optional<NET_LUID> luid) {
        if (!luid) {
            return std::wstring(L"—");
        }
        const NetAdapter* a = FindAdapter(g.adapters, *luid);
        return a ? a->alias : InterfaceName(*luid);
    };
    const PrimaryChoice choice = ChoosePrimary(g.config.primary, g.adapters, detected, InternetRoutes());
    std::optional<NET_LUID> current;
    try {
        current = CurrentInternetInterface();
    } catch (...) {
    }
    const std::wstring effective = name(current);   // через какой интерфейс трафик идёт на самом деле
    const bool running = IsRouteManagerRunning();
    if (running) {
        state = L"Сейчас весь трафик идёт через «" + effective + L"»";
        if (!choice.note.empty()) {
            state += L" · " + choice.note;
        }
    } else {
        // Выбор сохранён, но маршруты никто не меняет — показываем, как есть на самом деле
        state = std::format(L"Сейчас трафик идёт через «{}». Менеджер маршрутов не запущен — выбор "
                            L"применится после его запуска (кнопка справа).",
                            effective);
    }

    SetDlgItemTextW(g.main, IDC_PRIMARY_STATE, state.c_str());
    SetDlgItemTextW(g.main, IDC_MANAGER, running ? L"Остановить &менеджер маршрутов" : L"Запустить &менеджер маршрутов…");
    EnableWindow(GetDlgItem(g.main, IDC_MANAGER), !g.readOnly || running);
    WrapLabel(g.main, IDC_PRIMARY_STATE);

    if (g.trayAdded) {
        NOTIFYICONDATAW nid{};
        nid.cbSize = sizeof(nid);
        nid.hWnd = g.main;
        nid.uID = kTrayId;
        nid.uFlags = NIF_TIP | NIF_SHOWTIP;
        const std::wstring tip = L"AppRoute — весь трафик через «" + effective + L"»" +
                                 (running ? L"" : L" (менеджер маршрутов не запущен)");
        wcsncpy_s(nid.szTip, tip.c_str(), _TRUNCATE);
        Shell_NotifyIconW(NIM_MODIFY, &nid);
    }
}

void FillPrimaryCombo()
{
    HWND combo = GetDlgItem(g.main, IDC_PRIMARY);
    if (SendMessageW(combo, CB_GETDROPPEDSTATE, 0, 0)) {
        return;   // список открыт — не мешаем выбору
    }
    auto candidates = PrimaryCandidates();
    if (candidates != g.primaryGuids) {
        g.primaryGuids = std::move(candidates);
        SendMessageW(combo, CB_RESETCONTENT, 0, 0);
        for (const auto& guid : g.primaryGuids) {
            const std::wstring label = PrimaryLabel(guid);
            SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label.c_str()));
        }
    }
    SendMessageW(combo, CB_SETCURSEL, static_cast<WPARAM>(PrimaryIndex()), 0);
    EnableWindow(combo, !g.readOnly);
    UpdatePrimaryState();
}

bool Save(const std::wstring& done, std::optional<size_t> select);

void SetPrimary(const std::wstring& guid)
{
    if (g.readOnly || EqualsIgnoreCase(guid, g.config.primary)) {
        return;
    }
    g.config.primary = guid;
    if (const NetAdapter* a = AdapterByGuid(guid)) {
        RememberAdapter(g.config, {guid, a->alias, a->description});
    }
    Save(L"Весь трафик: " + (guid == L"auto" ? std::wstring(L"автоматически") : L"через «" + AdapterLabel(guid) + L"»"),
         SelectedRule());
    FillPrimaryCombo();
}

// Колесо мыши над закрытым списком меняет выбор — для переключателя всего трафика случайная
// прокрутка недопустима: колесо работает только в открытом списке
LRESULT CALLBACK NoWheelCombo(HWND h, UINT msg, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR)
{
    if (msg == WM_MOUSEWHEEL && !SendMessageW(h, CB_GETDROPPEDSTATE, 0, 0)) {
        return 0;
    }
    return DefSubclassProc(h, msg, wp, lp);
}

void OnPrimaryComboChanged()
{
    const int sel = static_cast<int>(SendDlgItemMessageW(g.main, IDC_PRIMARY, CB_GETCURSEL, 0, 0));
    if (sel >= 0 && static_cast<size_t>(sel) < g.primaryGuids.size()) {
        SetPrimary(g.primaryGuids[static_cast<size_t>(sel)]);
    }
}

// --- менеджер маршрутов: запуск с согласия и остановка (#15) --------------------------------

std::wstring ThisExe()
{
    std::wstring path(32768, L'\0');
    path.resize(GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size())));
    return path;
}
std::wstring BinPath(const wchar_t* file)
{
    const std::wstring self = ThisExe();
    return self.substr(0, self.find_last_of(L'\\') + 1) + file;
}

// Что менеджер сделает сейчас: политика из конфига и план изменений (без прав администратора)
std::wstring DescribeManagerPlan()
{
    const ConfigPolicy cp = PolicyFromConfig(g.config);
    std::wstring text;
    if (!cp.policy) {
        text = L"Основной интерфейс сейчас определить не удалось — менеджер будет ждать подключения.";
    } else {
        const RoutePolicy& p = *cp.policy;
        text = L"Весь трафик — через «" + InterfaceName(p.primary) + L"».";
        if (!p.ensureDefault.empty()) {
            text += L"\nМаршрут по умолчанию с низким приоритетом — на интерфейсах правил:";
            for (const NET_LUID l : p.ensureDefault) {
                text += L" «" + InterfaceName(l) + L"»";
            }
        }
        for (const PinnedRoute& r : p.pinned) {
            text += L"\nПодсеть " + FormatPrefix(r.prefix) + L" — всегда через «" + InterfaceName(r.luid) + L"».";
        }
        try {
            const RoutePlan plan = RouteManager(p).Plan();
            text += L"\n\nИзменения сейчас:";
            if (plan.changes.empty()) {
                text += L" не нужны — система уже соответствует.";
            }
            for (const RouteChange& c : plan.changes) {
                text += L"\n• " + c.description;
            }
            for (const std::wstring& w : plan.warnings) {
                text += L"\n⚠ " + w;
            }
        } catch (...) {
        }
    }
    for (const std::wstring& n : cp.notes) {
        text += L"\n⚠ " + n;
    }
    return text;
}

HRESULT CALLBACK ConsentCallback(HWND dialog, UINT msg, WPARAM, LPARAM, LONG_PTR)
{
    if (msg == TDN_CREATED) {
        SendMessageW(dialog, TDM_SET_BUTTON_ELEVATION_REQUIRED_STATE, 100, TRUE);   // щит UAC
    }
    return S_OK;
}

// Явное согласие: что именно будет изменено, что это временно, затем — запрос UAC
void StartManager()
{
    if (g.readOnly || IsRouteManagerRunning()) {
        return;
    }
    LoadAdapters();
    const std::wstring details = DescribeManagerPlan();
    const TASKDIALOG_BUTTON buttons[] = {
        {100, L"Запустить менеджер маршрутов\nWindows попросит подтвердить права администратора"},
        {101, L"Не запускать"},
    };
    TASKDIALOGCONFIG tdc{};
    tdc.cbSize = sizeof(tdc);
    tdc.hwndParent = g.main;
    tdc.hInstance = g.instance;
    tdc.dwFlags = TDF_USE_COMMAND_LINKS | TDF_EXPANDED_BY_DEFAULT | TDF_ALLOW_DIALOG_CANCELLATION |
                  TDF_POSITION_RELATIVE_TO_WINDOW;
    tdc.pszWindowTitle = L"AppRoute";
    tdc.pszMainIcon = TD_SHIELD_ICON;
    tdc.pszMainInstruction = L"Запустить менеджер маршрутов?";
    tdc.pszContent =
        L"Менеджер маршрутов держит маршрут в интернет на выбранном интерфейсе («весь трафик через») и даёт "
        L"программам с правилами выход через их интерфейсы. Он меняет метрики интерфейсов и маршруты Windows, "
        L"поэтому ему нужны права администратора.\n\n"
        L"Изменения временные: всё откатывается при остановке менеджера (здесь или в меню значка) и не "
        L"переживает перезагрузку. Чужие маршруты VPN-клиентов не удаляются, только получают меньший приоритет.";
    tdc.pszExpandedInformation = details.c_str();
    tdc.pszExpandedControlText = L"Скрыть подробности";
    tdc.pszCollapsedControlText = L"Что будет изменено";
    tdc.pButtons = buttons;
    tdc.cButtons = static_cast<UINT>(std::size(buttons));
    tdc.nDefaultButton = 101;
    tdc.pfCallback = ConsentCallback;
    int choice = 0;
    if (FAILED(TaskDialogIndirect(&tdc, &choice, nullptr, nullptr)) || choice != 100) {
        SetStatus(L"Менеджер маршрутов не запущен");
        return;
    }

    // Канал менеджера будет доступен только этому пользователю (и его окну approute-gui)
    const std::wstring routes = BinPath(L"approute-routes.exe");
    const std::wstring params =
        L"serve --config " + QuoteArgument(g.configPath) + L" --client-sid " + CurrentUserSid();
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOASYNC;
    sei.hwnd = g.main;
    sei.lpVerb = L"runas";
    sei.lpFile = routes.c_str();
    sei.lpParameters = params.c_str();
    sei.nShow = SW_HIDE;
    if (!ShellExecuteExW(&sei)) {
        const DWORD error = GetLastError();
        SetStatus(error == ERROR_CANCELLED ? L"Запуск менеджера маршрутов отменён"
                                           : L"Менеджер маршрутов не запущен: " + Win32ErrorMessage(error));
        return;
    }
    SetStatus(L"Менеджер маршрутов запущен · журнал: %LOCALAPPDATA%\\AppRoute\\routes.log");
    Sleep(500);
    RefreshStates();
}

void StopManager()
{
    const ManagerReply reply = CallManager(ManagerPipeName(), "STOP", BinPath(L"approute-routes.exe"));
    if (!reply.ok) {
        Message(g.main, L"Не удалось остановить менеджер маршрутов: " + reply.error +
                            L"\n\nЕсли он запущен из консоли (approute-routes watch), остановите его там: Ctrl+C.",
                MB_ICONWARNING);
        return;
    }
    // Менеджер откатывает изменения и завершается
    for (int i = 0; i < 20 && IsRouteManagerRunning(); ++i) {
        Sleep(200);
    }
    SetStatus(L"Менеджер маршрутов остановлен, изменения маршрутов откачены");
    RefreshStates();
}

void ToggleManager()
{
    if (IsRouteManagerRunning()) {
        StopManager();
    } else {
        StartManager();
    }
}

// --- значок в области уведомлений -----------------------------------------------------------

void AddTrayIcon()
{
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = g.main;
    nid.uID = kTrayId;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_SHOWTIP;
    nid.uCallbackMessage = kMsgTray;
    nid.hIcon = g.smallIcon;
    wcscpy_s(nid.szTip, L"AppRoute");
    g.trayAdded = Shell_NotifyIconW(NIM_ADD, &nid) != FALSE;
    if (g.trayAdded) {
        nid.uVersion = NOTIFYICON_VERSION_4;
        Shell_NotifyIconW(NIM_SETVERSION, &nid);
    }
}

void RemoveTrayIcon()
{
    if (!g.trayAdded) {
        return;
    }
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = g.main;
    nid.uID = kTrayId;
    Shell_NotifyIconW(NIM_DELETE, &nid);
    g.trayAdded = false;
}

void ShowMain()
{
    ShowWindow(g.main, IsIconic(g.main) ? SW_RESTORE : SW_SHOW);
    SetForegroundWindow(g.main);
}

// Закрытие окна — в трей: переключатель и правила остаются под рукой; выход — из меню значка
void HideToTray()
{
    if (!g.trayAdded) {
        DestroyWindow(g.main);
        return;
    }
    ShowWindow(g.main, SW_HIDE);
    if (!g.trayHintShown) {
        g.trayHintShown = true;
        NOTIFYICONDATAW nid{};
        nid.cbSize = sizeof(nid);
        nid.hWnd = g.main;
        nid.uID = kTrayId;
        nid.uFlags = NIF_INFO;
        nid.dwInfoFlags = NIIF_INFO | NIIF_RESPECT_QUIET_TIME;
        wcscpy_s(nid.szInfoTitle, L"AppRoute работает в области уведомлений");
        wcscpy_s(nid.szInfo, L"Здесь — переключатель «весь трафик через». Выход — в меню значка.");
        Shell_NotifyIconW(NIM_MODIFY, &nid);
    }
}

void ShowTrayMenu()
{
    LoadAdapters();
    FillPrimaryCombo();
    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, L"Весь трафик через:");
    for (size_t i = 0; i < g.primaryGuids.size(); ++i) {
        const std::wstring label = PrimaryLabel(g.primaryGuids[i]);
        AppendMenuW(menu, MF_STRING | (g.readOnly ? MF_GRAYED : 0), IDM_PRIMARY_FIRST + i, label.c_str());
    }
    if (!g.primaryGuids.empty()) {
        CheckMenuRadioItem(menu, IDM_PRIMARY_FIRST, IDM_PRIMARY_FIRST + static_cast<UINT>(g.primaryGuids.size()) - 1,
                           IDM_PRIMARY_FIRST + static_cast<UINT>(PrimaryIndex()), MF_BYCOMMAND);
    }
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    const bool running = IsRouteManagerRunning();
    AppendMenuW(menu, MF_STRING | (g.readOnly && !running ? MF_GRAYED : 0), IDM_TRAY_MANAGER,
                running ? L"Остановить &менеджер маршрутов" : L"Запустить &менеджер маршрутов…");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, IDM_TRAY_OPEN, L"&Открыть AppRoute");
    AppendMenuW(menu, MF_STRING, IDM_TRAY_EXIT, L"&Выход");
    SetMenuDefaultItem(menu, IDM_TRAY_OPEN, FALSE);

    POINT pt{};
    GetCursorPos(&pt);
    SetForegroundWindow(g.main);   // иначе меню не закроется щелчком мимо
    const UINT choice = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON, pt.x, pt.y, 0, g.main,
                                       nullptr);
    DestroyMenu(menu);
    if (choice == IDM_TRAY_MANAGER) {
        if (!running) {
            ShowMain();   // окно согласия — поверх главного окна
        }
        ToggleManager();
    } else if (choice == IDM_TRAY_OPEN) {
        ShowMain();
    } else if (choice == IDM_TRAY_EXIT) {
        DestroyWindow(g.main);
    } else if (choice >= IDM_PRIMARY_FIRST && choice < IDM_PRIMARY_FIRST + g.primaryGuids.size()) {
        SetPrimary(g.primaryGuids[choice - IDM_PRIMARY_FIRST]);
    }
}

// --- действия главного окна -----------------------------------------------------------------

void AddRule()
{
    if (g.readOnly) {
        return;
    }
    LoadAdapters();
    if (auto rule = RunAddWizard()) {
        RememberRuleAdapter(*rule);
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
        RememberRuleAdapter(*rule);
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
    SetStatus(std::format(L"Запущено: {} (PID {}{}) — трафик через «{}»", FileNameOf(result.image), result.pid,
                          result.is32Bit ? L", 32-бит" : L"", AdapterLabel(rule.adapter)));
}

std::wstring KnownFolder(REFKNOWNFOLDERID id)
{
    PWSTR path = nullptr;
    std::wstring out;
    if (SUCCEEDED(SHGetKnownFolderPath(id, KF_FLAG_CREATE, nullptr, &path))) {
        out = path;
    }
    CoTaskMemFree(path);
    return out;
}


// Ярлык запуска программы правила через AppRoute (#13): на рабочем столе или в меню «Пуск»
void CreateShortcutForSelected()
{
    const auto index = SelectedRule();
    if (!index) {
        return;
    }
    const Rule& rule = g.config.rules[*index];
    std::wstring error;
    const auto spec = LaunchShortcutFor(rule, ThisExe(), g.configPath, &error);
    if (!spec) {
        Message(g.main, error, MB_ICONINFORMATION);
        return;
    }

    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, IDM_SHORTCUT_DESKTOP, L"На &рабочем столе");
    AppendMenuW(menu, MF_STRING, IDM_SHORTCUT_START, L"В меню «&Пуск» (папка AppRoute)");
    RECT button{};
    GetWindowRect(GetDlgItem(g.main, IDC_SHORTCUT), &button);
    const UINT choice = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY | TPM_LEFTALIGN | TPM_TOPALIGN,
                                       button.left, button.bottom, 0, g.main, nullptr);
    DestroyMenu(menu);
    if (choice == 0) {
        return;
    }

    std::wstring folder = KnownFolder(choice == IDM_SHORTCUT_DESKTOP ? FOLDERID_Desktop : FOLDERID_Programs);
    if (folder.empty()) {
        Message(g.main, L"Не удалось определить папку для ярлыка.", MB_ICONWARNING);
        return;
    }
    if (choice == IDM_SHORTCUT_START) {
        folder += L"\\AppRoute";
        CreateDirectoryW(folder.c_str(), nullptr);
    }
    const std::wstring lnk = folder + L"\\" + LaunchShortcutFileName(rule);
    if (GetFileAttributesW(lnk.c_str()) != INVALID_FILE_ATTRIBUTES &&
        Message(g.main, std::format(L"Ярлык уже есть:\n{}\n\nЗаменить его?", lnk), MB_ICONQUESTION | MB_YESNO) != IDYES) {
        return;
    }
    if (!SaveShortcut(lnk, *spec, &error)) {
        Message(g.main, error, MB_ICONWARNING);
        return;
    }
    SetStatus(L"Ярлык создан: " + lnk);
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

    // Верхняя строка: «Весь трафик через: [список]» и под ней состояние
    const RECT top = DialogUnits(80, 7, 200, 12);      // список: x, y, ширина, высота строки
    const RECT stateRow = DialogUnits(0, 23, 0, 18);   // две строки
    const int listTop = DialogUnits(0, 45, 0, 0).top;

    const int buttonsX = client.right - margin - bw;
    const int listW = std::max(0, buttonsX - gap * 2 - margin);
    const int listH = std::max(0, static_cast<int>(client.bottom) - listTop - margin - statusH - gap);

    HDWP dwp = BeginDeferWindowPos(13);
    auto place = [&](int id, int x, int y, int w, int h) {
        dwp = DeferWindowPos(dwp, GetDlgItem(g.main, id), nullptr, x, y, w, h, SWP_NOZORDER | SWP_NOACTIVATE);
    };
    const RECT managerButton = DialogUnits(6, 6, 130, 14);   // промежуток, y, ширина, высота
    const int managerW = managerButton.right;
    const int comboW = std::min<int>(top.right, std::max<int>(0, static_cast<int>(client.right) - margin - managerW -
                                                                     managerButton.left - top.left));
    place(IDC_PRIMARY, top.left, top.top, comboW, DialogUnits(0, 0, 0, 200).bottom);   // высота — с выпадающим списком
    place(IDC_MANAGER, top.left + comboW + managerButton.left, managerButton.top, managerW, managerButton.bottom);
    place(IDC_PRIMARY_STATE, margin, stateRow.top, std::max(0, static_cast<int>(client.right) - margin * 2), stateRow.bottom);
    place(IDC_RULES, margin, listTop, listW, listH);
    int y = listTop;
    for (int id : {IDC_ADD, IDC_EDIT, IDC_REMOVE}) {
        place(id, buttonsX, y, bw, bh);
        y += bh + gap;
    }
    y += gap * 3;
    place(IDC_LAUNCH, buttonsX, y, bw, bh);
    y += bh + gap;
    place(IDC_SHORTCUT, buttonsX, y, bw, bh);
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
    SetWindowSubclass(GetDlgItem(g.main, IDC_PRIMARY), NoWheelCombo, 1, 0);
    AddTrayIcon();
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
    case kMsgTray:
        // NOTIFYICON_VERSION_4: событие — в младшем слове lParam
        switch (LOWORD(lp)) {
        case WM_CONTEXTMENU:
        case NIN_SELECT:
        case NIN_KEYSELECT:
            ShowTrayMenu();
            break;
        case WM_LBUTTONDBLCLK:
            ShowMain();
            break;
        }
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
        case IDC_SHORTCUT:
            CreateShortcutForSelected();
            return TRUE;
        case IDC_MANAGER:
            ToggleManager();
            return TRUE;
        case IDC_PRIMARY:
            if (HIWORD(wp) == CBN_SELCHANGE) {
                OnPrimaryComboChanged();
            }
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
        HideToTray();
        return TRUE;
    case WM_DESTROY:
        KillTimer(dlg, kStatusTimer);
        RemoveTrayIcon();
        PostQuitMessage(0);
        return TRUE;
    }
    if (msg == kMsgTaskbarCreated && msg != 0) {   // перезапуск Проводника — значок заново
        g.trayAdded = false;
        AddTrayIcon();
        UpdatePrimaryState();
        return TRUE;
    }
    return FALSE;
}

struct Arguments {
    std::wstring config;
    std::optional<std::wstring> run;       // --run PROGRAM
    std::wstring programArguments;         // после «--», уже в кавычках
};

Arguments ParseArguments()
{
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    Arguments a;
    for (int i = 1; argv && i < argc; ++i) {
        const std::wstring_view arg = argv[i];
        if (arg == L"--config" && i + 1 < argc) {
            a.config = argv[++i];
        } else if (arg == L"--run" && i + 1 < argc) {
            a.run = argv[++i];
        } else if (arg == L"--") {
            for (++i; i < argc; ++i) {
                a.programArguments += L" " + QuoteArgument(argv[i]);
            }
        }
    }
    if (argv) {
        LocalFree(argv);
    }
    if (a.config.empty()) {
        a.config = DefaultConfigPath();
    }
    return a;
}

// Запуск по правилу без окна — так работают ярлыки AppRoute (#13)
int RunFromShortcut(const Arguments& args)
{
    const std::wstring& app = *args.run;
    std::wstring error;
    const auto config = LoadConfig(args.config, &error);
    if (!config) {
        Message(nullptr, L"Не удалось прочитать правила AppRoute:\n\n" + error, MB_ICONERROR);
        return 1;
    }
    const Rule* rule = FindRule(*config, Expand(app));
    if (!rule) {
        // Правило удалили, а ярлык остался: решает пользователь, без AppRoute ничего не запускается молча
        if (Message(nullptr, std::format(L"Для «{}» нет правила AppRoute — возможно, его удалили.\n\n"
                                         L"Запустить программу без AppRoute (обычным маршрутом)?",
                                         FileNameOf(app)),
                    MB_ICONQUESTION | MB_YESNO) == IDYES) {
            ShellExecuteW(nullptr, nullptr, Expand(app).c_str(),
                          args.programArguments.empty() ? nullptr : args.programArguments.c_str(), nullptr,
                          SW_SHOWNORMAL);
        }
        return 1;
    }
    LaunchRequest request = RequestForRule(*rule, CommandLineForApp(app) + args.programArguments);
    request.inheritStdHandles = false;
    const LaunchResult result = LaunchWithRule(request);
    if (!result.Ok()) {
        Message(nullptr, std::format(L"Не удалось запустить «{}» через AppRoute:\n\n{}", FileNameOf(app),
                                     result.message),
                MB_ICONWARNING);
        return 1;
    }
    CloseHandle(result.process);
    return 0;
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show)
{
    g.instance = instance;
    const Arguments args = ParseArguments();
    g.configPath = args.config;
    // COM: ярлыки (IShellLink) и диалог выбора файла
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (args.run) {
        return RunFromShortcut(args);
    }
    // Одно окно на сеанс: оно живёт в трее, повторный запуск показывает его
    const HANDLE single = CreateMutexW(nullptr, FALSE, L"Local\\AppRoute.Gui");
    if (single && GetLastError() == ERROR_ALREADY_EXISTS) {
        if (HWND existing = FindWindowW(L"#32770", L"AppRoute — правила программ")) {
            ShowWindow(existing, IsIconic(existing) ? SW_RESTORE : SW_SHOW);
            SetForegroundWindow(existing);
        }
        CloseHandle(single);
        return 0;
    }

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
