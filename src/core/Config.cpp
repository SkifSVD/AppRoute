#include "core/Config.h"

#include "core/Json.h"
#include "core/Util.h"

#include <shlobj.h>

#include <cmath>
#include <format>

namespace approute {

namespace {

constexpr DWORD kMaxConfigSize = 1024 * 1024;

struct Names {
    const char* onUnavailable[2] = {"block", "default"};
    const char* dns[2] = {"adapter", "system"};
    const char* ipv6[3] = {"follow", "block", "default"};
};
constexpr Names kNames;

template <size_t N>
std::optional<int> IndexOf(const char* const (&names)[N], std::string_view value)
{
    for (size_t i = 0; i < N; ++i) {
        if (value == names[i]) {
            return static_cast<int>(i);
        }
    }
    return std::nullopt;
}

template <size_t N>
std::wstring Choices(const char* const (&names)[N])
{
    std::wstring out;
    for (size_t i = 0; i < N; ++i) {
        out += (i ? L", " : L"") + std::wstring(L"\"") + *FromUtf8(names[i]) + L"\"";
    }
    return out;
}

std::wstring Wide(const std::string& s)
{
    return FromUtf8(s).value_or(L"?");
}

// Разбор одного правила; path — "rules[N]" для сообщений об ошибках.
bool ParseRule(const json::Value& v, const std::wstring& path, Rule& rule, std::wstring& error)
{
    if (!v.IsObject()) {
        error = path + L": ожидался объект";
        return false;
    }

    const auto* app = v.Find("app");
    if (!app || !app->IsString() || app->AsString().empty()) {
        error = path + L".app: обязательная непустая строка — путь к программе";
        return false;
    }
    auto appWide = FromUtf8(app->AsString());
    if (!appWide) {
        error = path + L".app: некорректный UTF-8";
        return false;
    }
    rule.app = std::move(*appWide);

    const auto* target = v.Find("target");
    if (!target || !target->IsObject()) {
        error = path + L".target: обязательный объект { \"type\": \"adapter\", \"id\": \"{GUID}\" }";
        return false;
    }
    const auto* type = target->Find("type");
    if (!type || !type->IsString()) {
        error = path + L".target.type: обязательная строка";
        return false;
    }
    if (type->AsString() != "adapter") {
        error = std::format(L"{}.target.type: тип «{}» пока не поддерживается (есть только \"adapter\")",
                            path, Wide(type->AsString()));
        return false;
    }
    const auto* id = target->Find("id");
    std::optional<std::wstring> guid;
    if (id && id->IsString()) {
        if (auto w = FromUtf8(id->AsString())) {
            guid = NormalizeGuid(*w);
        }
    }
    if (!guid) {
        error = path + L".target.id: ожидался GUID интерфейса вида \"{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}\"";
        return false;
    }
    rule.adapter = std::move(*guid);

    const auto enumField = [&]<size_t N>(const char* name, const char* const (&names)[N], int& out) {
        const auto* f = v.Find(name);
        if (!f) {
            return true;   // значение по умолчанию
        }
        std::optional<int> index;
        if (f->IsString()) {
            index = IndexOf(names, f->AsString());
        }
        if (!index) {
            error = std::format(L"{}.{}: допустимые значения — {}", path, Wide(name), Choices(names));
            return false;
        }
        out = *index;
        return true;
    };
    int onUnavailable = static_cast<int>(rule.onUnavailable);
    int dns = static_cast<int>(rule.dns);
    int ipv6 = static_cast<int>(rule.ipv6);
    if (!enumField("onUnavailable", kNames.onUnavailable, onUnavailable) ||
        !enumField("dns", kNames.dns, dns) ||
        !enumField("ipv6", kNames.ipv6, ipv6)) {
        return false;
    }
    rule.onUnavailable = static_cast<OnUnavailable>(onUnavailable);
    rule.dns = static_cast<DnsMode>(dns);
    rule.ipv6 = static_cast<Ipv6Mode>(ipv6);

    if (const auto* children = v.Find("includeChildren")) {
        if (!children->IsBool()) {
            error = path + L".includeChildren: ожидалось true или false";
            return false;
        }
        rule.includeChildren = children->AsBool();
    }
    return true;
}

bool HasPathSeparator(std::wstring_view s)
{
    return s.find_first_of(L"\\/") != std::wstring_view::npos;
}

std::wstring_view FileName(std::wstring_view path)
{
    const auto pos = path.find_last_of(L"\\/");
    return pos == std::wstring_view::npos ? path : path.substr(pos + 1);
}

// Раскрыть %ПЕРЕМЕННЫЕ% и привести к полному пути (без обращения к диску).
std::wstring NormalizePath(std::wstring_view path)
{
    std::wstring in(path);
    wchar_t expanded[MAX_PATH * 2] = {};
    const DWORD n = ExpandEnvironmentStringsW(in.c_str(), expanded, static_cast<DWORD>(std::size(expanded)));
    if (n > 0 && n <= std::size(expanded)) {
        in = expanded;
    }
    wchar_t full[MAX_PATH * 2] = {};
    const DWORD m = GetFullPathNameW(in.c_str(), static_cast<DWORD>(std::size(full)), full, nullptr);
    if (m > 0 && m < std::size(full)) {
        return full;
    }
    return in;
}

template <typename ConfigT>
auto FindRuleImpl(ConfigT& config, std::wstring_view exePath) -> decltype(&config.rules[0])
{
    const std::wstring exe = NormalizePath(exePath);
    decltype(&config.rules[0]) byName = nullptr;
    for (auto& rule : config.rules) {
        if (HasPathSeparator(rule.app)) {
            if (EqualsIgnoreCase(NormalizePath(rule.app), exe)) {
                return &rule;
            }
        } else if (!byName && EqualsIgnoreCase(rule.app, FileName(exe))) {
            byName = &rule;
        }
    }
    return byName;
}

} // namespace

std::optional<std::wstring> NormalizeGuid(std::wstring_view text)
{
    // Строгий формат {8-4-4-4-12}: IIDFromString его и требует; без скобок — добавляем.
    std::wstring s(text);
    if (s.size() == 36) {
        s = L"{" + s + L"}";
    }
    if (s.size() != 38 || s.front() != L'{' || s.back() != L'}') {
        return std::nullopt;
    }
    GUID guid{};
    if (FAILED(IIDFromString(s.c_str(), &guid))) {
        return std::nullopt;
    }
    return GuidToString(guid);
}

std::wstring DefaultConfigPath()
{
    PWSTR folder = nullptr;
    std::wstring path;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, KF_FLAG_DEFAULT, nullptr, &folder))) {
        path = folder;
    }
    CoTaskMemFree(folder);
    if (path.empty()) {
        wchar_t buf[MAX_PATH] = {};
        if (GetEnvironmentVariableW(L"APPDATA", buf, MAX_PATH) > 0) {
            path = buf;
        }
    }
    return path + L"\\AppRoute\\config.json";
}

std::optional<Config> ParseConfig(std::string_view utf8, std::wstring* error)
{
    std::wstring err;
    const auto fail = [&](std::wstring message) -> std::optional<Config> {
        if (error) {
            *error = std::move(message);
        }
        return std::nullopt;
    };

    json::ParseError parseError;
    const auto root = json::Parse(utf8, &parseError);
    if (!root) {
        return fail(std::format(L"строка {}, столбец {}: {}", parseError.line, parseError.column,
                                Wide(parseError.message)));
    }
    if (!root->IsObject()) {
        return fail(L"корень конфига должен быть объектом { ... }");
    }

    if (const auto* version = root->Find("version")) {
        if (!version->IsNumber() || version->AsNumber() < 1 ||
            version->AsNumber() != std::floor(version->AsNumber())) {
            return fail(L"version: ожидалось целое число ≥ 1");
        }
        if (version->AsNumber() > kConfigVersion) {
            return fail(std::format(L"version {}: конфиг от более новой версии AppRoute (поддерживается {})",
                                    version->AsNumber(), kConfigVersion));
        }
    }

    Config config;
    if (const auto* primary = root->Find("primary")) {
        std::optional<std::wstring> value;
        if (primary->IsString()) {
            const auto w = FromUtf8(primary->AsString());
            if (w && *w == L"auto") {
                value = *w;
            } else if (w) {
                value = NormalizeGuid(*w);
            }
        }
        if (!value) {
            return fail(L"primary: ожидалось \"auto\" или GUID интерфейса");
        }
        config.primary = std::move(*value);
    }

    if (const auto* rules = root->Find("rules")) {
        if (!rules->IsArray()) {
            return fail(L"rules: ожидался массив правил");
        }
        for (size_t i = 0; i < rules->AsArray().size(); ++i) {
            Rule rule;
            if (!ParseRule(rules->AsArray()[i], std::format(L"rules[{}]", i), rule, err)) {
                return fail(std::move(err));
            }
            for (const auto& other : config.rules) {
                if (EqualsIgnoreCase(other.app, rule.app)) {
                    return fail(std::format(L"rules[{}]: повторное правило для «{}»", i, rule.app));
                }
            }
            config.rules.push_back(std::move(rule));
        }
    }

    if (const auto* routes = root->Find("routes")) {
        if (!routes->IsArray()) {
            return fail(L"routes: ожидался массив { \"prefix\": \"ПОДСЕТЬ\", \"adapter\": \"{GUID}\" }");
        }
        for (size_t i = 0; i < routes->AsArray().size(); ++i) {
            const auto& item = routes->AsArray()[i];
            const auto text = [&](const char* key) -> std::optional<std::wstring> {
                const auto* v = item.IsObject() ? item.Find(key) : nullptr;
                return v && v->IsString() ? FromUtf8(v->AsString()) : std::nullopt;
            };
            const auto prefix = text("prefix");
            const auto parsed = prefix ? ParsePrefix(*prefix) : std::nullopt;
            if (!parsed || parsed->PrefixLength == 0) {
                return fail(std::format(L"routes[{}].prefix: ожидалась подсеть вида \"160.79.104.0/23\" "
                                        L"(не маршрут по умолчанию)", i));
            }
            const auto adapter = text("adapter");
            const auto guid = adapter ? NormalizeGuid(*adapter) : std::nullopt;
            if (!guid) {
                return fail(std::format(L"routes[{}].adapter: ожидался GUID интерфейса", i));
            }
            config.routes.push_back({FormatPrefix(*parsed), *guid});
        }
    }

    // История интерфейсов — вспомогательные данные: ошибочные записи пропускаются, а не
    // делают конфиг нечитаемым
    if (const auto* known = root->Find("knownAdapters"); known && known->IsArray()) {
        for (const auto& item : known->AsArray()) {
            const auto text = [&](const char* key) {
                const auto* v = item.IsObject() ? item.Find(key) : nullptr;
                return v && v->IsString() ? FromUtf8(v->AsString()).value_or(L"") : std::wstring();
            };
            const auto id = NormalizeGuid(text("id"));
            if (id && !FindKnownAdapter(config, *id) && config.knownAdapters.size() < kMaxKnownAdapters) {
                config.knownAdapters.push_back({*id, text("name"), text("description")});
            }
        }
    }
    return config;
}

std::string SerializeConfig(const Config& config)
{
    json::Array rules;
    for (const auto& rule : config.rules) {
        json::Object target;
        target.emplace_back("type", "adapter");
        target.emplace_back("id", ToUtf8(rule.adapter));

        json::Object r;
        r.emplace_back("app", ToUtf8(rule.app));
        r.emplace_back("target", std::move(target));
        r.emplace_back("onUnavailable", kNames.onUnavailable[static_cast<int>(rule.onUnavailable)]);
        r.emplace_back("dns", kNames.dns[static_cast<int>(rule.dns)]);
        r.emplace_back("ipv6", kNames.ipv6[static_cast<int>(rule.ipv6)]);
        r.emplace_back("includeChildren", rule.includeChildren);
        rules.emplace_back(std::move(r));
    }

    json::Object root;
    root.emplace_back("version", kConfigVersion);
    root.emplace_back("primary", ToUtf8(config.primary));
    root.emplace_back("rules", std::move(rules));
    if (!config.routes.empty()) {
        json::Array routes;
        for (const auto& r : config.routes) {
            json::Object o;
            o.emplace_back("prefix", ToUtf8(r.prefix));
            o.emplace_back("adapter", ToUtf8(r.adapter));
            routes.emplace_back(std::move(o));
        }
        root.emplace_back("routes", std::move(routes));
    }
    if (!config.knownAdapters.empty()) {
        json::Array known;
        for (const auto& a : config.knownAdapters) {
            json::Object o;
            o.emplace_back("id", ToUtf8(a.id));
            o.emplace_back("name", ToUtf8(a.name));
            o.emplace_back("description", ToUtf8(a.description));
            known.emplace_back(std::move(o));
        }
        root.emplace_back("knownAdapters", std::move(known));
    }
    return json::Serialize(json::Value(std::move(root))) + "\n";
}

std::optional<Config> LoadConfig(const std::wstring& path, std::wstring* error)
{
    const auto fail = [&](std::wstring message) -> std::optional<Config> {
        if (error) {
            *error = std::format(L"{}: {}", path, message);
        }
        return std::nullopt;
    };

    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        const DWORD rc = GetLastError();
        if (rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND) {
            return Config{};
        }
        return fail(Win32ErrorMessage(rc));
    }
    LARGE_INTEGER size{};
    GetFileSizeEx(file, &size);
    if (size.QuadPart > kMaxConfigSize) {
        CloseHandle(file);
        return fail(L"файл слишком большой");
    }
    std::string text(static_cast<size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    const BOOL ok = text.empty() ||
                    ReadFile(file, text.data(), static_cast<DWORD>(text.size()), &read, nullptr);
    const DWORD rc = GetLastError();
    CloseHandle(file);
    if (!ok) {
        return fail(Win32ErrorMessage(rc));
    }
    text.resize(read);

    std::wstring parseError;
    auto config = ParseConfig(text, &parseError);
    if (!config) {
        return fail(parseError);
    }
    return config;
}

bool SaveConfig(const std::wstring& path, const Config& config, std::wstring* error)
{
    const auto fail = [&](DWORD rc) {
        if (error) {
            *error = std::format(L"{}: {}", path, Win32ErrorMessage(rc));
        }
        return false;
    };

    const auto slash = path.find_last_of(L"\\/");
    if (slash != std::wstring::npos) {
        const std::wstring dir = path.substr(0, slash);
        const int rc = SHCreateDirectoryExW(nullptr, dir.c_str(), nullptr);
        if (rc != ERROR_SUCCESS && rc != ERROR_ALREADY_EXISTS && rc != ERROR_FILE_EXISTS) {
            return fail(static_cast<DWORD>(rc));
        }
    }

    const std::string text = SerializeConfig(config);
    const std::wstring temp = path + L".tmp";
    HANDLE file = CreateFileW(temp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return fail(GetLastError());
    }
    DWORD written = 0;
    const BOOL ok = WriteFile(file, text.data(), static_cast<DWORD>(text.size()), &written, nullptr) &&
                    written == text.size() && FlushFileBuffers(file);
    const DWORD rc = GetLastError();
    CloseHandle(file);
    if (!ok) {
        DeleteFileW(temp.c_str());
        return fail(rc);
    }
    if (!MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        const DWORD moveRc = GetLastError();
        DeleteFileW(temp.c_str());
        return fail(moveRc);
    }
    return true;
}

const Rule* FindRule(const Config& config, std::wstring_view exePath)
{
    return FindRuleImpl(config, exePath);
}

Rule* FindRule(Config& config, std::wstring_view exePath)
{
    return FindRuleImpl(config, exePath);
}

std::optional<std::wstring> ValidateRule(const Rule& rule)
{
    if (rule.app.empty()) {
        return L"Не указана программа.";
    }
    if (rule.app.find_first_of(L"\"<>|?*") != std::wstring::npos) {
        return L"Путь к программе содержит недопустимые символы.";
    }
    if (!NormalizeGuid(rule.adapter)) {
        return L"Не выбран интерфейс.";
    }
    return std::nullopt;
}

std::optional<size_t> FindDuplicateRule(const Config& config, std::wstring_view app, std::optional<size_t> except)
{
    const bool isPath = HasPathSeparator(app);
    const std::wstring normalized = isPath ? NormalizePath(app) : std::wstring(app);
    for (size_t i = 0; i < config.rules.size(); ++i) {
        if (except && *except == i) {
            continue;
        }
        const auto& other = config.rules[i].app;
        if (HasPathSeparator(other) != isPath) {
            continue;
        }
        if (EqualsIgnoreCase(isPath ? NormalizePath(other) : other, normalized)) {
            return i;
        }
    }
    return std::nullopt;
}

std::wstring CleanAppPath(std::wstring_view input)
{
    auto isSpace = [](wchar_t c) { return c == L' ' || c == L'\t' || c == L'\r' || c == L'\n'; };
    while (!input.empty() && isSpace(input.front())) {
        input.remove_prefix(1);
    }
    while (!input.empty() && isSpace(input.back())) {
        input.remove_suffix(1);
    }
    if (input.size() >= 2 && input.front() == L'"' && input.back() == L'"') {
        input = input.substr(1, input.size() - 2);
    }
    return std::wstring(input);
}

void RememberAdapter(Config& config, KnownAdapter adapter)
{
    const auto id = NormalizeGuid(adapter.id);
    if (!id) {
        return;
    }
    adapter.id = *id;
    auto& known = config.knownAdapters;
    std::erase_if(known, [&](const KnownAdapter& a) { return EqualsIgnoreCase(a.id, adapter.id); });
    known.insert(known.begin(), std::move(adapter));
    if (known.size() > kMaxKnownAdapters) {
        known.resize(kMaxKnownAdapters);
    }
}

const KnownAdapter* FindKnownAdapter(const Config& config, std::wstring_view id)
{
    for (const auto& a : config.knownAdapters) {
        if (EqualsIgnoreCase(a.id, id)) {
            return &a;
        }
    }
    return nullptr;
}

} // namespace approute
