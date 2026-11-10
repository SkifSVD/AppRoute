#include "core/Shortcuts.h"

#include "core/Com.h"
#include "core/Util.h"

#include <shlobj.h>
#include <shobjidl.h>

#include <format>

namespace approute {

namespace {

std::wstring ExpandEnv(const std::wstring& s)
{
    const DWORD n = ExpandEnvironmentStringsW(s.c_str(), nullptr, 0);
    if (n == 0) {
        return s;
    }
    std::wstring out(n, L'\0');
    const DWORD m = ExpandEnvironmentStringsW(s.c_str(), out.data(), n);
    out.resize(m > 0 ? m - 1 : 0);
    return out;
}

std::wstring_view FileNamePart(std::wstring_view path)
{
    const auto pos = path.find_last_of(L"\\/");
    return pos == std::wstring_view::npos ? path : path.substr(pos + 1);
}

std::wstring Hr(HRESULT hr)
{
    return Win32ErrorMessage(static_cast<DWORD>(hr));
}

} // namespace

std::wstring QuoteArgument(std::wstring_view arg)
{
    if (!arg.empty() && arg.find_first_of(L" \t\n\v\"") == std::wstring_view::npos) {
        return std::wstring(arg);
    }
    // Обратные косые перед кавычкой и в конце удваиваются, кавычки экранируются
    std::wstring out = L"\"";
    size_t slashes = 0;
    for (const wchar_t c : arg) {
        if (c == L'\\') {
            ++slashes;
            continue;
        }
        if (c == L'"') {
            out.append(slashes * 2 + 1, L'\\');
        } else {
            out.append(slashes, L'\\');
        }
        slashes = 0;
        out += c;
    }
    out.append(slashes * 2, L'\\');
    out += L'"';
    return out;
}

std::optional<ShortcutSpec> LaunchShortcutFor(const Rule& rule, const std::wstring& launcherExe,
                                              const std::wstring& configPath, std::wstring* error)
{
    if (rule.app.find_first_of(L"\\/") == std::wstring::npos) {
        if (error) {
            *error = L"В правиле указано только имя файла программы — для ярлыка нужен полный путь. "
                     L"Укажите его в «Изменить…».";
        }
        return std::nullopt;
    }
    const std::wstring program = ExpandEnv(rule.app);
    ShortcutSpec s;
    s.target = launcherExe;
    if (!configPath.empty() && !EqualsIgnoreCase(configPath, DefaultConfigPath())) {
        s.arguments = L"--config " + QuoteArgument(configPath) + L" ";
    }
    s.arguments += L"--run " + QuoteArgument(rule.app);   // %ПЕРЕМЕННЫЕ% — как в правиле
    const auto slash = program.find_last_of(L"\\/");
    s.workingDirectory = program.substr(0, slash);
    s.iconPath = program;
    s.description = std::format(L"{} через AppRoute", FileNamePart(program));
    return s;
}

std::wstring LaunchShortcutFileName(const Rule& rule)
{
    std::wstring name(FileNamePart(rule.app));
    if (name.size() > 4 && EqualsIgnoreCase(std::wstring_view(name).substr(name.size() - 4), L".exe")) {
        name.resize(name.size() - 4);
    }
    for (auto& c : name) {
        if (c < 32 || std::wstring_view(L"<>:\"/\\|?*").find(c) != std::wstring_view::npos) {
            c = L'_';
        }
    }
    if (name.empty()) {
        name = L"Программа";
    }
    return name + L" (AppRoute).lnk";
}

bool SaveShortcut(const std::wstring& lnkPath, const ShortcutSpec& spec, std::wstring* error)
{
    const auto fail = [&](const std::wstring& what, HRESULT hr) {
        if (error) {
            *error = what + L": " + Hr(hr);
        }
        return false;
    };
    ComScope com;
    ComPtr<IShellLinkW> link;
    HRESULT hr = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&link));
    if (FAILED(hr)) {
        return fail(L"Не удалось создать ярлык", hr);
    }
    link->SetPath(spec.target.c_str());
    link->SetArguments(spec.arguments.c_str());
    link->SetWorkingDirectory(spec.workingDirectory.c_str());
    link->SetIconLocation(spec.iconPath.c_str(), spec.iconIndex);
    link->SetDescription(spec.description.c_str());
    ComPtr<IPersistFile> file;
    hr = link->QueryInterface(IID_PPV_ARGS(&file));
    if (SUCCEEDED(hr)) {
        hr = file->Save(lnkPath.c_str(), TRUE);
    }
    if (FAILED(hr)) {
        return fail(L"Не удалось записать ярлык " + lnkPath, hr);
    }
    SHChangeNotify(SHCNE_CREATE, SHCNF_PATHW | SHCNF_FLUSHNOWAIT, lnkPath.c_str(), nullptr);
    return true;
}

std::optional<ShortcutSpec> ReadShortcut(const std::wstring& lnkPath)
{
    ComScope com;
    ComPtr<IShellLinkW> link;
    ComPtr<IPersistFile> file;
    if (FAILED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&link))) ||
        FAILED(link->QueryInterface(IID_PPV_ARGS(&file))) || FAILED(file->Load(lnkPath.c_str(), STGM_READ))) {
        return std::nullopt;
    }
    const auto text = [](auto get) {
        std::wstring s(32768, L'\0');
        get(s.data(), static_cast<int>(s.size()));
        s.resize(wcslen(s.c_str()));
        return s;
    };
    ShortcutSpec s;
    s.target = text([&](wchar_t* b, int n) { link->GetPath(b, n, nullptr, SLGP_RAWPATH); });
    s.arguments = text([&](wchar_t* b, int n) { link->GetArguments(b, n); });
    s.workingDirectory = text([&](wchar_t* b, int n) { link->GetWorkingDirectory(b, n); });
    s.iconPath = text([&](wchar_t* b, int n) { link->GetIconLocation(b, n, &s.iconIndex); });
    s.description = text([&](wchar_t* b, int n) { link->GetDescription(b, n); });
    return s;
}

} // namespace approute
