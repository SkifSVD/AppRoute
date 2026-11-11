#include "core/PackagedApps.h"

#include "core/Com.h"
#include "core/Util.h"

#include <shlobj.h>
#include <shobjidl.h>

#include <winrt/Windows.ApplicationModel.h>
#include <winrt/Windows.Data.Xml.Dom.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Management.Deployment.h>

#include <algorithm>
#include <format>
#include <fstream>
#include <iterator>

namespace approute {

namespace {

namespace xml = winrt::Windows::Data::Xml::Dom;
using winrt::Windows::ApplicationModel::Package;
using winrt::Windows::ApplicationModel::PackageSignatureKind;
using winrt::Windows::Management::Deployment::PackageManager;
using winrt::Windows::Management::Deployment::PackageTypes;

// COM для WinRT на время вызова. C++/WinRT кэширует фабрики классов: перед снятием COM кэш
// сбрасывается, иначе следующий вызов возьмёт фабрику из уже закрытого апартамента.
class WinRtScope {
public:
    WinRtScope() : hr_(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE)) {}
    ~WinRtScope()
    {
        if (SUCCEEDED(hr_)) {
            winrt::clear_factory_cache();
            CoUninitialize();
        }
    }
    WinRtScope(const WinRtScope&) = delete;
    WinRtScope& operator=(const WinRtScope&) = delete;

private:
    HRESULT hr_;
};

bool IsAlnum(wchar_t c)
{
    return (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9');
}

bool IsAppIdChar(wchar_t c)
{
    return IsAlnum(c) || c == L'.';
}

bool EndsWithIgnoreCase(std::wstring_view s, std::wstring_view suffix)
{
    return s.size() >= suffix.size() && EqualsIgnoreCase(s.substr(s.size() - suffix.size()), suffix);
}

// "uap10:RuntimeBehavior" → "RuntimeBehavior"
std::wstring_view LocalName(std::wstring_view qualified)
{
    const auto colon = qualified.find(L':');
    return colon == std::wstring_view::npos ? qualified : qualified.substr(colon + 1);
}

std::wstring Attribute(const xml::XmlElement& e, std::wstring_view localName)
{
    for (const xml::IXmlNode& a : e.Attributes()) {
        const winrt::hstring name = a.NodeName();
        if (LocalName(name) == localName) {
            return std::wstring(winrt::unbox_value_or<winrt::hstring>(a.NodeValue(), L""));
        }
    }
    return {};
}

std::wstring HrMessage(const winrt::hresult_error& e)
{
    std::wstring m(e.message());
    while (!m.empty() && (m.back() == L'\n' || m.back() == L'\r' || m.back() == L' ')) {
        m.pop_back();
    }
    return m.empty() ? std::format(L"ошибка 0x{:08X}", static_cast<uint32_t>(e.code().value)) : m;
}

std::optional<std::wstring> ReadTextFile(const std::wstring& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }
    std::string bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (bytes.size() >= 3 && bytes.compare(0, 3, "\xEF\xBB\xBF") == 0) {
        bytes.erase(0, 3);
    }
    return FromUtf8(bytes);
}

std::vector<ManifestApp> ReadManifest(const std::wstring& packageDir)
{
    const auto text = ReadTextFile(packageDir + L"\\AppxManifest.xml");
    return text ? ParseAppxManifest(*text) : std::vector<ManifestApp>{};
}

std::wstring JoinPackagePath(const std::wstring& dir, std::wstring relative)
{
    std::replace(relative.begin(), relative.end(), L'/', L'\\');
    return dir + L"\\" + relative;
}

bool IsRunnable(const ManifestApp& a)
{
    return a.fullTrust && EndsWithIgnoreCase(a.executable, L".exe");
}

// Основной пакет семейства у пользователя (не ресурсный и не платформа)
std::optional<Package> FindMainPackage(std::wstring_view family, const std::wstring& userSid)
{
    PackageManager manager;
    for (const Package& p : manager.FindPackagesForUser(userSid, winrt::hstring(family))) {
        if (!p.IsFramework() && !p.IsResourcePackage()) {
            return p;
        }
    }
    return std::nullopt;
}

} // namespace

bool IsPackageApp(std::wstring_view app)
{
    const auto bang = app.find(L'!');
    if (bang == std::wstring_view::npos || app.find_first_of(L"\\/:", 0) != std::wstring_view::npos) {
        return false;
    }
    const std::wstring_view family = app.substr(0, bang);
    const std::wstring_view id = app.substr(bang + 1);
    // Семейство: "Имя_ИздательId", Id издателя — 13 символов base32
    const auto underscore = family.rfind(L'_');
    if (underscore == std::wstring_view::npos || underscore == 0 || family.size() - underscore - 1 != 13) {
        return false;
    }
    if (!std::all_of(family.begin() + static_cast<ptrdiff_t>(underscore) + 1, family.end(), IsAlnum)) {
        return false;
    }
    return !id.empty() && std::all_of(id.begin(), id.end(), IsAppIdChar) && !EndsWithIgnoreCase(id, L".exe");
}

std::wstring_view PackageFamilyOf(std::wstring_view app)
{
    return app.substr(0, app.find(L'!'));
}

std::wstring_view PackageAppIdOf(std::wstring_view app)
{
    const auto bang = app.find(L'!');
    return bang == std::wstring_view::npos ? std::wstring_view{} : app.substr(bang + 1);
}

std::vector<ManifestApp> ParseAppxManifest(std::wstring_view text)
{
    std::vector<ManifestApp> out;
    // Объявление <?xml ... encoding="utf-8"?> не соответствует строке UTF-16 — без него
    if (text.starts_with(L"<?xml")) {
        const auto end = text.find(L"?>");
        text = end == std::wstring_view::npos ? std::wstring_view{} : text.substr(end + 2);
    }
    try {
        WinRtScope com;
        xml::XmlDocument doc;
        doc.LoadXml(winrt::hstring(text));
        for (const xml::IXmlNode& node : doc.GetElementsByTagName(L"Application")) {
            const auto e = node.as<xml::XmlElement>();
            ManifestApp a;
            a.id = Attribute(e, L"Id");
            a.executable = Attribute(e, L"Executable");
            const std::wstring entry = Attribute(e, L"EntryPoint");
            const std::wstring behavior = Attribute(e, L"RuntimeBehavior");
            a.fullTrust = entry == L"Windows.FullTrustApplication" || behavior == L"packagedClassicApp" ||
                          behavior == L"win32App";
            for (const xml::IXmlNode& child : e.ChildNodes()) {
                if (child.NodeType() != xml::NodeType::ElementNode ||
                    LocalName(child.NodeName()) != std::wstring_view(L"VisualElements")) {
                    continue;
                }
                const auto ve = child.as<xml::XmlElement>();
                a.displayName = Attribute(ve, L"DisplayName");
                a.listed = !EqualsIgnoreCase(Attribute(ve, L"AppListEntry"), L"none");
            }
            if (!a.id.empty()) {
                out.push_back(std::move(a));
            }
        }
    } catch (const winrt::hresult_error&) {
        out.clear();
    }
    return out;
}

std::vector<PackagedApp> EnumeratePackagedApps()
{
    std::vector<PackagedApp> out;
    try {
        WinRtScope com;
        PackageManager manager;
        for (const Package& p : manager.FindPackagesForUserWithPackageTypes(L"", PackageTypes::Main)) {
            try {
                if (p.IsFramework() || p.SignatureKind() == PackageSignatureKind::System) {
                    continue;   // компоненты Windows
                }
                const std::wstring dir(p.InstalledPath());
                const std::wstring family(p.Id().FamilyName());
                for (const ManifestApp& a : ReadManifest(dir)) {
                    if (!IsRunnable(a) || !a.listed) {
                        continue;
                    }
                    PackagedApp app;
                    app.app = family + L"!" + a.id;
                    app.name = PackagedAppName(app.app);
                    if (app.name == app.app) {
                        app.name = a.displayName.starts_with(L"ms-resource:") ? std::wstring(p.DisplayName())
                                                                              : a.displayName;
                    }
                    app.executable = JoinPackagePath(dir, a.executable);
                    out.push_back(std::move(app));
                }
            } catch (const winrt::hresult_error&) {
                // пакет без доступа или повреждён — пропускаем
            }
        }
    } catch (const winrt::hresult_error&) {
        out.clear();
    }
    std::sort(out.begin(), out.end(), [](const PackagedApp& a, const PackagedApp& b) {
        return CompareStringEx(LOCALE_NAME_USER_DEFAULT, NORM_IGNORECASE, a.name.c_str(), -1, b.name.c_str(), -1,
                               nullptr, nullptr, 0) == CSTR_LESS_THAN;
    });
    return out;
}

std::optional<PackageExecutables> FindPackageExecutables(std::wstring_view app, const std::wstring& userSid,
                                                         std::wstring* error)
{
    const auto fail = [&](std::wstring message) -> std::optional<PackageExecutables> {
        if (error) {
            *error = std::move(message);
        }
        return std::nullopt;
    };
    if (!IsPackageApp(app)) {
        return fail(L"не идентификатор приложения из пакета");
    }
    try {
        WinRtScope com;
        const auto package = FindMainPackage(PackageFamilyOf(app), userSid);
        if (!package) {
            return fail(L"пакет не установлен у пользователя");
        }
        const std::wstring dir(package->InstalledPath());
        const auto apps = ReadManifest(dir);
        const auto it = std::find_if(apps.begin(), apps.end(),
                                     [&](const ManifestApp& a) { return EqualsIgnoreCase(a.id, PackageAppIdOf(app)); });
        if (it == apps.end()) {
            return fail(L"в пакете нет такого приложения");
        }
        if (!IsRunnable(*it)) {
            return fail(L"приложение не полного доверия — правило к нему не применяется");
        }
        PackageExecutables exes;
        exes.main = JoinPackagePath(dir, it->executable);
        for (const ManifestApp& a : apps) {
            if (!IsRunnable(a)) {
                continue;
            }
            std::wstring path = JoinPackagePath(dir, a.executable);
            const bool known = EqualsIgnoreCase(path, exes.main) ||
                               std::any_of(exes.helpers.begin(), exes.helpers.end(),
                                           [&](const std::wstring& h) { return EqualsIgnoreCase(h, path); });
            if (!known) {
                exes.helpers.push_back(std::move(path));
            }
        }
        return exes;
    } catch (const winrt::hresult_error& e) {
        return fail(HrMessage(e));
    }
}

std::wstring PackagedAppName(std::wstring_view app)
{
    ComScope com;
    ComPtr<IShellItem> item;
    const std::wstring parsing = L"shell:AppsFolder\\" + std::wstring(app);
    if (FAILED(SHCreateItemFromParsingName(parsing.c_str(), nullptr, IID_PPV_ARGS(&item)))) {
        return std::wstring(app);
    }
    PWSTR name = nullptr;
    std::wstring out(app);
    if (SUCCEEDED(item->GetDisplayName(SIGDN_NORMALDISPLAY, &name)) && name && *name) {
        out = name;
    }
    CoTaskMemFree(name);
    return out;
}

bool LaunchPackagedApp(std::wstring_view app, const std::wstring& arguments, DWORD* processId,
                       std::wstring* error)
{
    ComScope com;
    ComPtr<IApplicationActivationManager> manager;
    HRESULT hr = CoCreateInstance(CLSID_ApplicationActivationManager, nullptr, CLSCTX_LOCAL_SERVER,
                                  IID_PPV_ARGS(&manager));
    DWORD pid = 0;
    if (SUCCEEDED(hr)) {
        const std::wstring id(app);
        hr = manager->ActivateApplication(id.c_str(), arguments.empty() ? nullptr : arguments.c_str(), AO_NONE,
                                          &pid);
    }
    if (FAILED(hr)) {
        if (error) {
            *error = Win32ErrorMessage(static_cast<DWORD>(hr));
        }
        return false;
    }
    if (processId) {
        *processId = pid;
    }
    return true;
}

} // namespace approute
