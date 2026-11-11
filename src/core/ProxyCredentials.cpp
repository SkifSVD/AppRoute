#include "core/ProxyCredentials.h"

#include "core/Socks5.h"
#include "core/Util.h"

#include <wincred.h>

#include <vector>

namespace approute {

ProxyCredential::~ProxyCredential()
{
    if (!password.empty()) {
        SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
    }
}

std::wstring ProxyCredentialTarget(const SOCKADDR_INET& proxy)
{
    return L"AppRoute/SOCKS5/" + FormatProxyAddress(proxy);
}

std::optional<ProxyCredential> ReadProxyCredential(const SOCKADDR_INET& proxy)
{
    PCREDENTIALW cred = nullptr;
    const std::wstring target = ProxyCredentialTarget(proxy);
    if (!CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &cred)) {
        return std::nullopt;
    }
    ProxyCredential out;
    if (cred->UserName) {
        out.user = cred->UserName;
    }
    if (cred->CredentialBlob && cred->CredentialBlobSize >= sizeof(wchar_t)) {
        out.password.assign(reinterpret_cast<const wchar_t*>(cred->CredentialBlob),
                            cred->CredentialBlobSize / sizeof(wchar_t));
        SecureZeroMemory(cred->CredentialBlob, cred->CredentialBlobSize);
    }
    CredFree(cred);
    if (out.user.empty()) {
        return std::nullopt;
    }
    return out;
}

std::optional<std::wstring> ValidateProxyCredential(const ProxyCredential& credential)
{
    const auto fits = [](const std::wstring& s) {
        const std::string utf8 = ToUtf8(s);
        const bool ok = !utf8.empty() && utf8.size() <= 255;
        return ok;
    };
    if (!fits(credential.user)) {
        return L"Логин — от 1 до 255 байт.";
    }
    if (!fits(credential.password)) {
        return L"Пароль — от 1 до 255 байт.";
    }
    return std::nullopt;
}

bool SaveProxyCredential(const SOCKADDR_INET& proxy, const ProxyCredential& credential, std::wstring* error)
{
    if (const auto problem = ValidateProxyCredential(credential)) {
        if (error) {
            *error = *problem;
        }
        return false;
    }
    const std::wstring target = ProxyCredentialTarget(proxy);
    std::wstring user = credential.user;
    std::wstring comment = L"SOCKS5-прокси правил AppRoute";
    CREDENTIALW cred{};
    cred.Type = CRED_TYPE_GENERIC;
    cred.TargetName = const_cast<LPWSTR>(target.c_str());
    cred.Comment = comment.data();
    cred.UserName = user.data();
    cred.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<wchar_t*>(credential.password.data()));
    cred.CredentialBlobSize = static_cast<DWORD>(credential.password.size() * sizeof(wchar_t));
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE;   // только этот компьютер, без перемещаемого профиля
    if (!CredWriteW(&cred, 0)) {
        if (error) {
            *error = Win32ErrorMessage(GetLastError());
        }
        return false;
    }
    return true;
}

bool DeleteProxyCredential(const SOCKADDR_INET& proxy)
{
    const std::wstring target = ProxyCredentialTarget(proxy);
    return CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0) != FALSE;
}

} // namespace approute
