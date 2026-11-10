#include "core/Process.h"
#include "core/Util.h"

#include <sddl.h>

#include <algorithm>
#include <string_view>

namespace approute {

bool IsProcessWow64(HANDLE process)
{
    USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    if (!IsWow64Process2(process, &processMachine, &nativeMachine)) {
        return false;
    }
    return processMachine != IMAGE_FILE_MACHINE_UNKNOWN;
}

std::wstring GetProcessImageName(HANDLE process)
{
    wchar_t buffer[MAX_PATH * 2] = {};
    DWORD size = static_cast<DWORD>(std::size(buffer));
    if (QueryFullProcessImageNameW(process, 0, buffer, &size)) {
        return std::wstring(buffer, size);
    }
    return {};
}

bool IsProtectedExecutable(std::wstring_view imagePathOrName)
{
    // Защитное ПО (антивирусы, EDR) и критичные системные процессы. Нижний регистр.
    static constexpr std::wstring_view kProtected[] = {
        // Критичные системные процессы
        L"smss.exe", L"csrss.exe", L"wininit.exe", L"winlogon.exe", L"services.exe",
        L"lsass.exe", L"lsaiso.exe", L"fontdrvhost.exe", L"dwm.exe", L"sihost.exe",
        // Microsoft Defender / Windows Security
        L"msmpeng.exe", L"mpdefendercoreservice.exe", L"nissrv.exe", L"smartscreen.exe",
        L"securityhealthservice.exe", L"securityhealthsystray.exe",
        // Kaspersky
        L"avp.exe", L"avpui.exe", L"ksde.exe", L"ksdeui.exe",
        // ESET
        L"ekrn.exe", L"egui.exe",
        // Bitdefender
        L"bdagent.exe", L"vsserv.exe", L"bdservicehost.exe",
        // Avast / AVG
        L"avastsvc.exe", L"avastui.exe", L"avgsvc.exe", L"aswidsagent.exe",
        // Avira
        L"avguard.exe", L"avgnt.exe",
        // McAfee
        L"mcshield.exe", L"masvc.exe", L"mfemms.exe",
        // Norton / Symantec
        L"ccsvchst.exe", L"nortonsecurity.exe", L"rtvscan.exe", L"savservice.exe",
        // Sophos / Dr.Web / прочее
        L"sophosui.exe", L"savservice.exe", L"dwengine.exe", L"dwservice.exe", L"spideragent.exe",
    };

    // Имя файла из пути
    size_t slash = imagePathOrName.find_last_of(L"\\/");
    std::wstring_view name = slash == std::wstring_view::npos ? imagePathOrName : imagePathOrName.substr(slash + 1);
    for (auto candidate : kProtected) {
        if (EqualsIgnoreCase(name, candidate)) {
            return true;
        }
    }
    return false;
}

namespace {

// SID пользователя из токена процесса в виде строки; пусто при ошибке.
std::wstring TokenUserSid(HANDLE process)
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
        return {};
    }
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<std::byte> buffer(size);
    std::wstring sid;
    if (size && GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) {
        auto* user = reinterpret_cast<TOKEN_USER*>(buffer.data());
        wchar_t* text = nullptr;
        if (ConvertSidToStringSidW(user->User.Sid, &text)) {
            sid = text;
            LocalFree(text);
        }
    }
    CloseHandle(token);
    return sid;
}

} // namespace

bool ProcessUserMatchesCurrent(HANDLE process)
{
    const std::wstring mine = TokenUserSid(GetCurrentProcess());
    const std::wstring other = TokenUserSid(process);
    return !mine.empty() && !other.empty() && mine == other;
}

DWORD InjectDll(HANDLE process, const std::wstring& dllPath, DWORD timeoutMs)
{
    const SIZE_T bytes = (dllPath.size() + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        return GetLastError();
    }

    DWORD result = NO_ERROR;
    bool threadFinished = true;
    if (!WriteProcessMemory(process, remote, dllPath.c_str(), bytes, nullptr)) {
        result = GetLastError();
    } else {
        // kernel32 загружен по одному адресу во всех процессах одной разрядности (до перезагрузки)
        auto* loadLibrary = reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
        HANDLE thread = CreateRemoteThread(process, nullptr, 0, loadLibrary, remote, 0, nullptr);
        if (!thread) {
            result = GetLastError();
        } else {
            if (WaitForSingleObject(thread, timeoutMs) != WAIT_OBJECT_0) {
                result = WAIT_TIMEOUT;
                threadFinished = false;   // поток ещё читает строку — память не освобождаем
            } else {
                DWORD module = 0;   // младшие 32 бита HMODULE: 0 — LoadLibraryW не удался
                GetExitCodeThread(thread, &module);
                if (module == 0) {
                    result = ERROR_MOD_NOT_FOUND;
                }
            }
            CloseHandle(thread);
        }
    }
    if (threadFinished) {
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    }
    return result;
}

std::vector<wchar_t> MergeEnvironment(const void* block, bool unicode, const EnvVars& vars)
{
    auto overridden = [&](std::wstring_view entry) {
        const auto eq = entry.find(L'=', 1);   // "=C:=C:\..." — служебные переменные начинаются с '='
        const auto name = entry.substr(0, eq);
        return std::any_of(vars.begin(), vars.end(), [&](const auto& v) { return EqualsIgnoreCase(v.first, name); });
    };

    std::vector<wchar_t> out;
    auto append = [&](std::wstring_view entry) {
        if (!entry.empty() && !overridden(entry)) {
            out.insert(out.end(), entry.begin(), entry.end());
            out.push_back(L'\0');
        }
    };

    if (block) {
        if (unicode) {
            for (auto* p = static_cast<const wchar_t*>(block); *p; p += wcslen(p) + 1) {
                append(p);
            }
        } else {
            for (auto* p = static_cast<const char*>(block); *p; p += strlen(p) + 1) {
                const int len = MultiByteToWideChar(CP_ACP, 0, p, -1, nullptr, 0);
                std::wstring wide(static_cast<size_t>(len > 0 ? len - 1 : 0), L'\0');
                if (len > 1) {
                    MultiByteToWideChar(CP_ACP, 0, p, -1, wide.data(), len);
                }
                append(wide);
            }
        }
    }

    for (const auto& [name, value] : vars) {
        const std::wstring entry = name + L"=" + value;
        out.insert(out.end(), entry.begin(), entry.end());
        out.push_back(L'\0');
    }
    if (out.empty()) {
        out.push_back(L'\0');   // пустой блок — это два нуля подряд
    }
    out.push_back(L'\0');
    return out;
}

} // namespace approute
