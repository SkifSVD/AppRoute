#include "core/ManagerPipe.h"

#include "core/Util.h"

#include <aclapi.h>
#include <sddl.h>

#include <format>
#include <memory>
#include <vector>

namespace approute {

namespace {

constexpr DWORD kBufferSize = 64 * 1024;
constexpr DWORD kIoTimeoutMs = 3000;

struct LocalDeleter {
    void operator()(void* p) const { LocalFree(p); }
};

struct Handle {
    HANDLE h = nullptr;
    explicit Handle(HANDLE v = nullptr) : h(v) {}
    ~Handle()
    {
        if (h && h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
        }
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};

std::wstring TokenUserSid(HANDLE token)
{
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<BYTE> buffer(size);
    if (!size || !GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) {
        return {};
    }
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &text)) {
        return {};
    }
    std::wstring out = text;
    LocalFree(text);
    return out;
}

std::wstring ProcessUserSid(DWORD pid)
{
    Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    HANDLE token = nullptr;
    if (!process.h || !OpenProcessToken(process.h, TOKEN_QUERY, &token)) {
        return {};
    }
    Handle owned(token);
    return TokenUserSid(token);
}

// Ожидание завершения перекрытой операции; false — таймаут, стоп или ошибка (операция отменена)
bool WaitIo(HANDLE file, OVERLAPPED& ov, HANDLE stop, DWORD timeoutMs, DWORD& transferred)
{
    const HANDLE handles[] = {ov.hEvent, stop};
    const DWORD n = stop ? 2 : 1;
    if (WaitForMultipleObjects(n, handles, FALSE, timeoutMs) != WAIT_OBJECT_0) {
        CancelIoEx(file, &ov);
        GetOverlappedResult(file, &ov, &transferred, TRUE);
        return false;
    }
    return GetOverlappedResult(file, &ov, &transferred, FALSE) != FALSE;
}

std::optional<std::string> ReadMessage(HANDLE file, HANDLE stop, DWORD timeoutMs)
{
    std::string out;
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    for (;;) {
        std::string chunk(4096, '\0');
        OVERLAPPED ov{};
        ov.hEvent = event.h;
        ResetEvent(event.h);
        DWORD got = 0;
        BOOL ok = ReadFile(file, chunk.data(), static_cast<DWORD>(chunk.size()), &got, &ov);
        DWORD error = ok ? ERROR_SUCCESS : GetLastError();
        if (!ok && error == ERROR_IO_PENDING) {
            ok = WaitIo(file, ov, stop, timeoutMs, got);
            error = ok ? ERROR_SUCCESS : GetLastError();
        }
        if (!ok && error != ERROR_MORE_DATA) {
            return std::nullopt;
        }
        out.append(chunk.data(), got);
        if (out.size() > kBufferSize) {
            return std::nullopt;
        }
        if (ok) {
            return out;
        }
    }
}

bool WriteMessage(HANDLE file, std::string_view data, HANDLE stop, DWORD timeoutMs)
{
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    OVERLAPPED ov{};
    ov.hEvent = event.h;
    DWORD written = 0;
    BOOL ok = WriteFile(file, data.data(), static_cast<DWORD>(data.size()), &written, &ov);
    if (!ok && GetLastError() == ERROR_IO_PENDING) {
        ok = WaitIo(file, ov, stop, timeoutMs, written);
    }
    return ok && written == data.size();
}

// Владелец канала — администраторы или SYSTEM: канал создан повышенным процессом
bool OwnerIsElevated(HANDLE pipe)
{
    PSID owner = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetSecurityInfo(pipe, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION, &owner, nullptr, nullptr, nullptr,
                        &sd) != ERROR_SUCCESS) {
        return false;
    }
    std::unique_ptr<void, LocalDeleter> guard(sd);
    return IsWellKnownSid(owner, WinBuiltinAdministratorsSid) || IsWellKnownSid(owner, WinLocalSystemSid);
}

} // namespace

std::wstring ManagerPipeName()
{
    DWORD session = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &session);
    return std::format(L"\\\\.\\pipe\\AppRoute.RouteManager.{}", session);
}

std::wstring CurrentUserSid()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return {};
    }
    Handle owned(token);
    return TokenUserSid(token);
}

std::optional<std::wstring> ProcessImagePath(DWORD pid)
{
    Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!process.h) {
        return std::nullopt;
    }
    std::wstring path(32768, L'\0');
    DWORD size = static_cast<DWORD>(path.size());
    if (!QueryFullProcessImageNameW(process.h, 0, path.data(), &size)) {
        return std::nullopt;
    }
    path.resize(size);
    return path;
}

// --- сервер ---------------------------------------------------------------------------------

ManagerPipeServer::ManagerPipeServer(std::wstring name, std::wstring clientSid, std::wstring expectedClientImage,
                                     Handler handler)
    : name_(std::move(name)), clientSid_(std::move(clientSid)), expectedClientImage_(std::move(expectedClientImage)),
      handler_(std::move(handler))
{
}

ManagerPipeServer::~ManagerPipeServer()
{
    Stop();
}

bool ManagerPipeServer::Start(std::wstring* error)
{
    const auto fail = [&](const std::wstring& what) {
        if (error) {
            *error = what;
        }
        return false;
    };
    // SYSTEM и администраторы — полный доступ, пользователь — чтение и запись; метка Medium —
    // чтобы окно без повышения могло подключиться к каналу повышенного процесса
    const std::wstring sddl = std::format(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{})S:(ML;;NW;;;ME)", clientSid_);
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (clientSid_.empty() ||
        !ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr)) {
        return fail(L"не удалось подготовить права доступа канала: " + Win32ErrorMessage(GetLastError()));
    }
    std::unique_ptr<void, LocalDeleter> guard(sd);
    SECURITY_ATTRIBUTES sa{sizeof(sa), sd, FALSE};
    // Первый и единственный экземпляр: занятое имя (подложенный канал) — ошибка, а не подключение
    pipe_ = CreateNamedPipeW(name_.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                             PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1,
                             kBufferSize, kBufferSize, 0, &sa);
    if (pipe_ == INVALID_HANDLE_VALUE) {
        return fail(L"не удалось создать канал " + name_ + L": " + Win32ErrorMessage(GetLastError()));
    }
    stop_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    thread_ = std::thread([this] { Serve(); });
    return true;
}

void ManagerPipeServer::Stop()
{
    if (stop_) {
        SetEvent(stop_);
    }
    if (thread_.joinable()) {
        thread_.join();
    }
    if (pipe_ != INVALID_HANDLE_VALUE) {
        CloseHandle(pipe_);
        pipe_ = INVALID_HANDLE_VALUE;
    }
    if (stop_) {
        CloseHandle(stop_);
        stop_ = nullptr;
    }
}

bool ManagerPipeServer::ClientAllowed(std::wstring* reason) const
{
    ULONG pid = 0;
    if (!GetNamedPipeClientProcessId(pipe_, &pid)) {
        *reason = L"не удалось определить процесс клиента";
        return false;
    }
    if (!EqualsIgnoreCase(ProcessUserSid(pid), clientSid_)) {
        *reason = std::format(L"процесс {} другого пользователя", pid);
        return false;
    }
    if (!expectedClientImage_.empty()) {
        const auto image = ProcessImagePath(pid);
        if (!image || !EqualsIgnoreCase(*image, expectedClientImage_)) {
            *reason = std::format(L"процесс {} — не {}", pid, expectedClientImage_);
            return false;
        }
    }
    return true;
}

void ManagerPipeServer::Serve()
{
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    for (;;) {
        OVERLAPPED ov{};
        ov.hEvent = event.h;
        ResetEvent(event.h);
        BOOL connected = ConnectNamedPipe(pipe_, &ov);
        DWORD error = connected ? ERROR_SUCCESS : GetLastError();
        if (!connected && error == ERROR_IO_PENDING) {
            DWORD ignored = 0;
            connected = WaitIo(pipe_, ov, stop_, INFINITE, ignored);
        } else if (!connected && error == ERROR_PIPE_CONNECTED) {
            connected = TRUE;
        }
        if (WaitForSingleObject(stop_, 0) == WAIT_OBJECT_0) {
            return;
        }
        if (connected) {
            std::wstring reason;
            if (ClientAllowed(&reason)) {
                if (const auto request = ReadMessage(pipe_, stop_, kIoTimeoutMs)) {
                    WriteMessage(pipe_, handler_(*request), stop_, kIoTimeoutMs);
                    FlushFileBuffers(pipe_);
                }
            } else {
                WriteMessage(pipe_, "{\"error\":\"denied\"}", stop_, kIoTimeoutMs);
            }
        }
        DisconnectNamedPipe(pipe_);   // тот же экземпляр — без окна для подмены имени
    }
}

// --- клиент ---------------------------------------------------------------------------------

ManagerReply CallManager(const std::wstring& name, std::string_view request, const std::wstring& expectedServerImage,
                         DWORD timeoutMs, bool requireElevatedOwner)
{
    ManagerReply reply;
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (;;) {
        // Без SECURITY_IMPERSONATION: сервер не может действовать от имени клиента
        pipe = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                           FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        if (pipe != INVALID_HANDLE_VALUE) {
            break;
        }
        const DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND) {
            reply.error = L"менеджер маршрутов не запущен";
            return reply;
        }
        if (error != ERROR_PIPE_BUSY || GetTickCount64() >= deadline) {
            reply.error = L"нет связи с менеджером маршрутов: " + Win32ErrorMessage(error);
            return reply;
        }
        WaitNamedPipeW(name.c_str(), static_cast<DWORD>(deadline - GetTickCount64()));
    }
    Handle owned(pipe);

    if (requireElevatedOwner && !OwnerIsElevated(pipe)) {
        reply.error = L"канал менеджера маршрутов создан не повышенным процессом — запрос не отправлен";
        return reply;
    }
    ULONG serverPid = 0;
    GetNamedPipeServerProcessId(pipe, &serverPid);
    if (!expectedServerImage.empty()) {
        const auto image = ProcessImagePath(serverPid);
        if (image && !EqualsIgnoreCase(*image, expectedServerImage)) {
            reply.error = L"канал менеджера маршрутов принадлежит другой программе: " + *image;
            return reply;
        }
    }
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);
    if (!WriteMessage(pipe, request, nullptr, timeoutMs)) {
        reply.error = L"не удалось отправить запрос менеджеру маршрутов";
        return reply;
    }
    const auto text = ReadMessage(pipe, nullptr, timeoutMs);
    if (!text) {
        reply.error = L"менеджер маршрутов не ответил";
        return reply;
    }
    reply.ok = text->find("\"error\":\"denied\"") == std::string::npos;
    if (!reply.ok) {
        reply.error = L"менеджер маршрутов отклонил запрос (проверка клиента)";
    }
    reply.text = *text;
    return reply;
}

} // namespace approute
