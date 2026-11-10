#pragma once

// Канал approute-gui ↔ менеджер маршрутов (#15): именованный канал в пределах компьютера и
// сеанса, запрос — одна строка UTF-8, ответ — одна строка UTF-8 (JSON).
//
// Проверки:
//   • сервер (повышенный менеджер маршрутов): канал создаётся первым экземпляром
//     (FILE_FLAG_FIRST_PIPE_INSTANCE), удалённые клиенты отклоняются, доступ — только SYSTEM,
//     администраторам и указанному пользователю; клиент — процесс этого пользователя с
//     ожидаемым образом (approute-gui.exe из папки менеджера);
//   • клиент (GUI): владелец канала — администраторы или SYSTEM, то есть канал создан
//     повышенным процессом, а не подложен обычной программой; образ сервера — ожидаемый
//     (approute-routes.exe из папки GUI), если его можно прочитать.

#include "core/Win.h"

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <thread>

namespace approute {

// \\.\pipe\AppRoute.RouteManager.<номер сеанса>
std::wstring ManagerPipeName();

// SID пользователя текущего процесса ("S-1-5-21-...").
std::wstring CurrentUserSid();

// Полный путь образа процесса или nullopt (нет доступа, процесс завершён).
std::optional<std::wstring> ProcessImagePath(DWORD pid);

class ManagerPipeServer {
public:
    using Handler = std::function<std::string(std::string_view request)>;

    // clientSid — пользователь, которому разрешён канал; expectedClientImage — полный путь
    // программы-клиента (пусто — не проверять, для тестов).
    ManagerPipeServer(std::wstring name, std::wstring clientSid, std::wstring expectedClientImage, Handler handler);
    ~ManagerPipeServer();
    ManagerPipeServer(const ManagerPipeServer&) = delete;
    ManagerPipeServer& operator=(const ManagerPipeServer&) = delete;

    // Создать канал и начать обслуживание в отдельном потоке.
    bool Start(std::wstring* error);
    void Stop();

private:
    void Serve();
    bool ClientAllowed(std::wstring* reason) const;

    std::wstring name_;
    std::wstring clientSid_;
    std::wstring expectedClientImage_;
    Handler handler_;
    HANDLE pipe_ = INVALID_HANDLE_VALUE;
    HANDLE stop_ = nullptr;
    std::thread thread_;
};

struct ManagerReply {
    bool ok = false;
    std::string text;      // ответ сервера
    std::wstring error;    // почему не удалось (нет менеджера, проверка не пройдена)
};

// Отправить запрос менеджеру. expectedServerImage — полный путь approute-routes.exe
// (пусто — проверить только владельца канала).
ManagerReply CallManager(const std::wstring& name, std::string_view request,
                         const std::wstring& expectedServerImage, DWORD timeoutMs = 3000,
                         bool requireElevatedOwner = true);

} // namespace approute
