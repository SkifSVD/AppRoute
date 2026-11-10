#pragma once

// Политика менеджера маршрутов из конфига (#15) — то, что применяет approute-routes serve,
// запущенный из approute-gui, и что окно согласия показывает пользователю до запуска:
//   • основной интерфейс — переключатель «весь трафик через» ("primary", #14);
//   • маршрут 0/0 с низким приоритетом — на интерфейсах правил, чтобы к ним можно было
//     привязывать программы;
//   • закреплённые подсети — "routes".

#include "core/Config.h"
#include "core/NetAdapters.h"
#include "core/PrimarySwitch.h"
#include "core/RouteManager.h"

#include <optional>
#include <string>
#include <vector>

namespace approute {

struct ConfigPolicy {
    std::optional<RoutePolicy> policy;   // nullopt — основной интерфейс определить не удалось
    PrimaryChoice primary;
    std::vector<std::wstring> notes;     // пояснения: недоступный выбор, отсутствующие интерфейсы
};

// Чистая функция: состояние системы передаётся параметрами (тестируется без сети).
ConfigPolicy PolicyFromConfig(const Config& config, const std::vector<NetAdapter>& adapters,
                              std::optional<NET_LUID> detected, const std::vector<NET_LUID>& internetRoutes);

// То же по текущему состоянию системы.
ConfigPolicy PolicyFromConfig(const Config& config);

// Политики совпадают (основной интерфейс, интерфейсы для 0/0, подсети, метрика).
bool SamePolicy(const RoutePolicy& a, const RoutePolicy& b);

} // namespace approute
