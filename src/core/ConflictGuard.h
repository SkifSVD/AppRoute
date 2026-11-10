#pragma once

// Защита от «войны метрик» (issue #2): если VPN-клиент сам следит за своими маршрутами и
// метрикой и возвращает их, watch и клиент бесконечно перезаписывали бы друг друга.
// ConflictGuard считает исправления каждого объекта (метрика интерфейса для семейства,
// конкретный маршрут) за окно времени; при превышении порога объект на время перестаёт
// исправляться, и выдаётся предупреждение с названием интерфейса.

#include "core/RouteManager.h"

#include <map>
#include <string>
#include <vector>

namespace approute {

struct ConflictSettings {
    size_t maxFixes = 5;              // столько исправлений одного объекта за окно — ещё нормально
    ULONGLONG windowMs = 60'000;
    ULONGLONG cooldownMs = 300'000;   // пауза для объекта в конфликте, затем новая попытка
};

class ConflictGuard {
public:
    explicit ConflictGuard(ConflictSettings settings = {}) : settings_(settings) {}

    // Убирает из плана изменения объектов в конфликте и учитывает остальные как исправления.
    // Новые конфликты и окончания пауз описываются в messages. now — монотонное время в мс.
    std::vector<RouteChange> Filter(const std::vector<RouteChange>& changes, ULONGLONG now,
                                    std::vector<std::wstring>& messages);

    // Объект изменения: метрика интерфейса+семейство или маршрут (интерфейс, префикс, шлюз).
    static std::wstring Key(const RouteChange& change);

    bool InCooldown(const RouteChange& change, ULONGLONG now) const;

private:
    struct State {
        std::vector<ULONGLONG> fixes;   // моменты исправлений в пределах окна
        ULONGLONG blockedUntil = 0;
    };

    ConflictSettings settings_;
    std::map<std::wstring, State> objects_;
};

} // namespace approute
