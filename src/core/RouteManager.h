#pragma once

#include "core/Win.h"

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace approute {

// Политика маршрутизации системы.
//   primary        — интерфейс, через который по умолчанию идёт ВЕСЬ трафик
//                    (обычно физический Wi-Fi/Ethernet; "глобальный переключатель" меняет именно его).
//   ensureDefault  — интерфейсы, на которых должен существовать маршрут 0/0 с низким приоритетом,
//                    чтобы к ним можно было привязывать отдельные приложения (strong host model:
//                    сокет, привязанный к IP интерфейса, использует только маршруты этого интерфейса).
//   secondaryMetric — метрика интерфейса для "вторичных" интерфейсов с маршрутом по умолчанию.
struct RoutePolicy {
    NET_LUID primary{};
    std::vector<NET_LUID> ensureDefault;
    ULONG secondaryMetric = 5000;
};

enum class ChangeKind {
    SetInterfaceMetric,   // понизить приоритет интерфейса (поднять его метрику)
    DeleteRoute,          // удалить расщеплённый маршрут 0/1 / 128/1 чужого интерфейса
    AddRoute,             // добавить 0/0 с низким приоритетом
};

struct RouteChange {
    ChangeKind kind{};
    std::wstring description;

    // DeleteRoute / AddRoute
    MIB_IPFORWARD_ROW2 route{};

    // SetInterfaceMetric
    NET_LUID luid{};
    ADDRESS_FAMILY family = AF_UNSPEC;
    ULONG oldMetric = 0;
    bool oldAutomatic = false;
    ULONG newMetric = 0;
};

struct RoutePlan {
    std::vector<RouteChange> changes;
    std::vector<std::wstring> warnings;
};

using LogFn = std::function<void(std::wstring_view)>;

// Метрика IP-интерфейса для одного семейства адресов.
struct InterfaceMetric {
    NET_LUID luid{};
    ADDRESS_FAMILY family = AF_UNSPEC;
    ULONG metric = 0;
    bool automatic = false;
};

// Снимок того, что нужно планировщику: таблица маршрутов и метрики интерфейсов.
// Plan() по снимку — чистая функция, её можно проверять тестами без изменения системы.
struct NetworkSnapshot {
    std::vector<MIB_IPFORWARD_ROW2> routes;       // оба семейства
    std::vector<InterfaceMetric> interfaces;

    static NetworkSnapshot Capture();

    const InterfaceMetric* FindInterface(NET_LUID luid, ADDRESS_FAMILY family) const;

    // Итоговая метрика маршрута (маршрут + интерфейс), по которой Windows выбирает путь.
    ULONG64 EffectiveMetric(const MIB_IPFORWARD_ROW2& route) const;
};

class RouteManager {
public:
    explicit RouteManager(RoutePolicy policy);

    const RoutePolicy& Policy() const { return policy_; }

    // Вычисляет, что нужно изменить, чтобы система соответствовала политике. Ничего не меняет.
    // Повторный вызов после Apply() возвращает пустой план (идемпотентность).
    RoutePlan Plan() const;
    RoutePlan Plan(const NetworkSnapshot& snapshot) const;

    // Применяет изменения; успешные запоминает в журнале для отката. Возвращает число ошибок.
    size_t Apply(const std::vector<RouteChange>& changes, const LogFn& log);

    // Откатывает всё, что было применено, в обратном порядке. Изменения, которые с тех пор
    // перезаписал кто-то другой (VPN-клиент), не трогает.
    void Revert(const LogFn& log);

    bool HasJournal() const { return !journal_.empty(); }

private:
    void PlanFamily(const NetworkSnapshot& snapshot, ADDRESS_FAMILY family, RoutePlan& plan) const;

    RoutePolicy policy_;
    std::vector<RouteChange> journal_;
};

// Физический интерфейс с маршрутом IPv4 по умолчанию и наименьшей итоговой метрикой.
std::optional<NET_LUID> DetectPrimaryInterface();

// Подписка на изменения таблицы маршрутов и IP-интерфейсов. Event() взводится при любом
// изменении (событие с ручным сбросом).
class ChangeNotifier {
public:
    ChangeNotifier();
    ~ChangeNotifier();
    ChangeNotifier(const ChangeNotifier&) = delete;
    ChangeNotifier& operator=(const ChangeNotifier&) = delete;

    HANDLE Event() const { return event_; }

private:
    void Close();
    static VOID NETIOAPI_API_ OnRouteChange(PVOID context, PMIB_IPFORWARD_ROW2 row, MIB_NOTIFICATION_TYPE type);
    static VOID NETIOAPI_API_ OnInterfaceChange(PVOID context, PMIB_IPINTERFACE_ROW row, MIB_NOTIFICATION_TYPE type);

    HANDLE event_ = nullptr;
    HANDLE routeHandle_ = nullptr;
    HANDLE interfaceHandle_ = nullptr;
};

} // namespace approute
