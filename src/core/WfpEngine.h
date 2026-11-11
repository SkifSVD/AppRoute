#pragma once

// Применение WfpPlan в WFP (#18): провайдер, подслой, callout'ы драйвера approute-wfp.sys и
// фильтры правил. Сессия BFE динамическая: при закрытии (остановка службы, выход, сбой процесса)
// Windows сама удаляет все её объекты — изменения обратимы. Нужны права администратора.
//
// Для каждой программы правила (ALE_APP_ID) и пользователя (ALE_USER_ID):
//   • ALE_CONNECT_REDIRECT_V4/V6 и ALE_BIND_REDIRECT_V4/V6 — callout драйвера с целью в контексте;
//   • нет адреса нужного семейства и политика «блокировать» — блокировка в ALE_AUTH_CONNECT;
//   • исключения (loopback, локальные подсети) — разрешение с большим весом на CONNECT_REDIRECT и
//     AUTH_CONNECT: такие соединения идут как обычно.
// Callout драйвера, который не загружен, WFP считает блокировкой: без драйвера программы с
// правилом без сети, а не мимо интерфейса.

#include "core/WfpPlan.h"
#include "core/Win.h"

#include <string>
#include <vector>

namespace approute {

class WfpEngine {
public:
    WfpEngine() = default;
    ~WfpEngine();
    WfpEngine(const WfpEngine&) = delete;
    WfpEngine& operator=(const WfpEngine&) = delete;

    bool Open(std::wstring* error);
    void Close();

    // Заменить фильтры правил на новые (в одной транзакции). notes — программы, которые не
    // удалось добавить (например, файла нет).
    bool Apply(const WfpPlan& plan, std::vector<std::wstring>* notes, std::wstring* error);

    size_t FilterCount() const { return filterIds_.size(); }

private:
    bool EnsureBaseObjects(std::wstring* error);
    void RemoveRuleObjects();

    HANDLE engine_ = nullptr;
    bool baseAdded_ = false;
    std::vector<UINT64> filterIds_;
    std::vector<UINT64> contextIds_;
};

// Служба драйвера approute-wfp запущена (драйвер загружен).
bool IsWfpDriverRunning();

} // namespace approute
