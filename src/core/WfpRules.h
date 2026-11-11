#pragma once

// Правила программ через драйвер approute-wfp (#18) — для службы AppRoute и approute-routes wfp:
// конфиг и состояние сети → объекты WFP, повторно при каждом изменении.
//
// Фильтры с callout'ами есть только пока драйвер работает: callout без драйвера WFP считает
// блокировкой, и программы с правилом остались бы без сети. Драйвер не установлен — объектов
// нет, правила действуют только для программ, запущенных через AppRoute (hook). Установлен, но
// остановлен — запускается.

#include "core/Config.h"
#include "core/WfpEngine.h"
#include "core/WfpPlan.h"

#include <optional>
#include <string>
#include <vector>

namespace approute {

enum class WfpRulesState {
    NoDriver,   // драйвер не установлен — правила только для запуска через AppRoute
    Active,     // объекты WFP применены
    Error,      // драйвер не запустился или WFP не принял объекты
};

struct WfpRulesReport {
    WfpRulesState state = WfpRulesState::NoDriver;
    std::vector<std::wstring> lines;   // что применено: «программа → [интерфейс] IPv4», заметки
    std::wstring error;
};

class WfpRules {
public:
    // Применить правила config для процессов пользователя userSid. Нужны права администратора.
    // *changed — отчёт отличается от прошлого (стоит записать в журнал).
    WfpRulesReport Update(const Config& config, const std::wstring& userSid, bool* changed = nullptr);

    // Снять все объекты (закрыть динамическую сессию). true — они были.
    bool Close();

private:
    WfpRulesReport Finish(WfpRulesReport report, bool* changed);

    WfpEngine engine_;
    std::optional<WfpPlan> applied_;
    std::optional<WfpRulesReport> last_;
};

// Текст отчёта для журнала (без отметки времени), по строке на элемент.
std::vector<std::wstring> DescribeWfpRules(const WfpRulesReport& report);

} // namespace approute
