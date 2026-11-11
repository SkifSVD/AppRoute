#include "core/WfpRules.h"

#include "core/NetAdapters.h"
#include "core/ServiceSetup.h"
#include "core/Util.h"

#include <format>

namespace approute {

namespace {

bool SameReport(const WfpRulesReport& a, const WfpRulesReport& b)
{
    return a.state == b.state && a.lines == b.lines && a.error == b.error;
}

std::vector<std::wstring> PlanLines(const WfpPlan& plan, const std::vector<std::wstring>& notes)
{
    std::vector<std::wstring> lines;
    for (const WfpAppFilter& f : plan.filters) {
        const bool v4 = f.target.flags & APPROUTE_TARGET_HAS_V4;
        const bool v6 = f.target.flags & APPROUTE_TARGET_HAS_V6;
        lines.push_back(std::format(L"{} → [{}]{}{}{}", f.appPath, InterfaceName(NET_LUID{f.target.luid}),
                                    v4 ? L" IPv4" : L"", v6 ? L" IPv6" : L"",
                                    v4 || v6 ? L"" : L" — нет адреса, по политике правила"));
    }
    for (const std::wstring& n : notes) {
        lines.push_back(L"⚠ " + n);
    }
    return lines;
}

} // namespace

WfpRulesReport WfpRules::Finish(WfpRulesReport report, bool* changed)
{
    if (changed) {
        *changed = !last_ || !SameReport(*last_, report);
    }
    last_ = report;
    return report;
}

bool WfpRules::Close()
{
    const bool had = applied_.has_value();
    engine_.Close();
    applied_.reset();
    return had;
}

WfpRulesReport WfpRules::Update(const Config& config, const std::wstring& userSid, bool* changed)
{
    WfpRulesReport report;
    switch (QueryWfpDriver()) {
    case WfpDriverState::NotInstalled:
        Close();
        report.state = WfpRulesState::NoDriver;
        return Finish(std::move(report), changed);
    case WfpDriverState::Stopped:
        if (std::wstring error; !StartWfpDriver(&error)) {
            Close();
            report.state = WfpRulesState::Error;
            report.error = error;
            return Finish(std::move(report), changed);
        }
        break;
    case WfpDriverState::Running:
        break;
    }

    // Путь к exe пакета меняется с обновлением — ищется при каждом применении (#45)
    WfpPlan plan = WfpPlanFromConfig(config, EnumerateAdapters(), userSid,
                                     [&](std::wstring_view app, std::wstring* error) {
                                         return FindPackageExecutables(app, userSid, error);
                                     });
    std::vector<std::wstring> notes = plan.notes;
    if (!applied_ || !SameWfpPlan(*applied_, plan)) {
        std::wstring error;
        if (!engine_.Open(&error)) {
            report.state = WfpRulesState::Error;
            report.error = error;
            return Finish(std::move(report), changed);
        }
        if (!engine_.Apply(plan, &notes, &error)) {
            // Транзакция откатилась — действуют прежние объекты (если были)
            report.state = applied_ ? WfpRulesState::Active : WfpRulesState::Error;
            report.error = error;
            if (applied_ && last_) {
                report.lines = last_->lines;
            }
            return Finish(std::move(report), changed);
        }
        applied_ = std::move(plan);
        report.lines = PlanLines(*applied_, notes);
    } else if (last_) {
        report.lines = last_->lines;   // те же объекты — и заметки Apply прежние
    }
    report.state = WfpRulesState::Active;
    return Finish(std::move(report), changed);
}

std::vector<std::wstring> DescribeWfpRules(const WfpRulesReport& report)
{
    std::vector<std::wstring> out;
    switch (report.state) {
    case WfpRulesState::NoDriver:
        out.push_back(L"драйвер approute-wfp не установлен — правила действуют только для программ, "
                      L"запущенных через AppRoute");
        return out;
    case WfpRulesState::Error:
        out.push_back(L"⚠ правила через драйвер не применены: " + report.error);
        return out;
    case WfpRulesState::Active:
        break;
    }
    if (!report.error.empty()) {
        out.push_back(L"⚠ новые правила не применены, действуют прежние: " + report.error);
    }
    out.push_back(report.lines.empty() ? std::wstring(L"драйвер WFP: правил с полным путём программы нет")
                                       : std::wstring(L"драйвер WFP применяет правила ко всем запускам программ:"));
    for (const std::wstring& l : report.lines) {
        out.push_back(L"  " + l);
    }
    return out;
}

} // namespace approute
