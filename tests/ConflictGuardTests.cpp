// Тесты защиты от «войны метрик» (issue #2): время подставляется явно.

#include "core/ConflictGuard.h"
#include "core/Routes.h"
#include "core/Util.h"

#include "Test.h"

using namespace approute;

namespace {

RouteChange Metric(ULONG64 luid, ADDRESS_FAMILY family = AF_INET)
{
    RouteChange c;
    c.kind = ChangeKind::SetInterfaceMetric;
    c.luid.Value = luid;
    c.family = family;
    c.newMetric = 5000;
    return c;
}

RouteChange DeleteSplit(ULONG64 luid)
{
    RouteChange c;
    c.kind = ChangeKind::DeleteRoute;
    NET_LUID l{};
    l.Value = luid;
    c.route = MakeRoute(l, *ParsePrefix(L"0.0.0.0/1"), SOCKADDR_INET{}, 0);
    return c;
}

constexpr ConflictSettings kSettings{5, 60'000, 300'000};

} // namespace

TEST(ConflictNormalChangesPass)
{
    ConflictGuard guard(kSettings);
    std::vector<std::wstring> messages;
    // Разовые исправления разных объектов и редкие исправления одного — без конфликта
    for (ULONGLONG t = 0; t < 10 * 70'000; t += 70'000) {
        const auto out = guard.Filter({Metric(1), Metric(2)}, t, messages);
        CHECK(out.size() == 2);
    }
    CHECK(messages.empty());
}

TEST(ConflictDetectedAndPaused)
{
    ConflictGuard guard(kSettings);
    std::vector<std::wstring> messages;
    // VPN-клиент возвращает метрику каждые 2 с
    ULONGLONG t = 1000;
    for (int i = 0; i < 5; ++i, t += 2000) {
        CHECK(guard.Filter({Metric(1)}, t, messages).size() == 1);
    }
    CHECK(messages.empty());
    CHECK(guard.Filter({Metric(1)}, t, messages).empty());   // шестое — конфликт
    CHECK(messages.size() == 1);
    CHECK(messages[0].find(L"конфликт") != std::wstring::npos);
    CHECK(guard.InCooldown(Metric(1), t));

    // Во время паузы молчим и не исправляем
    for (int i = 0; i < 20; ++i) {
        t += 2000;
        CHECK(guard.Filter({Metric(1)}, t, messages).empty());
    }
    CHECK(messages.size() == 1);
    // Другие объекты не затронуты
    const auto out = guard.Filter({Metric(1), Metric(2)}, t, messages);
    CHECK(out.size() == 1 && out[0].luid.Value == 2);
    CHECK(!guard.InCooldown(Metric(1, AF_INET6), t));   // другое семейство — другой объект
}

TEST(ConflictCooldownEnds)
{
    ConflictGuard guard(kSettings);
    std::vector<std::wstring> messages;
    ULONGLONG t = 0;
    for (int i = 0; i < 6; ++i, t += 1000) {
        guard.Filter({Metric(1)}, t, messages);
    }
    CHECK(guard.InCooldown(Metric(1), t));
    t += 300'000;
    CHECK(guard.Filter({Metric(1)}, t, messages).size() == 1);   // новая попытка
    CHECK(messages.size() == 2);
    CHECK(messages[1].find(L"пауза закончилась") != std::wstring::npos);
}

TEST(ConflictWindowSlides)
{
    // 5 исправлений, затем перерыв больше окна — счёт начинается заново
    ConflictGuard guard(kSettings);
    std::vector<std::wstring> messages;
    ULONGLONG t = 0;
    for (int i = 0; i < 5; ++i, t += 1000) {
        guard.Filter({Metric(1)}, t, messages);
    }
    t += 61'000;
    for (int i = 0; i < 5; ++i, t += 1000) {
        CHECK(guard.Filter({Metric(1)}, t, messages).size() == 1);
    }
    CHECK(messages.empty());
}

TEST(ConflictOnRoutes)
{
    // VPN снова и снова добавляет свой 0/1, мы его удаляем
    ConflictGuard guard(kSettings);
    std::vector<std::wstring> messages;
    ULONGLONG t = 0;
    for (int i = 0; i < 5; ++i, t += 500) {
        CHECK(guard.Filter({DeleteSplit(7)}, t, messages).size() == 1);
    }
    CHECK(guard.Filter({DeleteSplit(7)}, t, messages).empty());
    CHECK(messages.size() == 1 && messages[0].find(L"0.0.0.0/1") != std::wstring::npos);
    CHECK(ConflictGuard::Key(DeleteSplit(7)) != ConflictGuard::Key(DeleteSplit(8)));
    CHECK(ConflictGuard::Key(Metric(7)) != ConflictGuard::Key(DeleteSplit(7)));
}
