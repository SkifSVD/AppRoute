#pragma once

// Мини-фреймворк модульных тестов AppRoute: TEST(имя) { CHECK(условие); }.

#include <cstdio>
#include <functional>
#include <utility>
#include <vector>

namespace approute::test {

struct TestCase {
    const char* name;
    std::function<void()> body;
};

inline std::vector<TestCase>& Registry()
{
    static std::vector<TestCase> tests;
    return tests;
}

inline int& Failures()
{
    static int failures = 0;
    return failures;
}

struct Register {
    Register(const char* name, std::function<void()> body) { Registry().push_back({name, std::move(body)}); }
};

} // namespace approute::test

#define CHECK(expr)                                                                   \
    do {                                                                              \
        if (!(expr)) {                                                                \
            std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);             \
            ++::approute::test::Failures();                                           \
        }                                                                             \
    } while (0)

#define TEST(name)                                                    \
    void name();                                                      \
    const ::approute::test::Register name##_reg(#name, name);         \
    void name()
