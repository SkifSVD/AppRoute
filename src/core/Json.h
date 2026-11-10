#pragma once

// Минимальный JSON (RFC 8259) для конфига AppRoute: разбор и запись UTF-8.
// Без сторонних зависимостей; порядок ключей объекта сохраняется.

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace approute::json {

class Value;
using Array = std::vector<Value>;
using Member = std::pair<std::string, Value>;
using Object = std::vector<Member>;

class Value {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };

    Value() = default;
    Value(std::nullptr_t) {}
    Value(bool b) : v_(b) {}
    Value(double d) : v_(d) {}
    Value(int i) : v_(static_cast<double>(i)) {}
    Value(std::string s) : v_(std::move(s)) {}
    Value(const char* s) : v_(std::string(s)) {}
    Value(Array a) : v_(std::move(a)) {}
    Value(Object o) : v_(std::move(o)) {}

    Type type() const { return static_cast<Type>(v_.index()); }
    bool IsNull() const { return type() == Type::Null; }
    bool IsBool() const { return type() == Type::Bool; }
    bool IsNumber() const { return type() == Type::Number; }
    bool IsString() const { return type() == Type::String; }
    bool IsArray() const { return type() == Type::Array; }
    bool IsObject() const { return type() == Type::Object; }

    // Доступ без проверки типа запрещён: вызывать только после Is*().
    bool AsBool() const { return std::get<bool>(v_); }
    double AsNumber() const { return std::get<double>(v_); }
    const std::string& AsString() const { return std::get<std::string>(v_); }
    const Array& AsArray() const { return std::get<Array>(v_); }
    const Object& AsObject() const { return std::get<Object>(v_); }
    Array& AsArray() { return std::get<Array>(v_); }
    Object& AsObject() { return std::get<Object>(v_); }

    // Член объекта по ключу; nullptr, если это не объект или ключа нет.
    const Value* Find(std::string_view key) const;

    // Добавить член объекта (значение должно быть объектом).
    void Set(std::string key, Value value);

private:
    std::variant<std::nullptr_t, bool, double, std::string, Array, Object> v_;
};

struct ParseError {
    size_t line = 0;     // с 1
    size_t column = 0;   // с 1
    std::string message;
};

// Разбор текста UTF-8 (BOM допускается). При ошибке — nullopt и описание в error.
std::optional<Value> Parse(std::string_view text, ParseError* error = nullptr);

// Запись с отступом в indent пробелов (0 — в одну строку). Строки — UTF-8 как есть.
std::string Serialize(const Value& value, int indent = 2);

} // namespace approute::json
