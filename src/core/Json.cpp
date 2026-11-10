#include "core/Json.h"

#include <charconv>
#include <cmath>
#include <format>

namespace approute::json {

const Value* Value::Find(std::string_view key) const
{
    if (!IsObject()) {
        return nullptr;
    }
    for (const auto& [k, v] : AsObject()) {
        if (k == key) {
            return &v;
        }
    }
    return nullptr;
}

void Value::Set(std::string key, Value value)
{
    auto& object = AsObject();
    for (auto& [k, v] : object) {
        if (k == key) {
            v = std::move(value);
            return;
        }
    }
    object.emplace_back(std::move(key), std::move(value));
}

namespace {

constexpr int kMaxDepth = 64;

class Parser {
public:
    explicit Parser(std::string_view text) : text_(text) {}

    std::optional<Value> Run(ParseError* error)
    {
        if (text_.starts_with("\xEF\xBB\xBF")) {
            pos_ = 3;
        }
        SkipSpace();
        auto value = ParseValue(0);
        if (value) {
            SkipSpace();
            if (pos_ != text_.size()) {
                Fail("лишние данные после значения");
                value.reset();
            }
        }
        if (!value && error) {
            *error = error_;
        }
        return value;
    }

private:
    void Fail(std::string message)
    {
        if (!error_.message.empty()) {
            return;   // первая ошибка — самая точная
        }
        error_.line = 1;
        error_.column = 1;
        for (size_t i = 0; i < pos_ && i < text_.size(); ++i) {
            if (text_[i] == '\n') {
                ++error_.line;
                error_.column = 1;
            } else if ((static_cast<unsigned char>(text_[i]) & 0xC0) != 0x80) {
                ++error_.column;   // считаем символы, а не байты UTF-8
            }
        }
        error_.message = std::move(message);
    }

    bool AtEnd() const { return pos_ >= text_.size(); }
    char Peek() const { return AtEnd() ? '\0' : text_[pos_]; }

    void SkipSpace()
    {
        while (!AtEnd() && (Peek() == ' ' || Peek() == '\t' || Peek() == '\n' || Peek() == '\r')) {
            ++pos_;
        }
    }

    bool Literal(std::string_view word)
    {
        if (text_.substr(pos_, word.size()) != word) {
            Fail("неизвестное значение");
            return false;
        }
        pos_ += word.size();
        return true;
    }

    std::optional<Value> ParseValue(int depth)
    {
        if (depth > kMaxDepth) {
            Fail("слишком глубокая вложенность");
            return std::nullopt;
        }
        switch (Peek()) {
        case '{': return ParseObject(depth);
        case '[': return ParseArray(depth);
        case '"': {
            auto s = ParseString();
            if (!s) {
                return std::nullopt;
            }
            return Value(std::move(*s));
        }
        case 't': if (Literal("true")) return Value(true); return std::nullopt;
        case 'f': if (Literal("false")) return Value(false); return std::nullopt;
        case 'n': if (Literal("null")) return Value(nullptr); return std::nullopt;
        default:
            if (Peek() == '-' || (Peek() >= '0' && Peek() <= '9')) {
                return ParseNumber();
            }
            Fail(AtEnd() ? "неожиданный конец текста" : "ожидалось значение");
            return std::nullopt;
        }
    }

    std::optional<Value> ParseObject(int depth)
    {
        ++pos_;   // '{'
        Object object;
        SkipSpace();
        if (Peek() == '}') {
            ++pos_;
            return Value(std::move(object));
        }
        for (;;) {
            SkipSpace();
            if (Peek() != '"') {
                Fail("ожидался ключ в кавычках");
                return std::nullopt;
            }
            auto key = ParseString();
            if (!key) {
                return std::nullopt;
            }
            SkipSpace();
            if (Peek() != ':') {
                Fail("ожидалось ':'");
                return std::nullopt;
            }
            ++pos_;
            SkipSpace();
            auto value = ParseValue(depth + 1);
            if (!value) {
                return std::nullopt;
            }
            for (const auto& member : object) {
                if (member.first == *key) {
                    Fail(std::format("повторяющийся ключ \"{}\"", *key));
                    return std::nullopt;
                }
            }
            object.emplace_back(std::move(*key), std::move(*value));
            SkipSpace();
            if (Peek() == ',') {
                ++pos_;
                continue;
            }
            if (Peek() == '}') {
                ++pos_;
                return Value(std::move(object));
            }
            Fail("ожидалось ',' или '}'");
            return std::nullopt;
        }
    }

    std::optional<Value> ParseArray(int depth)
    {
        ++pos_;   // '['
        Array array;
        SkipSpace();
        if (Peek() == ']') {
            ++pos_;
            return Value(std::move(array));
        }
        for (;;) {
            SkipSpace();
            auto value = ParseValue(depth + 1);
            if (!value) {
                return std::nullopt;
            }
            array.push_back(std::move(*value));
            SkipSpace();
            if (Peek() == ',') {
                ++pos_;
                continue;
            }
            if (Peek() == ']') {
                ++pos_;
                return Value(std::move(array));
            }
            Fail("ожидалось ',' или ']'");
            return std::nullopt;
        }
    }

    std::optional<Value> ParseNumber()
    {
        // Проверяем грамматику JSON (from_chars допускает больше), затем преобразуем.
        const size_t start = pos_;
        if (Peek() == '-') {
            ++pos_;
        }
        if (Peek() == '0') {
            ++pos_;
        } else if (Peek() >= '1' && Peek() <= '9') {
            while (Peek() >= '0' && Peek() <= '9') ++pos_;
        } else {
            Fail("неверное число");
            return std::nullopt;
        }
        if (Peek() == '.') {
            ++pos_;
            if (!(Peek() >= '0' && Peek() <= '9')) {
                Fail("неверное число");
                return std::nullopt;
            }
            while (Peek() >= '0' && Peek() <= '9') ++pos_;
        }
        if (Peek() == 'e' || Peek() == 'E') {
            ++pos_;
            if (Peek() == '+' || Peek() == '-') ++pos_;
            if (!(Peek() >= '0' && Peek() <= '9')) {
                Fail("неверное число");
                return std::nullopt;
            }
            while (Peek() >= '0' && Peek() <= '9') ++pos_;
        }
        double d = 0;
        const auto* first = text_.data() + start;
        const auto* last = text_.data() + pos_;
        const auto [ptr, ec] = std::from_chars(first, last, d);
        if (ec != std::errc{} || ptr != last || !std::isfinite(d)) {
            pos_ = start;
            Fail("число вне допустимого диапазона");
            return std::nullopt;
        }
        return Value(d);
    }

    static void AppendUtf8(std::string& out, char32_t cp)
    {
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }

    std::optional<char32_t> Hex4()
    {
        if (pos_ + 4 > text_.size()) {
            Fail("неполная последовательность \\u");
            return std::nullopt;
        }
        char32_t cp = 0;
        for (int i = 0; i < 4; ++i) {
            const char c = text_[pos_++];
            cp <<= 4;
            if (c >= '0' && c <= '9') cp |= static_cast<char32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') cp |= static_cast<char32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') cp |= static_cast<char32_t>(c - 'A' + 10);
            else {
                Fail("неверная последовательность \\u");
                return std::nullopt;
            }
        }
        return cp;
    }

    std::optional<std::string> ParseString()
    {
        ++pos_;   // '"'
        std::string out;
        for (;;) {
            if (AtEnd()) {
                Fail("незакрытая строка");
                return std::nullopt;
            }
            const char c = text_[pos_];
            if (c == '"') {
                ++pos_;
                return out;
            }
            if (static_cast<unsigned char>(c) < 0x20) {
                Fail("управляющий символ в строке");
                return std::nullopt;
            }
            if (c != '\\') {
                out += c;
                ++pos_;
                continue;
            }
            ++pos_;
            const char e = Peek();
            ++pos_;
            switch (e) {
            case '"':  out += '"'; break;
            case '\\': out += '\\'; break;
            case '/':  out += '/'; break;
            case 'b':  out += '\b'; break;
            case 'f':  out += '\f'; break;
            case 'n':  out += '\n'; break;
            case 'r':  out += '\r'; break;
            case 't':  out += '\t'; break;
            case 'u': {
                auto cp = Hex4();
                if (!cp) {
                    return std::nullopt;
                }
                if (*cp >= 0xD800 && *cp <= 0xDBFF) {
                    // суррогатная пара
                    if (text_.substr(pos_, 2) != "\\u") {
                        Fail("непарный суррогат в \\u");
                        return std::nullopt;
                    }
                    pos_ += 2;
                    auto low = Hex4();
                    if (!low) {
                        return std::nullopt;
                    }
                    if (*low < 0xDC00 || *low > 0xDFFF) {
                        Fail("непарный суррогат в \\u");
                        return std::nullopt;
                    }
                    *cp = 0x10000 + ((*cp - 0xD800) << 10) + (*low - 0xDC00);
                } else if (*cp >= 0xDC00 && *cp <= 0xDFFF) {
                    Fail("непарный суррогат в \\u");
                    return std::nullopt;
                }
                AppendUtf8(out, *cp);
                break;
            }
            default:
                --pos_;
                Fail("неверная escape-последовательность");
                return std::nullopt;
            }
        }
    }

    std::string_view text_;
    size_t pos_ = 0;
    ParseError error_;
};

void WriteString(std::string& out, const std::string& s)
{
    out += '"';
    for (const char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                out += std::format("\\u{:04x}", static_cast<unsigned>(c));
            } else {
                out += c;
            }
        }
    }
    out += '"';
}

void WriteNumber(std::string& out, double d)
{
    if (!std::isfinite(d)) {
        out += "null";   // в JSON нет NaN/Inf
        return;
    }
    char buf[32];
    const auto [ptr, ec] = std::to_chars(buf, buf + sizeof(buf), d);   // кратчайшая точная запись
    out.append(buf, ec == std::errc{} ? ptr : buf);
}

void Write(std::string& out, const Value& v, int indent, int level)
{
    const auto newline = [&](int lvl) {
        if (indent > 0) {
            out += '\n';
            out.append(static_cast<size_t>(indent * lvl), ' ');
        }
    };
    switch (v.type()) {
    case Value::Type::Null:   out += "null"; break;
    case Value::Type::Bool:   out += v.AsBool() ? "true" : "false"; break;
    case Value::Type::Number: WriteNumber(out, v.AsNumber()); break;
    case Value::Type::String: WriteString(out, v.AsString()); break;
    case Value::Type::Array: {
        const auto& a = v.AsArray();
        if (a.empty()) {
            out += "[]";
            break;
        }
        out += '[';
        for (size_t i = 0; i < a.size(); ++i) {
            if (i) out += ',';
            newline(level + 1);
            Write(out, a[i], indent, level + 1);
        }
        newline(level);
        out += ']';
        break;
    }
    case Value::Type::Object: {
        const auto& o = v.AsObject();
        if (o.empty()) {
            out += "{}";
            break;
        }
        out += '{';
        for (size_t i = 0; i < o.size(); ++i) {
            if (i) out += ',';
            newline(level + 1);
            WriteString(out, o[i].first);
            out += indent > 0 ? ": " : ":";
            Write(out, o[i].second, indent, level + 1);
        }
        newline(level);
        out += '}';
        break;
    }
    }
}

} // namespace

std::optional<Value> Parse(std::string_view text, ParseError* error)
{
    return Parser(text).Run(error);
}

std::string Serialize(const Value& value, int indent)
{
    std::string out;
    Write(out, value, indent, 0);
    return out;
}

} // namespace approute::json
