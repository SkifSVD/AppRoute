#pragma once

// Конфиг правил AppRoute: %APPDATA%\AppRoute\config.json (issue #11).
//
// {
//   "version": 1,
//   "primary": "auto",
//   "rules": [
//     { "app": "C:\\...\\app.exe", "target": { "type": "adapter", "id": "{GUID}" },
//       "onUnavailable": "block", "dns": "adapter", "ipv6": "follow", "includeChildren": true }
//   ]
// }
//
// Адаптер задаётся только GUID: имя и ifIndex меняются, GUID — нет.

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace approute {

inline constexpr int kConfigVersion = 1;

// Интерфейс правила недоступен (VPN отключён): блокировать или пустить маршрутом по умолчанию (#9).
enum class OnUnavailable { Block, Default };

// DNS приложения: через интерфейс правила или системным резолвером.
enum class DnsMode { Adapter, System };

// IPv6, если у интерфейса нет IPv6-адреса: как onUnavailable, блокировать или пропустить.
enum class Ipv6Mode { Follow, Block, Default };

struct Rule {
    std::wstring app;        // полный путь (допускаются %ПЕРЕМЕННЫЕ%) или только имя файла
    std::wstring adapter;    // GUID интерфейса, "{...}" в верхнем регистре
    OnUnavailable onUnavailable = OnUnavailable::Block;
    DnsMode dns = DnsMode::Adapter;
    Ipv6Mode ipv6 = Ipv6Mode::Follow;
    bool includeChildren = true;
};

struct Config {
    std::wstring primary = L"auto";   // "auto" или GUID основного интерфейса
    std::vector<Rule> rules;
};

// %APPDATA%\AppRoute\config.json
std::wstring DefaultConfigPath();

// Разбор/запись текста конфига (UTF-8). Неизвестные поля игнорируются.
std::optional<Config> ParseConfig(std::string_view utf8, std::wstring* error);
std::string SerializeConfig(const Config& config);

// Нет файла — пустой конфиг. Ошибка чтения или разбора — nullopt и описание.
std::optional<Config> LoadConfig(const std::wstring& path, std::wstring* error);

// Атомарная запись (временный файл + замена), каталог создаётся при необходимости.
bool SaveConfig(const std::wstring& path, const Config& config, std::wstring* error);

// Правило для программы: сравнение полного пути без учёта регистра; правило с одним именем
// файла подходит программе с таким именем в любом каталоге. Полный путь важнее имени.
const Rule* FindRule(const Config& config, std::wstring_view exePath);
Rule* FindRule(Config& config, std::wstring_view exePath);

// "{GUID}" в каноническом виде или nullopt, если строка — не GUID.
std::optional<std::wstring> NormalizeGuid(std::wstring_view text);

// Проверка правила перед сохранением (GUI, approute-config): текст ошибки или nullopt.
std::optional<std::wstring> ValidateRule(const Rule& rule);

// Правило для той же программы, что app (полный путь — с полным путём, имя файла — с именем),
// кроме правила с индексом except. Для запрета дублей при добавлении и правке.
std::optional<size_t> FindDuplicateRule(const Config& config, std::wstring_view app,
                                        std::optional<size_t> except = std::nullopt);

// Значение поля app из ввода пользователя: без пробелов по краям и без кавычек вокруг пути.
std::wstring CleanAppPath(std::wstring_view input);

} // namespace approute
