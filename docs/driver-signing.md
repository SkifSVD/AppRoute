# Подпись драйвера approute-wfp (#51)

В Windows 10/11 с включённой проверкой подписи (Secure Boot) драйвер ядра загружается только с
подписью Microsoft. Сейчас `approute-wfp.sys` подписан лишь тестовой подписью, поэтому:

- **без подписи Microsoft правила действуют через hook-DLL** — основной путь AppRoute, подпись ему
  не нужна;
- драйвер можно проверить только в тестовом режиме Windows, в виртуальной машине (README,
  «Драйвер: сборка и проверка»). AppRoute не включает тестовый режим и не обходит проверку подписи.

## Бесплатного способа подписать драйвер нет

Подпись Microsoft для драйвера выдаётся через Partner Center (attestation signing или сертификация
HLK). Для регистрации в Hardware Developer Program нужен **EV-сертификат подписи кода** — он платный
и выдаётся физлицу или организации после проверки. Обычные (не EV) и облачные сертификаты для
программ, в том числе бесплатные для открытых проектов, драйвер ядра не подписывают.

Другие способы загрузить неподписанный драйвер (чужие или утёкшие сертификаты, отключение проверки
подписи у пользователя, загрузчики) — это приёмы вредоносного ПО. AppRoute ими не пользуется.

## Что готово в репозитории

- `src/driver/approute-wfp.inf` — INF пакета для Partner Center (класс WFPCALLOUTS). Обычная
  установка идёт без него: служба регистрирует драйвер сама (`install-service --with-driver`).
- `./tools/driver/Build-Driver.ps1 -Package` собирает пакет:
  - `build\driver\package\approute-wfp\` — `.sys` без тестовой подписи, `.inf` с `DriverVer`
    (дата сборки и версия из `CMakeLists.txt`), `.pdb`;
  - проверку INF через InfVerif (`/w`);
  - `build\driver\approute-wfp.cab` — файлы в подпапке `approute-wfp`, как требует Partner Center.
- CI собирает тот же пакет (без подписи), если на runner'е есть WDK, — артефакт
  `approute-wfp-package`.

## Шаги владельца сертификата

1. Получить EV-сертификат подписи кода (обычно на токене) и зарегистрироваться в Hardware Developer
   Program в Partner Center.
2. Собрать и подписать CAB этим сертификатом:

   ```powershell
   ./tools/driver/Build-Driver.ps1 -Package -CabCertThumbprint <SHA1 отпечаток> -TimestampUrl <URL службы меток времени УЦ>
   ```

3. Partner Center → Hardware → Submit new hardware: загрузить `approute-wfp.cab`, выбрать
   подпись для клиентских Windows 10/11 x64. Attestation-подпись действует только для клиентских
   Windows; для Windows Server нужна сертификация HLK.
4. Скачать подписанный пакет и проверить `.sys`:

   ```powershell
   signtool verify /kp /v approute-wfp.sys   # издатель — Microsoft Windows Hardware Compatibility Publisher
   ```

5. Положить подписанный `approute-wfp.sys` в выпуск рядом с `approute-gui.exe` и проверить в ВМ
   **без** тестового режима (`bcdedit /set testsigning off`, Secure Boot включён):
   `Test-Driver.ps1` и `Test-Driver.ps1 -Service`.

## Бесплатно: подпись программ (не драйвера)

Открытые проекты могут бесплатно подписывать `.exe` и `.dll` через
[SignPath Foundation](https://signpath.org/) (по заявке, сборка — в публичном CI). Драйвер это не
заменяет, но подписанные `approute-gui.exe`, hook-DLL и помощники внедрения реже вызывают
предупреждения SmartScreen и антивирусов.

## Счётчики диагностики (`Stats`)

Драйвер считает события по типам (сколько соединений и привязок подменено, пропущено и т. п.) и
при выгрузке записывает их в значение `Stats` своего раздела службы
(`HKLM\SYSTEM\CurrentControlSet\Services\approute-wfp`). Это только числа: без адресов, имён
программ и содержимого трафика; никуда не передаются. Стоимость — инкремент в памяти на событие и
одна запись в реестр при выгрузке. Счётчики остаются и в выпускной сборке — по ним `Test-Driver.ps1`
проверяет работу драйвера, и они помогают разбирать проблемы.
