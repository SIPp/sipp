# SIPp

## Build

CMake-проект, C++17. Точка входа: `src/sipp.cpp`.

```sh
# Быстрый старт (требует OpenSSL, ncurses, pugixml)
cmake . && make -j$(nproc) sipp

# С GSL+PCAP+SCTP:
./build.sh --full

# Без опций:
./build.sh --none
```

Ключевые cmake-флаги: `USE_SCTP`, `USE_PCAP`, `USE_GSL`, `USE_ASAN`,
`TLS_KEY_LOGGING`, `USE_WOLFSSL`, `USE_SYSTEM_GTEST`, `USE_SYSTEM_PUGIXML`,
`USE_LOCAL_IP_HINTS`, `BUILD_STATIC`, `DEBUG`, `SIPP_MAX_MSG_SIZE`.

`./build.sh` собирает sipp + sipp_unittest (если есть gtest submodule) и
запускает юнит-тесты. Принудительно указать make: `VERBOSE=1 make`.

Версия из `git describe`. Git-субмодули: `gtest/googletest`, `third_party/pugixml`.

## Testing

Два уровня:

1. **Модульные** — блоки `#ifdef GTEST` прямо в `src/*.cpp` (8 файлов).
   ```sh
   make sipp_unittest && ./sipp_unittest
   ```
   Чтобы использовать system GTest вместо submodule: `-DUSE_SYSTEM_GTEST=ON`.

2. **Регрессионные** — shell-скрипты в `regress/github-*/run`:
   ```sh
   TEST_SKIP_VALGRIND=1 ./regress/runtests
   ```
   Переменные: `SIPP=/path/to/sipp`, `VERBOSE_EXITSTATUS=1`,
   `TEST_SKIP_VALGRIND=1`. Коды возврата: 0=ok, 1=fail, 2=unexpected_ok,
   3=expected_fail, 4=skip.

## Линтеры и форматтеры

- `./validate-src.sh` — табуляция, концевые пробелы, отступы (проверяется в CI).
- `./dtd_check.sh` — XML-валидация по `sipp.dtd` (нужен `xmllint`).
- `clang-format` (v18) — смотри `CONTRIBUTING.md`. Стиль на базе LLVM:
  4 пробела, Allman-скобки, 120 символов, указатели/ссылки справа.
  **`SortIncludes: false` — не переставлять include!**
- `cpplint.py` — Google style linter (лежит в корне).

## Архитектура

- `src/sipp.cpp` — главный исполняемый файл (не линкуется в sipp_unittest).
- `include/sipp.hpp` — центральный заголовок (`GLOBALS_FULL_DEFINITION`).
- Сценарии SIPp: `scenario.cpp`, `call.cpp`, `actions.cpp`.
- SIP-парсер: `sip_parser.cpp`.
- Сеть: `socket.cpp`, `sslsocket.cpp`.
- RTP/SRTP: `rtpstream.cpp`, `jlsrtp.cpp`.
- Свой XML-парсер: `xp_parser.cpp` + `xp_parser_ut.cpp`.
- Аутентификация: `auth.cpp`.
- Остальное: `stat.cpp`, `screen.cpp`, `logger.cpp`, `task.cpp`,
  `variables.cpp`, `strings.cpp`, `time.cpp`, `message.cpp`.

## Примечания

- Не переставлять `#include` — сборка сломается.
- Тесты писать прямо в `.cpp` рядом с кодом под `#ifdef GTEST`.
- Исполняемых целей две: `sipp` и `sipp_unittest` (EXCLUDE_FROM_ALL).
- `opencode.json` содержит команду `push` (коммит + пуш) и
  `update-changelog` (релизный процесс).
- Docker-сборка: `docker/Dockerfile` (Alpine, статический бинарник) и
  `docker/Dockerfile.debian` (Debian, с поддержкой wolfSSL).
