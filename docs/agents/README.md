# Документация для агентов: PEDA — форк с поддержкой RISC-V

Этот каталог — база знаний для агентов (и преподавателей), работающих над репозиторием.
Документы отражают состояние после портирования PEDA на RISC-V (ветка `modernize`).

## Карта документов

| Файл | Содержание |
|---|---|
| [architecture.md](architecture.md) | Устройство кодовой базы: модули, ключевые механики GDB-Python (`execute_redirect`, `@memoized`, `msg.bufferize`, `hook-stop`), поток данных команд |
| [riscv-port.md](riscv-port.md) | Архитектурно-зависимый код: что и почему изменено для RISC-V (vmmap-каскад, ABI аргументов, ветвления, таблица регистров), критерии готовности |
| [environment-and-testing.md](environment-and-testing.md) | Окружение, тестовый стенд, все сценарии запуска (static/PIE/dynamic, x86-регресс), тестовый набор и правила его прогонки |
| [pitfalls.md](pitfalls.md) | Проверенные на практике грабли: форматы вывода GDB/QEMU, отличия версий, поведение компилятора — всё, что не очевидно из кода |

## Быстрый старт агента

1. Прочитать [architecture.md](architecture.md) → понимать, как вообще работает peda.
2. Прочитать [riscv-port.md](riscv-port.md) → понимать, где архитектурно-зависимые места.
3. Перед любыми изменениями — прогнать тесты (см. [environment-and-testing.md](environment-and-testing.md)):

```sh
tests/run_unit_tests.sh    # 15 standalone + 52 gdb-embedded тестов
tests/smoke_riscv.sh       # командный уровень под qemu (13 проверок)
tests/smoke_x86.sh         # регресс x86-64 (10 проверок)
```

4. Главные правила:
   - **Не ломать x86.** Все изменения архитектурно-условные (`_is_riscv()` / `_is_x86()`), x86-код не удалять.
   - **Python 3.13+** (тот, что в составе GDB): без `six`, `from __future__`, веток `sys.version_info`. Новых зависимостей нет — только stdlib и `lib/`.
   - **Вывод GDB парсить defensively** с fallback-ами: форматы меняются между версиями (см. [pitfalls.md](pitfalls.md)).
   - **Не полагаться на кэш `@memoized` между командами** — `reset_cache()` вызывается на каждую peda-команду.
