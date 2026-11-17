# Архитектура PEDA (форк, ветка modernize)

## Обзор

PEDA — GDB-хелпер на Python (~6300 строк в `peda.py` + `lib/`), подключаемый через
`source peda.py`. Работает как в интерактивной сессии, так и в batch-режиме
(`gdb -batch -ex ... -ex 'source peda.py'`), что активно используется тестами.

## Файлы

| Путь | Роль |
|---|---|
| `peda.py` | Весь основной код: класс `PEDA` (движок), `PEDACmd` (команды), регистрация команд/алиасов, init-блок внизу файла |
| `lib/utils.py` | `to_int`, `to_hex`, `colorize`, `message`/`msg`, `@memoized`, `reset_cache`, `tmpfile`, `pager` — **не зависит от gdb, тестируется standalone** (`tests/test_lib_utils.py`) |
| `lib/config.py` | Пути к внешним утилитам (`/usr/bin/readelf`, ...), глобальные опции peda. Чистый Python |
| `lib/nasm.py`, `lib/shellcode.py`, `lib/skeleton.py` | x86-специфика (NASM, шеллкоды, шаблоны эксплойтов) |
| `tests/` | Тестовый набор (см. [environment-and-testing.md](environment-and-testing.md)) |

## Ключевые механики (важно понимать до правок)

### `PEDA.execute_redirect(cmd)` — захват вывода GDB

Почти весь парсинг вывода GDB идёт через него. Механика: `set logging file <tmpfile>`
+ `set logging redirect on` + чтение tmpfile. Следствия:

- Исключение внутри `gdb.execute` глушится, возвращается `None` — **всегда
  проверяйте результат на `None`/пустоту**.
- При исключении логирование аккуратно выключается (иначе весь вывод сессии
  уходит в tmpfile).
- В GDB 16 команды `set logging on/off` deprecated (печатается Warning) — шум
  в начале сессии нормален.

### `@memoized` и `reset_cache()`

Кэш на функциях и методах `PEDA`. `pedaGDBCommand.invoke` вызывает
`reset_cache(sys.modules['__main__'])` **на каждую peda-команду** — кэш живёт
в пределах одной команды. `reset_cache()` обходит и методы инстансов
(`dir(peda)` → `__get__` биндит instance → `_reset()` чистит по ключу).

Внутри одного python-блока кэш НЕ сбрасывается — при патче `execute_redirect`
в тестах вызывайте `reset_cache()` вручную.

### `msg` / `@msg.bufferize` — вывод команд

`message` пишет в `self.out` (по умолчанию `sys.stdout`; в GDB python-stdout
завёрнут в GDB-канал, поэтому подчиняется `set logging redirect`). Декоратор
`@msg.bufferize` копит вывод команды в StringIO и печатает в конце.

**Критично:** wrapper делает flush в `finally` (починено в этом форке).
Исторически исключение внутри команды утекало счётчик `buffering` и весь
последующий вывод peda молча исчезал до конца сессии — именно это маскировало
все ошибки при первом запуске под RISC-V.

### `hook-stop` — контекст на каждой остановке

Init-блок определяет gdb-команду `hook-stop` → `peda context`. Любая остановка
(breakpoint/continue/stepi) печатает registers/code/stack. Следствия:

- В batch-логах вывод интерливится контекстом — тесты должны это переживать
  (grep по строкам, а не по позициям).
- Крэш в `context` роняет всю сессию по цепочке (см. riscv-port.md, eflags).

### Сессии-автосейвы

peda сохраняет `peda-session-<имя_бинаря>.txt` в **текущий каталог** gdb.
Запускайте gdb из временной директории (все тестовые скрипты так делают),
иначе мусор появится в репозитории.

### Поток данных команды (пример: `vmmap binary`)

```
Alias "vmmap" → gdb.Command.invoke
  → pedaGDBCommand.invoke → reset_cache()
    → PEDACmd.vmmap()
      → PEDA.get_vmmap("binary")
        → getpid() → get_status() → execute_redirect("info program")
        → is_target_remote()
        → _get_allmaps_linux(pid, remote)   # каскад, см. riscv-port.md
      → фильтрация по имени, форматирование, msg()
```

### Регистрация команд

- `peda <cmd>` — мастер-команда (`pedaGDBCommand`); `PEDACmd.commands` — список.
- На каждую команду создаётся `Alias(cmd, "peda cmd")` → короткие имена
  (`vmmap`, `dumpargs`, ...). Алиас `find` **перебивает** встроенную `find` GDB
  (задокументировано в README).
- Опции `pset/pshow option ...` — из `lib/config.py` (`config.Option`).
