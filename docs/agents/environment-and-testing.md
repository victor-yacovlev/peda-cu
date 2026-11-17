# Окружение, стенд и тестирование

## Требуемое окружение (Linux-хост)

| Компонент | Проверенная версия | Примечание |
|---|---|---|
| Debian / другой x86-64 Linux | Debian 13 (trixie) | |
| `riscv64-linux-gnu-gcc` | 14.2.0 | `sudo apt install gcc-riscv64-linux-gnu` |
| `qemu-riscv64` | 10.0.13 | `sudo apt install qemu-user`; важна пара GDB×QEMU для `info proc mappings` (см. pitfalls) |
| `aarch64-linux-gnu-gcc` | 14.2.0 | `sudo apt install gcc-aarch64-linux-gnu`; для этапа 3 unit-тестов |
| `qemu-aarch64` | 10.x | из `qemu-user`; этап 3 пропускается без него (graceful skip) |
| `gdb-multiarch` | 16.3 | `sudo apt install gdb-multiarch` |
| `readelf`/`objdump` | binutils | пути зашиты в `lib/config.py` |
| `python3` | 3.13 | для standalone-тестов |
| `nasm`/`ndisasm` | — | опционально, только x86 `asm`/`ropsearch` |

## Тестовый стенд

Исходник `tests/assets/test.c` (6 аргументов + ветвление — покрывает ABI,
ветвления, searchmem). Матрица сборки:

```sh
riscv64-linux-gnu-gcc -static -no-pie -g -O0 tests/assets/test.c -o test_static
riscv64-linux-gnu-gcc -static -pie  -g -O0 tests/assets/test.c -o test_pie
riscv64-linux-gnu-gcc           -g -O0 tests/assets/test.c -o test_dyn

aarch64-linux-gnu-gcc -static -no-pie -g -O0 tests/assets/test.c -o test_static
aarch64-linux-gnu-gcc -static -pie  -g -O0 tests/assets/test.c -o test_pie
aarch64-linux-gnu-gcc           -g -O0 tests/assets/test.c -o test_dyn
```

Запуск под отладчиком (студенческий сценарий):

```sh
qemu-riscv64 -g 1234 ./test_static                       # терминал 1
gdb-multiarch -q ./test_static \
    -ex 'source /path/to/peda.py' \
    -ex 'target remote :1234' \
    -ex 'peda start'                                      # терминал 2
```

Динамический бинарник: добавить `-L /usr/riscv64-linux-gnu` к qemu и
`set sysroot /usr/riscv64-linux-gnu` в gdb.

## Тестовый набор — прогонять перед каждым коммитом

| Скрипт | Что делает | Объём |
|---|---|---|
| `tests/run_unit_tests.sh` | (1) standalone-тесты `lib/utils.py` обычным python3; (2) `tests/test_peda_gdb.py` — unittest внутри `gdb-multiarch -batch` под живым qemu-riscv64-таргетом; (3) `tests/test_peda_gdb_aarch64.py` — то же под qemu-aarch64 (graceful skip без тулчейна) | 15 + 52 + 45 тестов |
| `tests/smoke_riscv.sh` | командный уровень: vmmap/context/eflags/dumpargs/searchmem/checksec/JUMP-аннотация | 13 проверок |
| `tests/smoke_aarch64.sh` | то же для AArch64 (x-регистры, dumpargs x0-x7, b.cond-аннотация) | 13 проверок |
| `tests/smoke_x86.sh` | x86-64 регресс: start/context/EFLAGS/intel-flavor/vmmap/dumpargs/checksec/pattern | 10 проверок |
| `tests/regex_audit.py`, `tests/regex_functional.py` | аудит конверсии regex в r-строки | — |

Все скрипты самодостаточны: сами собирают бинарник во временный каталог,
сами выбирают свободный порт, сами убирают за собой (trap). Запускать можно
из любого каталога.

### Устройство gdb-embedded набора (`tests/test_peda_gdb.py`)

Файл **исполняется внутри GDB** (после `source peda.py` и `target remote`),
поэтому ему доступны `peda`, `REGISTERS`, `reset_cache` из `__main__`.

- Изоляция: патчинг `peda.execute_redirect` / `peda.execute` canned-выводом
  (контекст-менеджеры `patch_redirect`/`patch_execute`) + `reset_cache()` —
  `@memoized` в пределах python-блока сам не сбрасывается.
- `CallFlowTests` идут **первыми**: они ведут живую прогонку (call-site →
  entry → ветвление); остальные тесты свободно пишут регистры, что исказило бы
  argc/argv живого прогона.
- Полярность ветки `if (s > 10)` зависит от версии gcc (`bge` или `blt`) —
  тесты сверяют предсказание `testjump` с **реальным `stepi`**, а не с
  захардкоженным taken/not-taken.
- Вывод `hook-stop` (peda context) интерливится с unittest-выводом — сводка
  парсится построчно (`grep -E '^test_|^(OK|FAILED|Ran )'`).

## Ручные сценарии для проверки нестандартных случаев

- **PIE:** собрать `test_pie`, проверить `vmmap` (базовая загрузка 0x10000 у
  qemu для static-pie) и `dumpargs`.
- **Fallback vmmap №3:** в live-сессии патчнуть `execute_redirect` так, чтобы
  `"info proc mappings"` возвращал `None`, и `execute` чтобы `"remote get"`
  возвращал `False` → `get_vmmap` должен прочитать локальный `/proc/<qemu_pid>/maps`.
- **Знаковое/беззнаковое:** остановиться на ветвлении, `set $a4 = -1`,
  сравнить аннотацию для `blt`/`bltu`-семантики.

## Регламент изменений (из правил работы)

1. **Не ломать x86**: после каждого этапа — `tests/smoke_x86.sh`; изменения
   архитектурно-условные, x86-код не удалять.
2. Python 3.13+; никаких `six`, `from __future__`, `sys.version_info`.
3. Парсинг вывода GDB — всегда defensively, с fallback.
4. Не полагаться на `@memoized` между командами.
5. Не запускать gdb из корня репозитория (файлы сессий `peda-session-*.txt`
   создаются в cwd).
