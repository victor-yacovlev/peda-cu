# HANDOFF: портирование PEDA на RISC-V (для агента на Linux)

## Контекст

Этот репозиторий — форк PEDA (GDB-хелпер, Python ~8 700 строк), используется студентами
курса «Архитектура компьютера и операционные системы» для лабораторных по RISC-V.
Типичный сценарий студента (см. `AGENTS.md`): Linux, `riscv64-linux-gnu-gcc`,
запуск под `qemu-riscv64 -g PORT`, подключение из GDB через `target remote PORT`.

Анализ кода выполнен на macOS (commit `84d38bd`, ветка `modernize`), где нет
RISC-V тулчейна и QEMU-user — поэтому всё, что связано с реальным запуском,
**не проверено на практике** и помечено ниже как «проверить». Статический анализ
показал: слово «riscv» в коде не встречается, вся архитектурно-зависимая логика —
x86-only. Ниже — задачи в порядке приоритета.

Ссылки на строки даны по commit `84d38bd`; строки могут сдвинуться,
ориентируйтесь на имена функций.

## 0. Окружение и стенд

### 0.1. Проверить окружение

```sh
riscv64-linux-gnu-gcc --version   # кросс-компилятор
qemu-riscv64 --version            # qemu-user (проверить версию: >= 5.x)
gdb-multiarch --version           # проверьте версию: важна для вывода info proc mappings
which readelf objdump             # peda ждёт /usr/bin/readelf (lib/config.py)
which nasm ndisasm                # опционально, для x86-команд asm/ropsearch
```

Если `gdb-multiarch` нет — установить: `sudo apt install gdb-multiarch
gcc-riscv64-linux-gnu qemu-user`.

### 0.2. Тестовый стенд

Создать рабочую директорию вне репозитория, например `~/riscv-peda-test/`.

`test.c` (намеренно много аргументов и ветвление — покрывает задачи 3, 5, 7):

```c
#include <stdio.h>

int sum6(int a, int b, int c, int d, int e, int f) {
    return a + b + c + d + e + f;
}

int main(int argc, char **argv) {
    int s = sum6(1, 2, 3, 4, 5, 6);
    if (s > 10)
        puts("big");
    else
        puts("small");
    printf("%d\n", s);
    return 0;
}
```

Матрица сборки (студенты используют разные варианты; PIE-бинарь — частый источник
расхождений в vmmap):

```sh
riscv64-linux-gnu-gcc -static -no-pie -g -O0 test.c -o test_static
riscv64-linux-gnu-gcc -static -pie  -g -O0 test.c -o test_pie     # может понадобиться -nopie альтернатива
riscv64-linux-gnu-gcc           -g -O0 test.c -o test_dyn         # динамический (нужен riscv64 sysroot)
```

Запуск отладочной цели и подключение (в двух терминалах):

```sh
qemu-riscv64 -g 1234 ./test_static
# другой терминал:
gdb-multiarch -q ./test_static \
    -ex 'source /path/to/peda/peda.py' \
    -ex 'target remote :1234' \
    -ex 'peda start'
```

### 0.3. Задача P0 — baseline-аудит

Прогнать под `qemu-riscv64` + `gdb-multiarch` и заполнить таблицу
(✅ работает / ⚠️ частично / ❌ ломается, с копией вывода):

| Команда | Что проверять |
|---|---|
| `peda context` | регистры / код вокруг `$pc` / стек рисуются без исключений |
| `vmmap` / `vmmap binary` | непустой ли список маппингов |
| `peda start` (break at main) | останавливается ли на `main` |
| `dumpargs` на `break sum6` | вывод аргументов (сейчас будет пустым/неверным) |
| `pattern create 100` / `pattern search` | генерация и поиск смещения |
| `checksec` | RELRO/NX/PIE для RISC-V ELF |
| `searchmem "big" binary` | поиск строки в памяти |
| `xinfo $pc`, `telescope 20` | аннотации адресов/значений |
| `pdisass` / `nearpc` | подсветка, корректность границ инструкций |
| `eflags` | поведение (сейчас — исключение/пусто) |
| `info program` (сырой вывод!) | **сохранить дословно** — нужно для задачи 1 |
| `info proc mappings` (сырой вывод) | **сохранить дословно** — нужно для задачи 2 |

Результат аудита сохранить в `HANDOFF-Linux-baseline.md`. Также зафиксировать
версии: `gdb-multiarch --version`, `qemu-riscv64 --version`, дистрибутив.

Аудит — источник истины: мои выводы ниже по каждой задаче помечены
**(предположение — проверить)** там, где они не подтверждены запуском.

## 1. Задача P1 — детект remote-таргета: `is_target_remote()`

**Где:** `peda.py`, `PEDA.is_target_remote()` (~L348).

**Проблема:** метод считает таргет remote, только если в выводе `info program`
есть подстрока `"serial line"` — формат старых GDB. В современных `gdb-multiarch`
вывод другой (предположение — проверить выводом из аудита P0: ожидается что-то
вроде `process 1 attached via /dev/tcp` или `It's a remote target`).

**Решение:** надёжный детект без парсинга текста:

```python
@memoized
def is_target_remote(self):
    try:
        return "remote" in gdb.selected_target().shortname()
    except Exception:
        out = self.execute_redirect("info program")
        return bool(out) and "serial line" in out
```

(`gdb.selected_target()` доступен в GDB ≥ 7.x с python; fallback оставить.)

**Проверка:** под qemu — `python print(peda.is_target_remote())` → `True`;
на нативном x86 бинарнике → `False`.

**Критерий готовности:** True/False в обоих сценариях; вывод `info program`
больше не парсится как единственный способ.

## 2. Задача P1 — `get_vmmap()` под qemu-user

**Где:** `peda.py`, `PEDA.get_vmmap()` (~L1394), вложенная `_get_allmaps_linux()`.

**Проблема (предположение — проверить в P0):** при remote-таргете код делает
`remote get /proc/<pid>/maps`. Gdbstub QEMU-user не реализует host I/O
(vFile-пакеты), поэтому `remote get` падает, а `getpid()` для remote inferior
возвращает 1, не PID процесса qemu. Итог — пустой vmmap, из-за него деградируют
`searchmem`, `xinfo`, `is_address`, `nxtest`, `examine_mem_value`.

**Решение — каскад из трёх источников** (первый успешный выигрывает):

1. `info proc mappings` — в новых GDB выводит таблицу с колонками
   `Start Addr End Addr Size Offset Perms objfile`. Работает, только если
   GDB сможет получить маппинги (для remote это зависит от версии пары
   GDB×QEMU — проверить в аудите). Парсить гибко: в старых GDB нет колонок
   Perms/objfile.
2. Существующий `remote get /proc/<pid>/maps` (оставить как есть).
3. **Fallback для qemu-user:** qemu-user работает локально, и гостевые
   маппинги — это маппинги процесса qemu. Найти PID процесса qemu по
   `/proc/*/cmdline` (искать `qemu-riscv64` и имя файла отладляемого
   бинараря из `getfile()`), затем прочитать его `/proc/<qemu_pid>/maps`
   локально. Это тот же трюк, что используют pwndbg/gef.

**Гейт:** не забывать, что весь `get_vmmap` должен по-прежнему работать для
нативного x86 Linux-процесса (путь `open(mpath).read()` не трогать).

**Проверка:** `vmmap` под qemu показывает ≥ 3 строки (r-x/r--/rw- бинарника
+ стек); `vmmap binary` возвращает диапазоны; `searchmem "big" binary` находит
строку в .rodata.

**Критерий готовности:** `vmmap`, `searchmem ... binary`, `xinfo $pc`,
`nxtest` работают под `qemu-riscv64 -g` для `test_static` и `test_pie`.

## 3. Задача P2 — RISC-V ABI: `dumpargs` / `get_function_args()`

**Где:** `peda.py`, `get_function_args()` (~L1000), новые `_get_function_args_riscv()`.

**Проблема:** сейчас только две ветки — `"i386" in arch` (stack-конвенция) и
`"64" in arch` (x86-64: `rdi,rsi,rdx,rcx,r8,r9`). RISC-V не попадает ни в одну.

**Решение:**

1. В `getarch()` (~L437) убедиться, что для RISC-V бинарника `arch ==
   "elf64-riscv"` (парсится из `maintenance info sections ?` → строка
   `file type elf64-riscv.`) — проверить фактически в P0.
2. Добавить `_get_function_args_riscv(code, argc=None)`:
   - аргументы — регистры `a0..a7`;
   - при `argc=None` эвристика: взять предыдущие инструкции до границы вызова
     (см. п. 3 ниже) и посчитать, сколько различных регистов из `a0..a7`
     записывается (лексемы `a0`–`a7` в первом операнде `mv`/`li`/`addi`/`lw`...);
     если ничего не нашли — вернуть пустой список (не гадать);
   - при заданном `argc` — просто взять значения `a0..a{argc-1}` через `getregs()`.
3. **Граница вызова:** в `get_function_args()` цикл по `prev_inst` прерывается
   по `"call" in inst.split()[0]`. Для RISC-V call-подобные опкоды: `call`,
   `jal`, `jalr`. Условие нужно расширить по арху (иначе «предыстория»
   инструкций уедет за вызов и эвристика argc сломается).

**Проверка:**

```
gdb-multiarch ./test_static -ex 'source peda.py' -ex 'target remote :1234' \
    -ex 'break sum6' -ex 'continue' -ex 'dumpargs'
```

**Критерий готовности:** `dumpargs` на входе в `sum6` показывает 6 аргументов
со значениями 1..6. Явное указание числа: `dumpargs 8` показывает `a0..a7`.
Регресс: на x86-64 нативном бинарнике `dumpargs` работает как раньше.

## 4. Задача P2 — словарь регистров RISC-V

**Где:** `peda.py`, глобальный `REGISTERS` (~L54); потребители:
`parse_and_eval()` (~L146), `xinfo()` (~L4843), `search_asm` (не приоритетно —
он всё равно NASM/x86).

**Проблема:** ключи словаря — разрядность x86 (8/16/32/64), значения — только
x86-имена. Для RISC-V-таргета с bits=64 будут подставлены `rax, rbx...`.

**Решение:** хранить имена по арху, например:

```python
REGISTERS = {
    "x86": {...существующие словари...},
    "riscv": {32: [...], 64: ["ra", "sp", "gp", "tp",
        "t0","t1","t2","t3","t4","t5","t6",
        "s0","s1",...,"s11",
        "a0",...,"a7", "pc"]},
}
```

и helper `get_regnames()`/доступ через текущий `getarch()`. В `xinfo`
используется `REGISTERS[bits]` — заменить на выборку по (arch, bits).
Для отображения в `xinfo`/`context_register` имеет смысл показывать ABI-имена
(`a0..a7`, `s0..`, `t0..`) — GDB их уже так выводит в `info registers`.

**Критерий готовности:** `peda context` под RISC-V рисует секцию регистров
без x86-имён; `xinfo $a0` работает; `telescope` корректно определяет значения,
равные значениям регистров (использует список имён в `examine_mem_reference`).

## 5. Задача P2 — `set disassembly-flavor intel` только для x86

**Где:** два места — `PEDA.disassemble()` (~L756) и блок инициализации
внизу `peda.py` (~L6158).

**Проблема:** `set disassembly-flavor` — x86-специфичная настройка GDB; на
RISC-V-таргете GDB её отвергает (peda глушит ошибку через `execute`, но при
`pset option verbose on` мусорный вывод; плюс лишний сбой на каждый вызов
`pdisass`/`nearpc`).

**Решение:** оборачивать в проверку аров:

```python
def _is_x86(self):
    arch, _ = self.getarch()
    return "i386" in arch or "x86-64" in arch or "80x86" in arch
```

и вызывать `set disassembly-flavor intel` только если `_is_x86()`.
Внимание: на этапе инициализации скрипта (`source peda.py`) файл ещё может
быть не загружен и `getarch()` вернёт unknown — тогда настройку можно
выполнить лениво (при первом `disassemble()`).

**Критерий готовности:** под RISC-V `pdisass`/`nearpc`/`disassemble` работают
без сообщений об ошибке flavor; на x86 вывод по-прежнему в intel-синтаксисе.

## 6. Задача P3 — `context_code`: анализ ветвлений RISC-V

**Где:** `peda.py`, `testjump()` (~L1241), `eval_target()` (~L1208),
`context_code()` (~L4259).

**Проблема:** `testjump` завязан на EFLAGS (которых на RISC-V нет), а
`eval_target` парсит x86-синтаксис (`DWORD PTR [...]). Сейчас на RISC-V
ветвлении `context_code` не может сказать «JUMP is taken».

**Решение (на RISC-V проще, чем на x86 — флаги не нужны, всё видно по
регистрам):**

1. В `eval_target` добавить ветку для RISC-V: из вывода `x/i` вида
   `0x101ac <main+24>: beq a0, a1, 0x10234` доставать операнды-адрес
   назначения (последний операнд) и выражения для GDB-парсинга.
   **Ловушка с разделителями:** binutils-дизассемблеры RISC-V выводят
   мнемонику и операнды через ТАБ (`beq\ta0,a1,0x10234`), а не через
   пробелы, как x86. В regex-парсерах использовать `\S` вместо `[^ ]`
   (пример фикс- в `xrefs`, peda.py ~L898). Метод `str.split()` без
   аргументов таб обрабатывает — им можно пользоваться.
2. В `testjump` для RISC-V: безусловные `j`/`jal`/`jalr`/`c.jalr` → взят
   всегда; условные `beq/bne/blt/bge/bltu/bgeu` (+ compressed `c.beqz`,
   `c.bnez`, `c.bltz`...) → сравнить значения регистров операндов через
   `getreg()` (для `...z`-форм второй операнд — x0/`zero` = 0; для `bltu/
   bgeu` — беззнаковое сравнение). Регистры-синонимы: `zero==x0`, `s0==fp` —
   GDB принимает оба имени.

**Проверка:** на `test.c` — брейкпоинт на `if (s > 10)`, смотреть `peda context`:
должна появляться аннотация «JUMP is taken» / «JUMP is NOT taken» в обе стороны
(проверить обе ветки, поменяв константы).

**Критерий готовности:** для `bltu`/`bgeu` (беззнаковые) и знаковых `blt/bge`
аннотация верна на граничных значениях (например −1 против 1 как unsigned/signed).

## 7. Задача P3 — `eflags` и graceful degradation

**Где:** `get_eflags()`/`set_eflags()` (~L1133), команда `eflags` (~L4774).

**Решение:** на не-x86 арах команда `eflags` должна печатать понятное сообщение
(«not supported on riscv: no flags register»), а не пустоту/исключение.
Внутренние вызовы (`testjump`) уже обрабатывают `None` — после задачи 6
`testjump` вообще не должен звать `get_eflags` на RISC-V.

**Критерий готовности:** `peda eflags` под RISC-V печатает warning и не
бросает исключение; под x86 работает как раньше.

## 8. Задача P4 — гигиена кода (опционально, делается на любой ОС)

- **38 `SyntaxWarning: invalid escape sequence`** (`python3 -W error -m py_compile
  peda.py lib/*.py` покажет все): регулярки перевести на raw-строки
  `r"\s*(.*)"`. В будущих Python это станет `SyntaxError`.
- ~~`lib/skeleton.py`: шаблоны эксплойтов генерируют Python 2-код~~
  (исправлено: шаблоны переведены на Python 3, `telnetlib` заменён).
- Алиас `find` (~L6141) перебивает встроенную `find` GDB — по меньшей мере
  упомянуть это в README.
- В `peda.py` `struct` не импортирован напрямую — приходит через star-import
  из `lib/shellcode.py`. Добавить явный `import struct` при случае.

## Правила работы

1. **Не ломать x86.** После каждого этапа — регресс на нативном x86-64
   бинарнике (Linux): `peda context`, `vmmap`, `dumpargs`, `checksec`,
   `pattern search`, `eflags`. Это же — причина держать изменения
   архитектурно-условными, а не удалять x86-код.
2. **Python 3.13+** — рудименты Python 2, `six` и `from __future__`
   удалены; аннотации типов используют нативный синтаксис 3.10+
   (`str | None`, `list[int]`). Не возвращать `from __future__`, `six.*`,
   ветки `sys.version_info`. Проверять, что код исполняется python из
   состава GDB (>= 3.13); новых зависимостей не добавлять — только
   stdlib и то, что в `lib/`.
3. **Вывод GDB парсить defensively**: формат `info proc mappings`, `x/i`,
   `info program` меняется между версиями GDB — там, где парсите, пишите
   fallback и не падайте с исключением.
4. Глобальное состояние: у команд PEDA кэш `@memoized` сбрасывается на каждый
   вызов команды (`reset_cache` в `pedaGDBCommand.invoke`). Не полагаться на
   кэш между командами.
5. Тестов в репозитории нет. По итогам P0 полезно
   добавить `tests/smoke_riscv.sh` (сборка `test_static`, запуск qemu,
   gdb-multiarch batch-режим с проверкой ключевых команд) — и прогонять его
   перед каждым коммитом.

## Резюме приоритетов

| # | Задача | Приоритет | Эффект для студента |
|---|---|---|---|
| 0 | Baseline-аудит + smoke-скрипт | P0 | источник истины, защита от регрессов |
| 1 | `is_target_remote()` | P1 | фундамент для vmmap |
| 2 | `get_vmmap()` каскад | P1 | чинит vmmap/searchmem/xinfo/nxtest под qemu |
| 3 | RISC-V ABI `dumpargs` | P2 | главный сценарий лабораторных |
| 4 | Словарь регистров RISC-V | P2 | корректный context/telescope/xinfo |
| 5 | `disassembly-flavor` только x86 | P2 | чистый вывод pdisass/nearpc |
| 6 | Анализ ветвлений в context | P3 | «JUMP is taken» для RISC-V |
| 7 | `eflags` graceful | P3 | UX |
| 8 | Гигиена (regex r-строки и пр.) | P4 | будущее Python |
