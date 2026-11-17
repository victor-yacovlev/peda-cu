# Портирование на RISC-V: что сделано и почему

Выполнено по плану HANDOFF (P0–P4) на стенете Debian 13 / gcc-riscv 14.2 /
qemu-riscv64 10.0.13 / gdb-multiarch 16.3. Все решения проверены запуском;
ключевые сырые данные аудита (форматы вывода GDB, поведение qemu) перенесены
в [pitfalls.md](pitfalls.md).

## Сценарий студента (целевой)

```sh
riscv64-linux-gnu-gcc -static -no-pie -g -O0 test.c -o test_static
qemu-riscv64 -g 1234 ./test_static          # терминал 1
gdb-multiarch -q ./test_static \
    -ex 'source /path/to/peda.py' \
    -ex 'target remote :1234' \
    -ex 'peda start'                        # терминал 2
```

Проверено также: `-static -pie`, динамический бинарник
(`qemu-riscv64 -L /usr/riscv64-linux-gnu` + `set sysroot /usr/riscv64-linux-gnu`).

## Точки входа по арху

```python
def _is_x86(self):    # "i386" / "x86-64" / "80x86" в arch
def _is_riscv(self):  # "riscv" в arch
def get_regnames(self) -> dict[int, list[str]]  # REGISTERS["x86"|"riscv"]
```

`getarch()` парсит `maintenance info sections ?` → строка
`file type elf64-littleriscv.` → `("elf64-littleriscv", 64)`.
**Внимание:** подстрока для матчинга — `"riscv"` (не `elf64-riscv`, как
предполагали изначально). `getarch` безопасен при незагруженном файле
(возвращает `("unknown", 32)` вместо исключения).

`REGISTERS` — вложенная структура `{arch: {bits: [имена]}}`; riscv-имена —
ABI-алиасы, которые GDB сам печатает в `info registers` (`a0..a7`, `t0..t6`,
`s0..s11`, `zero`, `ra`, `sp`, `gp`, `tp`, `pc`, плюс `fp`).

## 1. `is_target_remote()` — детект remote-таргета

```python
conn = gdb.selected_inferior().connection       # GDB >= 12
return isinstance(conn, gdb.RemoteTargetConnection)
```

Fallback — парсинг `info program` на `"serial line"` (старые GDB) ИЛИ
`"remote debugging"` (современные). Важно: предложенный когда-то
`gdb.selected_target()` **не существует** в API — не использовать.

## 2. `get_vmmap()` — каскад из трёх источников (первый успешный выигрывает)

1. `info proc mappings` — работает под qemu-user (qemu 10 + gdb 16 проверены).
   Парсер `_parse_info_proc_mappings` терпим к форматам: с колонками
   `Perms/objfile` (GDB >= 9) и без них; числовые колонки size/offset
   пропускаются, непарсibельные строки игнорируются.
2. `remote get /proc/<pid>/maps` — для настоящего gdbserver; qemu-gdbstub
   отклоняет vFile (`Remote I/O error: Permission denied`).
3. Локальное чтение `/proc/<pid>/maps` — только если `/proc/<pid>/cmdline`
   действительно принадлежит qemu. Корректно, потому что под qemu-user
   `gdb.selected_inferior().pid` == PID хост-процесса qemu, а гостевые адреса
   совпадают с хостовыми (нет трансляции). Даёт «шумные» host-маппинги qemu —
   это осознанный last-resort.

**Гейт:** локальный нативный путь (`open(mpath).read()`) не тронут.
**Ловушка:** в теле `get_vmmap` локальная переменная `os = self.getos()`
затеняет модуль `os` — во вложенных функциях нельзя использовать `os.*`.

## 3. `dumpargs` / `get_function_args()` — RISC-V ABI (a0–a7)

Два режима:

- **На инструкции вызова** (`jal`/`call`): значения регистров a0..aN.
  Эвристика argc: скан инструкций до границы вызова (opcode из
  `call/jal/jalr/tail/c.jal/c.jalr/c.tail`), считаются записи в a0..a7
  (первый операнд у «писателей» `li/mv/addi/lw/...`; сторы `sd/sw` исключены —
  у них первый операнд источник). argc = максимальный индекс записанного + 1.
- **На входе функции** (`break sum6`): gcc -O0 пролог **ротирует и
  раскладывает аргументы по стеку** (`mv a6,a0; mv a0,a1; ... sw a5,-N(s0)`),
  поэтому регистры уже перетасованы → берём значения из DWARF (`info args`,
  метод `_get_function_args_dwarf`). Формат GDB 16 — построчный
  (`a = 1\nb = 2`), старые GDB — через запятые; парсер умеет оба. Не-int
  аргумент → `None` → откат на регистровую эвристику.

Диспетчеризация в `get_function_args` — строго `if/elif` с проверкой
`"riscv" in arch` ПЕРЕД `"64" in arch` (`elf64-littleriscv` содержит `"64"` —
иначе попадёт в x86-64 ветку). x86-пути (`_32`/`_64`) не изменены.

## 4. `parse_and_eval()` — подстановка имён регистров по границам слов

```python
exp = re.sub(r"(?<![\w$])%s(?![\w])" % re.escape(r), "$%s" % r, exp)
```

Причина: ABI-имена RISC-V (`a0`, `a7`, `t0`...) — валидные hex-подстроки;
наивный `str.replace` портил `"0x1a0b"` → `"0x1$a0b"`. Границы слов решают
и x86-случаи (`esi` не трогает `si`). Регресс-тесты: `tests/test_peda_gdb.py::
ParseAndEvalTests`.

## 5. `disassembly-flavor intel` — только x86

`set disassembly-flavor` — x86-специфичная настройка; на RISC-V GDB её
отвергает. Выставляется лениво в `disassemble()` (при `source peda.py` файл
может быть ещё не загружен и арх неизвестен); init-блок обёрнут в try/except.

## 6. Ветвления: `eval_target` / `_testjump_riscv` / `context_code`

Особенности формата RISC-V (binutils):
- мнемоника и операнды разделены **TAB** (`bge\ta5,a4,0x1052e`) — в regex
  использовать `\s`, `str.split()` без аргументов работает;
- offsetы ветвлений могут быть **bare hex** (без `0x`): `104ee <sum6+58>` —
  `to_int` такое не берёт, есть явный `int(t, 16)` fallback;
- `jr`/`jalr` берут цель из **регистра** (`jr ra`, `jalr rd,rs1,imm`) —
  отдельно от last-operand логики.

Семантика (без EFLAGS — сравнение регистров напрямую):
- безусловные `j/jal/jalr/jr/tail/c.*` → взят всегда;
- `beq/bne/blt/bge/bltu/bgeu` — таблица `(signed?, comparator)`;
  псевдо-формы `beqz/bnez/bltz/bgez/bgtz/blez` — второй операнд 0;
  compressed `c.beqz/c.bnez`.
- Значения `info registers` беззнаковые → для знаковых операций
  sign-extension по `bits` из `getarch()` (граничный тест: `blt`/`bltu`
  на `-1` vs `1`).
- `zero`/`x0` → 0; `fp` нормализуется в `s0`.

`context_code` на RISC-V: call-подобные опкоды по имени
(`call/jal/jalr/c.jal/c.jalr`), ветвления — `opcode[0] == "b"` или
`c.b*`, плюс `j/jr/c.j/c.jr`. Аннотация `JUMP is taken/NOT taken` рисуется.

## 7. `eflags` — graceful degradation

`PEDACmd.eflags`: если `get_eflags()` вернул `None` (не-x86) — warning
`"eflags is not supported on this architecture (...)"` вместо TypeError.
`xinfo` вызывает `eflags` только на x86 (`"i386" in arch or "x86" in arch`).

## 8. `peda start` на remote

`run` на remote-таргете не работает (qemu уже остановил процесс на входе) —
для remote используется `continue`. Нативный x86-путь (`run`) не тронут.

## Известные ограничения

- `dumpargs` на входе функции **без debug-инфы** показывает фактические
  (перетасованные прологом) регистры — студентам рекомендовать собирать с `-g`.
- `search_asm`/`ropsearch`/`asm` — NASM/x86-only (не портировались, осознанно).
- «No argument» у `dumpargs` на `break func` на x86 — исходное поведение
  upstream (проверено дифференцированно), на call-site работает.
- pyright-предупреждения (~530 в `peda.py`) унаследованы; ошибок нет.

## Критерии готовности (все выполнены и зафиксированы тестами)

- `vmmap` ≥ 3 строк под qemu; `vmmap binary`; `searchmem ... binary`;
  `xinfo $pc` — `tests/smoke_riscv.sh`.
- `dumpargs` = 1..6 на call-site и на `break sum6`; `dumpargs 8` = a0..a7 —
  `tests/test_peda_gdb.py::CallFlowTests`.
- Аннотация ветвлений верна для знаковых/беззнаковых на граничных значениях —
  `BranchSemanticsTests` (проверка предсказания реальным `stepi`).
- x86-регресс — `tests/smoke_x86.sh`.
