# Портирование на AArch64: что сделано и почему

Выполнено по аналогии с RISC-V-портом (см. [riscv-port.md](riscv-port.md)) на
стенде Debian 13 / gcc-aarch64 14.2 / qemu-aarch64 10.x / gdb-multiarch 16.3.
Все решения проверены запуском; сырые данные аудита — в [pitfalls.md](pitfalls.md).

## Сценарий студента (целевой)

```sh
aarch64-linux-gnu-gcc -static -no-pie -g -O0 test.c -o test_static
qemu-aarch64 -g 1234 ./test_static          # терминал 1
gdb-multiarch -q ./test_static \
    -ex 'source /path/to/peda.py' \
    -ex 'target remote :1234' \
    -ex 'peda start'                        # терминал 2
```

Проверено также: `-static -pie` (qemu грузит с базы 0x400000), динамический
бинарник (`qemu-aarch64 -L /usr/aarch64-linux-gnu` +
`set sysroot /usr/aarch64-linux-gnu`).

## Точки входа по арху

- `_is_aarch64()`: подстрока `"aarch64"` в arch (`elf64-littleaarch64`).
- `REGISTERS["aarch64"]`: x0–x30, sp, pc — имена, которые GDB сам печатает
  в `info registers` (cpsr/fpsr/fpcr и прочее не включены — как eflags
  не включён в x86-таблицу).

Важно: `elf64-littleaarch64` содержит `"64"` — диспетчеризация в
`get_function_args` строго до catch-all ветки `"64" in arch`.

## 1. `vmmap` — без изменений

Каскад RISC-V-порта архитектурно-независим: `info proc mappings` под
qemu-aarch64 даёт тот же современный формат (колонки Perms/File).

## 2. `dumpargs` / `get_function_args()` — AArch64 ABI (x0–x7)

Два режима (зеркально RISC-V):

- **На инструкции вызова** (`bl`/`blr`): значения регистров x0–xN. Эвристика
  argc сканит инструкции до вызова; «писатели» — первый операнд
  (`mov/movz/ldr/add/...`), сторы `str/stp` исключены. Особенность: gcc
  печатает аргументные регистры в 32-битных именах (`mov w0, #0x1`) —
  `wN` нормализуется в `xN`. Objdump-комментарии (`mov w5, #0x6 // #6`)
  вырезаются.
- **На входе функции** (`break sum6`): gcc -O0 пролог НЕ тасует x0–x7
  (в отличие от RISC-V — он просто раскладывает их по стеку `str w0, [sp,#N]`),
  но код подготовки аргументов находится ДО вызова — назад за `bl` скан
  не идёт, argc неизвестен → берём значения из DWARF (`info args`),
  как и на RISC-V.

## 3. `parse_and_eval()` — границы слов

Имена `x0..x30` — валидные hex-подстроки: `"0x30"` содержит `"x30"`.
Lookbehind `(?<![\w$])` защищает: перед `x30` в `0x30` стоит `0` (\w) —
замены нет. Регресс-тесты: `ParseAndEvalTests` в
`tests/test_peda_gdb_aarch64.py`.

## 4. Ветвления: `eval_target` / `_testjump_aarch64` / `context_code`

Особенности формата AArch64 (binutils/GDB):

- мнемоника и операнды разделены **TAB** (как на RISC-V);
- операнды через запятую+пробел, могут иметь префикс `#` и хвостовой
  комментарий `// #imm`;
- цель ветвления — `0x`-hex со `<symbol>` (bare-hex fallback оставлен
  для objdump-формата);
- `ret` **без операндов** → цель в x30 (lr); regex обязан терпеть пустые
  операнды (`\s*`, не `\s+`).

Семантика — через **флаги NZCV регистра CPSR** (N=31, Z=30, C=29, V=28),
аналогично eflags на x86: к моменту остановки на `b.cond` флаги уже
выставлены предыдущей `cmp`. Таблица условий: eq/ne, cs|hs/cc|lo, mi/pl,
vs/vc, hi/ls, ge/lt (N==V / N!=V), gt/le, al/nv. Плюс:

- `cbz`/`cbnz` — регистр против нуля; ширина важна: операнд `w0` читается
  как 32-битное представление (граничный тест: x0=0x100000000 →
  `cbz w0` взят, `cbz x0` нет);
- `tbz`/`tbnz` — бит #N регистра;
- безусловные `b/bl/br/blr/ret`.

`context_code`: is_call = `bl`/`blr`; is_jump = `b`, `b.*`, `br`, `ret`,
`cbz`, `cbnz`, `tbz`, `tbnz` — точные имена (`bic`/`bfm` не ветвления).

## 5. `eflags` — graceful degradation

Без изменений (наследие RISC-V-порта): `get_eflags()` → None → warning.
`xinfo` вызывает eflags только на x86.

## Известные ограничения

- `search_asm`/`ropsearch`/`asm` — NASM/x86-only (не портировались, осознанно).
- `ret`-аннотация на RISC-V не рисуется (`ret` не в is_jump списке riscv) —
  исходное поведение riscv-порта не менялось; на AArch64 `ret` аннотируется.

## Критерии готовности (все выполнены и зафиксированы тестами)

- `vmmap` ≥ 3 строк под qemu; `vmmap binary`; `searchmem ... binary`;
  `xinfo $pc` — `tests/smoke_aarch64.sh` (13 проверок).
- `dumpargs` = 1..6 на call-site и на `break sum6` —
  `tests/test_peda_gdb_aarch64.py::CallFlowTests`.
- `b.cond` по синтетическим NZCV, cbz-ширина w/x, tbz/tbnz, br/ret —
  `BranchSemanticsTests`; предсказание сверяется с реальным `stepi`
  (включая флип через `set $cpsr`).
- Регресс: riscv (52) + x86 smoke не сломаны; aarch64-набор — 45 тестов
  в `tests/run_unit_tests.sh` (этап 3, graceful skip без тулчейна).
