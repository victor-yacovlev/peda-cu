# PEDA - Хелпер для GDB предназначенный для работы с ассемблером

Форк проекта https://github.com/longld/peda

Используется студентами на курсе "Архитектура компьютера и операционные системы" при выполнении лабораторных работ по RISC-V. 

## Документация для агентов

Подробная документация по архитектуре, RISC-V-портированию, окружению, тестам и известным граблям:

→ [docs/agents/README.md](docs/agents/README.md)

Обязательно к прочтению перед изменениями в коде:

- [docs/agents/architecture.md](docs/agents/architecture.md) - устройство кодовой базы
- [docs/agents/riscv-port.md](docs/agents/riscv-port.md) - архитектурно-зависимый код и решения
- [docs/agents/environment-and-testing.md](docs/agents/environment-and-testing.md) - окружение, стенд, тестовый набор
- [docs/agents/pitfalls.md](docs/agents/pitfalls.md) - проверенные на практике грабли QEMU × GDB × gcc

## Контекст про RISC-V

Большинство студентов используют Linux. 

В качетстве компилятора используется `riscv64-linux-gnu-gcc`, для запуска программ - QEMU-user.

Студенты запускают `qemu-riscv64` с опцией `-g PORT`, а затем подключаются к нему из `gdb` с помощью `target remote PORT`
