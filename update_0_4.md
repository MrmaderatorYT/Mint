# Mint 0.4 Preview — зроблено та що залишилося

Стан за кодом і [README](README.md) на 5 листопада 2026 року. Документ зіставляє початковий перелік 0.4 із наявними можливостями та незавершеними роботами. Для великих напрямів немає затвердженої повної матриці вимог, за якою можна достовірно порахувати відсоток завершення. Позначені нижче незавершені пункти включають реалізацію, перевірку та інтеграцію в наявні сценарії. Невідомі чи недоведені результати мають залишатися явно позначеними, без вигаданих семантики або типів.

## Що вже реалізовано за початковим переліком

Можливості нижче реалізовані в зазначених межах. Це не означає, що весь відповідний напрям досяг повного покриття або parity з desktop-інструментами; конкретний залишок наведено далі.

### 1. Архітектури та ISA

- Працюють декодування та native analysis pipeline для AArch64, ARM, Thumb, x86-32, x86-64, RISC-V32 і RISC-V64. Покрито scalar та окремі FP/SIMD/atomic-інструкції; невідомі семантики представлені як explicit intrinsics.
- Реалізовано окремі ARM/Thumb VFP і integer NEON, RISC-V A/F/D та compressed-патерни, AArch64 LSE і x86 LOCK operations. Семантика підтриманих операцій проходить через IR та відповідні регресійні перевірки.
- Для AArch64 ELF64 і raw-проєктів підтримується big-endian порядок даних: loader, memory, ABI, DWARF та інші підтримані шляхи враховують byte order. Memory blocks показує порядок байтів; вибір для raw AArch64 доступний при імпорті.
- Підтримуються PE32/PE32+ і little-endian Mach-O thin/universal з описаними в README обмеженими imports, relocations, fixups та unwind metadata. Є явний вибір Mach-O slice і збереження цього вибору в проєкті.

### 2. Декомпіляція та аналіз пам’яті

- Декомпілятор формує pseudo-C з умовами, циклами й частиною switch-конструкцій; для складних непідтверджених регіонів зберігаються labels і `goto`.
- Реалізовано SSA, базове відновлення типів та структур, стекові slots, reaching-store evidence і консервативні memory dependencies. Local layout recovery використовує підтверджені offsets, store/reload aliases і деякі pointer phi.
- Підтримуються обмежені transitive memory-effect summaries для перевірених локальних direct calls і міжпроцедурні свідчення про ширину та pointer-аргументи. Невідомі виклики та alias зберігають консервативні бар’єри.
- Явні прототипи підтримують низку ABI, stack parameters, окремі FP/aggregate storage, hidden result pointers та named variadic parameters. Автоматична inference має вужче покриття.

### 3. C++ і debug-метадані

- Підтримуються DWARF 2–5 із little- і big-endian даними та DWARF32/64 offsets у реалізованих форматах; доступні типи, прототипи, source lines та окремі variable locations. Є підтримка частини compressed, external і split DWARF з перевіркою доступних identity-даних.
- Реалізовано імпорт підтриманих PDB7/CodeView symbols, типів, прототипів та C13 source lines, включно з підтриманим OMAPFROM mapping; некоректні або непідтримувані дані не перетворюються на вигадані адреси.
- Є Itanium demangling, evidence-backed Itanium/Microsoft RTTI і vtable inventory, підтримані direct/virtual-base evidence та обмежений аналіз Itanium EH-frame/LSDA. Динамічні virtual-base offsets і непідтверджені exception-конструкції залишаються невизначеними.

### 4. Dynamic analysis і debugger

- Є bounded MintIR interpreter для контрольованої емуляції та підключення до наявних GDB/RSP або LLDB-DAP backend. Доступність окремих операцій залежить від backend.
- Реалізовані регістри, читання пам’яті, breakpoints, step/continue/interrupt, список потоків, явне зіставлення image/runtime addresses, DAP stack/modules і підтримані RSP module lists. Автоматично ASLR mapping не вгадується.
- У all-stop RSP реалізовано узгодження multiprocess і вибір точної пари `pPID.TID`, зокрема однакових TID у різних процесах; після зміни процесу попередні mapping і layout регістрів очищаються. Перевірки включають mock-відповіді; широку сумісність із реальними multiprocess серверами ще не підтверджено.

### 5. Плагіни та безпека

- Є версійний native C SDK, підтримані decoder/lifter/ABI extensions, commands, analysis passes і lifecycle observers. Trusted native plugins виконуються з необмеженими правами процесу застосунку.
- На Android 10+ окрему plugin-команду можна запустити в single-use isolated service з окремим UID, обмеженим обміном даними, cancellation і deadline. Є device instrumentation для окремих сценаріїв відмови в доступі, збою та зависання. Це обмежений режим, а не повний sandbox для всіх розширень чи marketplace.

### 6. Масштаб і продуктивність

- Є persistent derived analysis snapshots із перевіркою ідентичності та відновленням, а також dependency-scoped incremental reanalysis для підтриманих flow-preserving змін і окремих retargeting-випадків. Для непідтверджених випадків зберігається fallback до full analysis.
- Довгі listing завантажуються сторінками; аналіз виконується поза UI thread і підтримує cooperative cancellation. Є host, Android unit, corpus, fuzz і окремі device instrumentation тести.

### 7. Pro workflow: batch, diff і автоматизація

- Реалізовано headless-команди та permission-gated Lua scripts. Batch runner запускає незалежні аналізи з обмеженням паралельності, часу й stdout/stderr, формує статуси та зберігає результати.
- Batch checkpoint/resume перевіряє inputs, engine/tool/runner і artifacts; повторно запускає невдалі, перервані та змінені завдання. Передбачено regression tests для відновлення та пошкоджених даних; чинні обмеження runner наведено нижче.
- Version tracking підтримує порівняння функцій та інструкцій, підтвердження відповідностей, збереження identity-bound matches і preview/apply підтриманих анотацій до незалежного comparison Program. Відповідності з непідтвердженою неоднозначністю не використовуються для перенесення.
- Окремо вже існує offline three-way merge імен, коментарів і bookmarks із попереднім переглядом та виявленням конфліктів. Повноцінна командна система виключена з поточного обсягу.

### Додатково: Android UI

- Інструменти workspace згруповано за призначенням; Memory blocks показує byte order. Оновлено зелений Material-кольоровий стиль і діалоги.
- Кнопка **?** відкриває вбудовану українську/англійську довідку з поясненнями дій, умовними прикладами екранів і підсвіткою прикладів коду. У debugger список потоків може показувати process-qualified IDs.
- Після останніх змін застосунок зібрано й встановлено на Pixel 7a; пройшли 44 host-тести, 54 Android unit-тести та два debugger-тести із санітайзерами. Це результати конкретного прогону, а не гарантія повної сумісності всіх сценаріїв.

## Що залишилося

## Архітектури, ISA та формати виконуваних файлів

- [ ] Скласти й підтримувати матрицю декодування, lifting, IR, інтерпретації та тестів для AArch64, ARM, Thumb, x86-32, x86-64, RISC-V32 і RISC-V64; закрити пропуски scalar, FP, SIMD/vector, atomic, system/privileged і predication. Непідтримувані інструкції зараз залишаються explicit intrinsics.
- [ ] Розширити ARM/Thumb: умовні операції з пам’яттю, виклики, пастки й записи PC; відсутні VFP/NEON інструкції, порівняння та керування FPSCR, режими округлення і конверсії.
- [ ] Розширити RISC-V: LR/SC та модель reservation, vector та інші розширення, instruction-cache і privileged semantics, відсутні режими округлення й повні FP exception flags. Перевірити семантику на RV32/RV64 і різних конфігураціях ABI.
- [ ] Доповнити x86/AArch64 та інші режими відсутніми FP/SIMD/atomic/system-сімействами й точнішою моделлю weak-memory ordering; розширити assembler, включно з цими сімействами та branch relaxation.
- [ ] Додати big-endian для інших підтримуваних ISA та контейнерів, зокрема ELF32 і Mach-O, з наскрізними loader/ABI/debug/IR/UI тестами. Наразі реалізовано big-endian AArch64 ELF64 і відповідний raw-режим; A64 instruction bytes залишаються little-endian.
- [ ] Розширити платформені ABI та fixups: PE/Mach-O relocation, bind/rebase/chained-fixup, imports/exports, unwind і нетипові варіанти; додати відсутні Windows debug/unwind encodings та ARM/Thumb PE32.
- [ ] Розширити target ABI: ARM/Thumb stack ABI, Windows automatic inference, RISC-V E/Q і vector, складні aggregate/FP та неназвані variadic arguments. Підтвердити compiler corpus для кожного підтриманого правила.

## Декомпілятор, типи та аналіз пам’яті

- [ ] Поліпшити структурування CFG: більше loop/switch idioms і складних виходів із регіонів, менше `goto` там, де перетворення доведено зберігає edge effects та поведінку.
- [ ] Розширити розпізнавання jump tables та indirect flow за межі поточних обмежених AArch64 PIC patterns і доведених SSA finite sets; коректно позначати неповні та залежні від runtime результати.
- [ ] Реалізувати глибшу автоматичну інференцію типів і поширення aggregate/pointer types між виразами, полями, функціями та викликами; зберегти пріоритет явних і debug-декларацій.
- [ ] Розширити alias/points-to, memory SSA, heap-object, allocation/lifetime і escape recovery; обробляти незрозумілі alias та зовнішні ефекти консервативно.
- [ ] Розширити міжпроцедурний аналіз пам’яті на recursion, indirect/external calls, tail calls та більші графи викликів. Поточні bounded summaries покривають перевірені локальні direct calls, а не повний interprocedural heap analysis.
- [ ] Покращити автоматичну реконструкцію викликів, прототипів, hidden arguments, variadic і aggregate/FP storage для різних ABI. Автоматична inference зараз вужча за модель авторитетних, явно заданих прототипів.
- [ ] Розширити production corpus і перевірки правильності псевдо-C для оптимізацій, різних компіляторів, ABI, складних CFG і aliasing.

## C++, DWARF, PDB та source mapping

- [ ] Розширити відновлення об’єктної моделі C++: layout і розміри класів, construction/vtordisp, повні vtable extents, stripped classes, шаблони, multiple/virtual inheritance та runtime virtual-base offsets.
- [ ] Додати повнішу семантику Itanium і Microsoft RTTI та exception flow, включно з коректною реконструкцією try/catch у decompiler view, де вона підтверджена метаданими й CFG.
- [ ] Розширити DWARF 2–5, зокрема відсутні expression/type layouts, supplementary references і DWP packages; перевірити optimized, split і external debug metadata для обох порядків байтів. Big-endian DWARF для вже підтримуваних цілей існує; це не повна підтримка всіх DWARF edge cases.
- [ ] Розширити PDB/CodeView: type servers, legacy C11 source lines, bitfields, складні virtual/nontrivial C++ типи, інші compiler-specific records та безпечну обробку OMAPTO-only випадків без припущення про оборотність mapping.
- [ ] Покращити source-level mapping, локальні змінні й locations для оптимізованого коду; перевірити точність прив’язок на реальних compiler/linker corpus і не переносити source ranges на непідтверджений код.

## Dynamic analysis і debugger

- [ ] Додати portable RSP stack unwinding і ширшу сумісність із реальними GDB/LLDB stub та DAP backend; перевірити стек, модулі, регістри й адреси на різних платформах і пристроях.
- [ ] Розширити RSP multiprocess за межі реалізованого all-stop вибору `pPID.TID`: non-stop, fork/exec lifecycle та їхні переходи стану. Поточну підтримку пар PID/TID і process exit перевірено на mock/loopback; потрібен corpus реальних серверів і UI-перевірка з ними.
- [ ] Глибше інтегрувати runtime evidence у static analysis з позначенням джерела, актуальності та меж достовірності; не підміняти спостереженнями доведені статичні факти.
- [ ] Розширити емуляцію за межі bounded MintIR interpreter: модель процесу/ОС та необхідних зовнішніх взаємодій, контроль ресурсів і перевірка семантики. Поточний інтерпретатор не є повним процесним емулятором або sandbox.

## Плагіни та ізоляція

- [ ] Розвинути SDK та extension API: більше мовних bindings, чітка версійність і сумісність ABI, ширші hooks, документація, приклади й compatibility tests.
- [ ] Розширити ізольоване виконання за межі наявних Android 10+ окремих plugin-команд: інші платформи та потрібні види розширень; перевірити поведінку на різних пристроях і версіях Android.
- [ ] Реалізувати й перевірити жорсткі обмеження CPU, пам’яті та інших ресурсів, керований доступ до даних і безпечний IPC. Наявний deadline обмежує очікування, але не є kernel resource quota.
- [ ] Побудувати інфраструктуру спільноти: пакетування, документацію, сумісність версій, підпис/перевірку походження та репозиторій. Trusted native plugins залишаються необмеженим кодом; наявна ізоляція окремих команд не означає безпечний marketplace.

## Масштаб, продуктивність і регресії

- [ ] Розширити dependency-scoped incremental reanalysis для змін CFG, indirect-pointer dependencies, code/data boundaries і type models; узгодити інвалідацію memory/alias SSA та references. Непідтверджені випадки зараз переходять до full analysis.
- [ ] Виміряти й оптимізувати пам’ять, latency, відкриття, аналіз та індексацію великих бінарів і проєктів; розвинути background indexing і контрольоване скасування довгих native-операцій.
- [ ] Збільшити різноманітність production corpus і regression suite: реальні ELF/PE/Mach-O, компілятори, ABI, debug metadata, malformed input, fuzzing і Android-пристрої. Порівнювати інкрементальний результат із повним повторним аналізом.

## Batch, automation і version tracking

Базовий batch-блок, визначений раніше, реалізовано: checkpoint/resume з перевіркою ідентичності, повторний запуск невдалих або перерваних завдань і змінених inputs, ліміт stdout/stderr, статуси та регресійні тести. Це не означає завершення всього напрямку version tracking або автоматизації.

- [x] Розширити batch read-only командами для типів, прототипів, сигнатур, C++/DWARF та address-based listing, decompile, IR, CFG, references і metadata; адресу включено до report та перевірки checkpoint. Одна адреса застосовується до всіх inputs запуску.
- [ ] Розширити batch/headless для великих пайплайнів за межі поточного host POSIX runner і наявного набору read-only команд; визначити додаткові необхідні сценарії та стабільний контракт інтеграції.
- [ ] Усунути або явно обробити поточні межі batch: залежність від POSIX locking, відсутність жорсткого ліміту пам’яті процесу, незв’язані сторонні dynamic libraries/environment, одночасні зміни input та можливе коротке життя child після hard kill runner.
- [ ] Поглибити version tracking і semantic diff для змін під оптимізацією компілятора, register allocation, складнішого control flow й інших модифікацій; перевірити matching на ширшому corpus.
- [ ] Розширювати перенесення анотацій лише для доведених відповідностей і підтриманих видів даних. Зараз неоднозначні зіставлення, patches і type libraries не переносяться; ручні підтвердження прив’язані до ідентичності вхідних даних.

## Межі поточного плану

- Командні workflows та collaborative reverse engineering **не входять до поточного обсягу** за рішенням користувача. Наявні окремі offline annotation merge можливості не означають завершеної командної системи.
- APK/DEX і multidex/resource/manifest analysis залишаються частковими та не є поточним пріоритетом native pipeline.
- Для кожного напряму критерій завершення потрібно визначати через конкретну матрицю підтримки, поведінку для непідтримуваних випадків, інтеграцію та регресійні/реальні corpus-тести; загальну desktop parity не слід вважати досягнутою за наявністю окремих реалізованих можливостей.
