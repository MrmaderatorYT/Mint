# Mint: now → production → 1.0

Дата початкової редакції: **11 листопада 2026 року**.

Ціль: випустити **робочий Android-інструмент для регулярного reverse engineering native binaries**, якому можна довіряти свої проєкти, правки й результати аналізу. Версія 1.0 не є початком відкритого бетатестування. Основні сценарії, міграції, межі підтримки, відмови та продуктивність мають бути перевірені до її випуску.

Preview може бути скільки потрібно: `0.5-preview`, `0.20-preview`, `0.123-preview`. Номер не визначає готовність. Жоден етап нижче не означає автоматичного підвищення версії; кілька preview можуть закривати один етап.

Це **план реалізації та приймання**, а не звіт про вже пройдені перевірки. Всі незакриті вимоги позначені `[ ]`. Наявна основа описана окремо; її існування не закриває production-вимогу без відповідних доказів. Числові пороги нижче — початкові вимоги цього плану, а не поточні виміряні показники Mint.

## 1. Що вже є і від чого починаємо

Вихідна основа за [README](README.md), [станом 0.4](update_0_4.md), конфігурацією збірки та тестовими інструментами репозиторію:

| Напрям | Уже реалізована основа | Що це ще не доводить |
| --- | --- | --- |
| Native pipeline | Loader → discovery/CFG → MintIR → SSA → pseudo-C; сім native ISA modes | Повноту семантики ISA та якість на всіх compiler patterns |
| Формати | ELF32/64, PE32/32+, підтримані thin/universal Mach-O, explicit raw mappings | Всі platform fixups, unwind/debug records і ABI |
| Аналіз пам’яті | Stack/reaching-store evidence, conservative alias barriers, bounded direct-call summaries зі стабільними рекурсивними SCC | Загальний points-to/heap solver, purity довільних викликів або tail-call summaries |
| Типи | Явні layouts/prototypes, DWARF/PDB imports, локальні свідчення, AArch64/AAPCS64 direct-call pointer/layout propagation | Автоматичну точну структуру чи прототип у кожному випадку; inferred layouts зараз можуть залишатися коментарями/`uintptr_t` |
| Control flow | Частина loop/switch structuring, bounded indirect-flow recovery, ранні ELF64/x86-64 signed-rel32 PIC switches | Довільні jump tables, непрямі dispatchers чи повну відсутність `goto` |
| Tail calls | Перевірені ELF64/x86-64 direct tail exits; explicit IR/SSA inputs; typed scalar SysV64 returns за доведених контрактів | Stack/FP/aggregate/variadic аргументи, довільні ABI або indirect tail calls |
| Program | Persistent overlays, patches, annotations/types, transactional edits, session undo/redo, archives, derived snapshots | Повну crash consistency, сумісність усіх майбутніх міграцій і надійність на всіх Android storage providers |
| Робочі інструменти | Listing/search/xrefs, type manager, CFG/IR/pseudo-C, exports, headless/Lua/batch, version tracking | Завершеність щоденних сценаріїв, масштаб і стабільність зовнішніх контрактів |
| Debug/extensions | RSP/DAP clients, bounded interpreter, trusted SDK, окремі isolated Android plugin commands | Загальну backend parity, повний OS emulator або безпечний marketplace |
| Перевірки | Host/unit/JNI/corpus/fuzz/device tests, ASan/UBSan | Повну production-кваліфікацію всього продукту |

Останній зафіксований у цій серії робіт прогін: 22 вибрані host-набори з ASan/UBSan та чисті SSA sweeps, включно з новими switch/tail-call сценаріями. Це baseline для відповідних змін, **не** повний release gate. Раніше зафіксовані device/unit прогони також не замінюють перевірку майбутнього release candidate.

## 2. Контракт продукту 1.0

### 2.1. Основний результат для користувача

Користувач повинен мати змогу відкрити підтриманий бінарний файл, знайти потрібну функцію, дослідити її код і виклики, виправити назви/типи/межі, перевірити вплив patches, зберегти роботу, продовжити після перезапуску й експортувати результати. Жоден крок не повинен вимагати знання внутрішньої структури Mint або ручного ремонту файлів проєкту.

Аналіз може бути неповним. **Неповнота має бути видимою та безпечною**: невідомий перехід лишається невідомим, непрозора інструкція не зникає, непідтверджений тип не стає фактом, budget exhaustion не виглядає успішним завершенням.

### 2.2. Матриця підтримки, яку треба зафіксувати

- [x] **SCOPE-01:** Створити машинозчитувану матрицю `format × target ISA/mode × byte order × ABI × operation`. Для кожної комбінації окремо вказати loader, listing, CFG, lifting, decompile, interpreter, assembler/patching, debug import та external debugging. [Матриця для baseline 0.6](docs/production/support-matrix.json).
- [ ] **SCOPE-02:** Для кожної клітинки визначити `production`, `experimental` або `unsupported`, конкретні обмеження, відповідальний набір тестів і останній release evidence. Наявність декодера не означає production decompiler.
- [ ] **SCOPE-03:** Обов’язкове ядро 1.0: ELF64/AArch64 little-endian з AAPCS64 та ELF64/x86-64 little-endian з SysV64, stripped/unstripped executable/shared libraries і типові Android/Linux toolchains. Raw-аналіз цих ISA має бути придатним до роботи за явно заданих mappings/entry/ABI; системні метадані raw не вгадуються.
- [ ] **SCOPE-04:** Для вже наявних ARM/Thumb, x86-32, RV32/RV64, big-endian AArch64, PE та Mach-O виконати окрему кваліфікацію. Рекомендована ціль — production для заявлених native browsing/analysis сценаріїв, з точними межами ABI та декомпіляції. До завершення кваліфікації вони залишаються явно experimental; це не дозволяє ігнорувати crash, втрату даних або небезпечну обробку файла.
- [ ] **SCOPE-05:** Перед feature freeze затвердити остаточний набір production-комбінацій. Не знижувати статус проваленого сценарію лише для проходження release gate. Зміна контракту потребує окремого запису з причиною та впливом на користувачів.
- [ ] **SCOPE-06:** Показувати матрицю та обмеження в документації й при відкритті відповідного формату. В інтерфейсі не називати часткову підтримку «повною».

Production-рівень означає перевірений контракт, а не реалізацію кожної інструкції, кожного компілятора та кожної ОС. Рідкісна непідтримана семантика допустима як explicit fallback; fallback у звичайному прологу, виклику чи арифметиці основного production corpus є дефектом покриття, який треба закрити.

### 2.3. Розподіл пріоритетів

| Пріоритет | Значення | Наслідок для 1.0 |
| --- | --- | --- |
| P0 | Втрата/пошкодження роботи, прихована неправильна семантика, memory safety, зависання без виходу, неправильна identity/mapping | Безумовний блокер |
| P1 | Зламаний обов’язковий сценарій, істотна прогалина production-покриття, неприйнятні ресурси/UX | Блокер відповідного production-контракту |
| P2 | Поліпшення поза прийнятим контрактом або з прийнятним документованим обходом | Може перейти після 1.0 лише з явним обґрунтуванням |

## 3. CORE — коректність аналізу та довіра до результатів

### Що має бути реалізовано

- [ ] **CORE-01 / P0:** Єдина модель повноти результату: `complete`, `partial`, `unsupported`, `budget-exhausted`, `cancelled`, `error`. Вона має проходити через native API, JNI, UI, headless та exports. «Complete» визначається для конкретного аналізу й контракту, а не для всього бінаря назавжди.
- [ ] **CORE-02 / P0:** Явні unknown effects для нерозпізнаної семантики: control flow, пам’ять, registers/flags, exceptions і ordering. Intrinsic не може дозволяти оптимізацію на підставі відсутнього опису ефектів.
- [ ] **CORE-03 / P0:** Верифікація на межах loader → discovery → IR → normalized IR → SSA → optimized SSA → AST. Невалідний результат не публікується як придатний псевдокод; доступний безпечніший нижчий рівень і зрозуміла причина.
- [ ] **CORE-04 / P0:** Перевірити всі оптимізації: widths, sign/zero extension, overflow, shifts, division traps, flags, uninitialized values, volatile/atomic/unknown memory та виклики. Неповні факти не виправдовують load folding, store elimination чи read-only.
- [ ] **CORE-05 / P0:** Відокремити inference, user/debug declarations, heuristics і runtime observations. Зберігати походження, залежності, межі доказу й причину конфлікту. Впевненість евристики не підвищує її до семантичного доказу.
- [ ] **CORE-06 / P0:** Детермінізм для однакових bytes, Program, options і engine identity. Порядок обходу maps, потоків або викликів decompiler не повинен змінювати семантичний результат. Стабільні IDs/ordering потрібні для регресій та exports.
- [ ] **CORE-07 / P1:** Діагностика причин fallback із адресою, стадією та дією для користувача: непідтриманий opcode, недоведений target, неоднозначний argument binding, конфлікт layout, перевищений budget.

### Критерії приймання

- Негативні fixtures доводять, що після unknown call/store/alias втрачаються саме потенційно застарілі факти, а незалежні доведені факти зберігаються.
- Differential/property tests порівнюють raw IR, transformed IR та виконання контрольованих оригінальних fixtures. Другий режим того самого помилкового lifter не є незалежним oracle.
- Для випадків з undefined/implementation-defined source behavior задається машинна семантика або тест виключається з еквівалентності з поясненням. Згенерований C не може випадково залежати від host UB.
- Нуль невирішених відомих випадків прихованої зміни поведінки в production-контракті. Непідтриманий випадок може дати partial output, але не неправильний «успішний» результат.

## 4. ISA — інструкції, ABI та виконувані формати

### 4.1. Інструкції й машинний стан

- [ ] **ISA-01 / P1:** Побудувати instruction-family coverage inventory для всіх семи modes. Відокремити decode, lift, optimizer understanding, interpreter та assembler. Прив’язати кожне правило до тестів widths/flags/aliasing та compiler usage.
- [ ] **ISA-02 / P1:** Для основних AArch64/x86-64 закрити звичайні compiler-generated scalar, prologue/epilogue, address calculation, calls/returns, stack protection та position-independent idioms. Вимірювати частоту intrinsic fallback у corpus за причиною й сімейством, а не одним загальним відсотком.
- [ ] **ISA-03 / P1:** Довести семантику поширених FP/SIMD families: lane widths, permutations, conversions, NaN, signed zero, rounding і статусні прапори. Там, де floating environment не змодельовано, зберігати явну операцію й відповідні effects.
- [ ] **ISA-04 / P0:** Atomic/exclusive/LOCK operations не спрощуються до звичайних незалежних loads/stores. Unsupported weak-memory/reservation/system behavior лишається бар’єром. Не заявляти еквівалентність багатопотокових програм за sequential interpreter tests.
- [ ] **ISA-05 / P1:** ARM/Thumb predication та mode transitions: перевірити IT blocks, conditional memory/call/PC writes, interworking і pointer tags. Для RISC-V — XLEN, compressed forms, ABI flags і FP register representation. Непідтримані розширення визначати явно.
- [ ] **ISA-06 / P1:** Наскрізна перевірка byte order: loader, memory reads, relocation, ABI, types/debug, interpreter, patches і exports. Розрізняти порядок даних та коду там, де вони різні.

### 4.2. ABI та виклики

- [ ] **ABI-01 / P1:** Для production ABI реалізувати й перевірити register/stack placement, alignment, narrow values, saved registers, return storage, FP/SIMD arguments, supported aggregates і hidden result pointers. Окремо фіксувати можливості авторитетних декларацій та автоматичної inference.
- [ ] **ABI-02 / P0:** Call-input binding має доводити відповідність значення, ширини й місця зберігання. Register number, сусідня assignment чи зручний predecessor не є достатнім доказом.
- [ ] **ABI-03 / P1:** Розширювати inference до returns, stack arguments і типових FP/aggregate cases на основних ABI. Кожен новий клас — через compiler fixtures з register exhaustion, spills, phis та conflicting callers. Variadic unknown arguments не домислювати.
- [ ] **ABI-04 / P1:** Для tail calls розширювати лише доведені контракти: stack/FP/aggregate forwarding, додаткові ABI, потім indirect targets. Спершу — machine exit proof, потім argument/return proof. Підтримка всіх цих випадків не є передумовою безпечного fallback у 1.0.
- [ ] **ABI-05 / P0:** Prototype/type edits мають одразу перебудовувати залежні bindings і псевдокод. Неправильний явний прототип не можна непомітно «виправляти» іншою ABI або застосовувати до несумісної цілі.

### 4.3. Loaders та platform metadata

- [ ] **FMT-01 / P0:** Checked arithmetic для offsets, sizes, virtual ranges і decompression; коректна обробка overlap, sparse mappings, truncated sections, executable/data permissions і file-backed проти zero-fill memory.
- [ ] **FMT-02 / P1:** ELF: production compiler/linker corpus для PIE/shared/stripped, PLT/GOT, TLS, REL/RELA/RELR, Android packed relocations та доступних unwind roots. Відрізняти inventory relocation від фактично застосованого fixup.
- [ ] **FMT-03 / P1:** PE: перевірити imports/delay imports, exports/forwarders, base relocation, runtime functions, unwind, CodeView identity та Windows ABI. Невідоме encoding не дає вигаданого function range або прототипу.
- [ ] **FMT-04 / P1:** Mach-O: validate slices, bind/rebase/chained fixups, exports, stubs, function starts та unwind. Зберігати точну ідентичність обраного slice у cache, archive, reopen і patch export.
- [ ] **FMT-05 / P0:** Після patches чітко розділяти змінені mapped bytes і метадані початкового контейнера. Якщо довільний patch header/fixup не підтриманий, заборонити або позначити межу; не показувати loader state як свіжо розібраний patched file.
- [ ] **FMT-06 / P1:** Broken optional debug/unwind metadata не має знищувати придатний base binary analysis. Часткова відмова описується окремо; небезпечний основний контейнер відхиляється до публікації Program.

### Критерії приймання ISA/ABI/formats

Кожна production-комбінація має executable, shared-library та stripped variants, позитивні compiler fixtures, malformed negatives і наскрізний UI/headless сценарій. Для машинних семантик потрібні boundary cases, а не лише приклад з типовими числами. Непідтриманий формат/режим відхиляється явно, без автоматичного переходу в raw із довільною архітектурою.

## 5. DECOMP — читабельна та семантично коректна декомпіляція

### 5.1. Discovery та control flow

- [ ] **CFG-01 / P0:** Відрізняти доведені function entries, candidate roots, shared code, tail exits і випадкові дані. Не поглинати сусідню функцію лише для отримання «повного» CFG.
- [ ] **CFG-02 / P1:** Зібрати inventory compiler switch idioms на основних цілях і додавати найчастіші: relative/absolute tables, index normalization, range guards, duplicate targets, default exits. Всі guards доводяться для реально використаного index на всіх шляхах.
- [ ] **CFG-03 / P0:** Зберігати case index → target та edge effects через discovery, IR, SSA і AST. Unknown/partial table, mutable data, external target або limit не можуть завершувати CFG без доказу.
- [ ] **CFG-04 / P1:** Поліпшити loop/region structuring: nested loops, multiple exits, early returns, short-circuit conditions, shared switch tails, continue/break. Неперетворювані irreducible regions лишаються labels/goto з точною поведінкою.
- [ ] **CFG-05 / P0:** Непідтверджений computed transfer у псевдокоді не підміняється звичайним `return 0`, пустим блоком або успішним fallthrough. Якщо synthetic default доведено недосяжним, це має бути відображено як unreachable, а не можлива поведінка вихідної програми.

### 5.2. Змінні, expressions і типи

- [ ] **TYPE-01 / P1:** Стабільне відновлення локальних змінних: live ranges, split/reused stack slots, spills, overlapping accesses, pointer escapes. Promoted locals мають зберігати memory semantics та debug/user bindings.
- [ ] **TYPE-02 / P1:** Зменшити шум temporaries, flag calculations, зайвих casts і low-level ABI helpers там, де є доведена заміна. Не прибирати statements лише тому, що вони погано виглядають.
- [ ] **TYPE-03 / P0:** Пріоритет і provenance: user declaration → підтримані authoritative debug facts → analysis evidence → heuristic suggestion. Конфлікт зберігати та показувати; imported metadata теж може бути stale або непідтриманою.
- [ ] **TYPE-04 / P1:** Розширити pointer/layout propagation на returns, кілька callers, додаткові production ABI та підтримані shifted pointers. Offset від поля не стає початком об’єкта; різний layout не породжує вигаданий union.
- [ ] **TYPE-05 / P1:** Довести inference до корисного presentation: запропонований layout можна переглянути й явно прийняти як тип; після прийняття підтримані accesses використовують field names. Автоматично inferred declarations мають бути чітко відмінні від authoritative та не публікувати конфліктну точність.
- [ ] **TYPE-06 / P0:** Тип не доводить identity об’єкта, lifetime, noalias або read-only. Жодне type-only поліпшення не послаблює memory barriers.
- [ ] **TYPE-07 / P1:** Стабільні function/local names та code-to-pseudo mapping після локальних правок; cross-navigation до відповідних instructions/IR/CFG nodes. При неоднозначній mapping показувати range/невизначеність.

### 5.3. Аналіз пам’яті та міжпроцедурні факти

- [ ] **MEM-01 / P0:** Формалізувати summary contract: початковий unknown/bottom, merge/join, можливі writes, escapes, effect completeness і return behavior. Порожній проміжний набір не є read-only.
- [ ] **MEM-02 / P0:** Перевірити bounded SCC fixed-point для memory та type evidence: спільна збіжність, deterministic merge, конфлікти, offset growth, recursion budgets, transactional publication. Незбіжність залишає conservative fallback для залежних висновків.
- [ ] **MEM-03 / P1:** Розширити точність на практичні випадки: підтримані direct tail calls, відомі бібліотечні ефекти з versioned contracts, додаткові pointer origins. External contract не застосовується лише за схожим ім’ям символу.
- [ ] **MEM-04 / P1:** За даними corpus визначити потрібні bounded allocation/escape/object facts. Реалізовувати окремими перевірюваними моделями; повний heap recovery і загальний points-to solver не є умовою 1.0.
- [ ] **MEM-05 / P0:** Summary/type/memory sidecars залежать від bytes, callee graph, prototype/ABI/type revisions та options. Повторне використання дозволене лише за збігу всіх релевантних залежностей.

### Критерії приймання DECOMP

- Semantic fixtures перевіряють return values, observable writes, edge effects і terminal transfers; «рядок містить switch» недостатньо.
- Для визначеної підтриманої підмножини pseudo-C компілюється з перевіркою типів і виконується на контрольованих inputs. Реальні недовірені binaries не запускаються для такого тесту без окремого контрольованого середовища.
- Відмінності з reference tools використовуються для пошуку проблем, але результат IDA/Ghidra сам по собі не є доказом правильності Mint.
- Для кожного production target є reviewed samples з типовими optimized functions: людина може простежити основну логіку без переходу до IR для кожної операції. Перелік samples та конкретні зауваження фіксуються, а не замінюються оцінкою «стало красивіше».

## 6. DEBUGDATA — DWARF, PDB, C++ та source mapping

- [ ] **DBGDATA-01 / P0:** Перевіряти identity external debug objects: build IDs, debuglink CRC, split-unit IDs, PDB GUID/age та доступні інші ознаки. Реальний mismatch не обходиться підтвердженням користувача про відсутній ID.
- [ ] **DBGDATA-02 / P1:** DWARF: optimized locations, ranges, inlining, type references, compressed/external/split дані, DWARF32/64 і byte order у production-матриці. Непідтримані expressions або supplementary references лишають часткові дані з причиною.
- [ ] **DBGDATA-03 / P1:** PDB/CodeView: поширені MSVC/clang-cl types, prototypes, bitfields, source lines, address mappings та optimized builds. OMAP не інвертувати без доказу однозначності.
- [ ] **DBGDATA-04 / P1:** C++ inventory має коректно представляти підтримані primary/secondary vtables, base offsets, this adjustments і RTTI. Не змішувати construction tables з остаточним layout; dynamic virtual bases лишають symbolic offsets.
- [ ] **DBGDATA-05 / P0:** Exception/unwind control flow не губиться при звичайній структуризації. Якщо try/catch reconstruction не доведена, зберігати низькорівневі landing-pad/exception edges та межі підтримки.
- [ ] **DBGDATA-06 / P1:** Source navigation має працювати з відсутнім source file, кількома compilation units і неоднозначними line ranges. Не відкривати довільні шляхи з metadata автоматично; користувач задає source roots/remapping.

**Приймання:** compiler/linker fixtures із source truth та stripped/debug-sidecar variants; конфлікти user/debug не стирають edits. Повна реконструкція довільних C++ класів, шаблонів та source-level exceptions не є умовою 1.0, але UI не має видавати inventory за повне відновлення класу.

## 7. STATE — проєкти, правки, кеші та міграції

Це безумовний production-блокер. Надійність збереженої роботи важливіша за додатковий decoder або красивіший псевдокод.

- [ ] **STATE-01 / P0:** Документувати й перевірити transaction boundaries для user edits, Program serialization та derived cache publication. На помилці зберігається попередній валідний стан або повністю новий, без суміші revisions.
- [ ] **STATE-02 / P0:** Fault injection: kill/process death на кожній фазі save/import/archive/restore/export, disk full, short write, denied permission, provider disconnect, checksum error. Обробити можливі відмінності atomic rename/fsync на доступних storage paths.
- [ ] **STATE-03 / P0:** Відновлення після process death та Android lifecycle: background, rotation, activity recreation, low-memory kill і холодний старт. Збережені edits не губляться; незбережений стан/незавершена операція мають явну політику recovery.
- [ ] **STATE-04 / P0:** Міграції всіх збережених підтриманих Program versions до поточної. Golden fixtures містять patches, raw configs, Mach-O selection, debug bindings, types, names/comments/bookmarks і local bindings. Новіша несумісна версія відхиляється без перезапису.
- [ ] **STATE-05 / P0:** Undo/redo є атомарним для взаємопов’язаних edits. Задокументувати, що є session-only і які ліміти history. Persistent undo не обов’язковий, але користувач не повинен очікувати його після reopen через неправильний UI.
- [ ] **STATE-06 / P0:** Єдиний dependency/invalidation contract для code/table patches, boundaries, type/prototype changes, library imports та options. Старі IR/SSA/summaries/references/pseudo-C не можна показувати як поточні.
- [ ] **STATE-07 / P0:** Incremental, restored та fresh-full results семантично збігаються. Перевіряти не лише counts, а membership, decode modes, edges, case mapping, callees, xrefs, summaries, types та pseudo-C facts.
- [ ] **STATE-08 / P0:** Пошкоджений derived cache можна викинути без втрати user state. Recovery доступний у UI; повторний full analysis не застосовує stale proof annotations.
- [ ] **STATE-09 / P0:** Import/archive/export не перезаписують чужий проєкт або source binary. Перевіряти path traversal, duplicate ZIP entries, decompression bounds, identity та unselected Mach-O slices.
- [ ] **STATE-10 / P1:** Керування проєктами: зрозумілі назви, розмір, стан, дата останнього збереження, duplicate/import behavior, backup/restore і явне видалення. Нестача місця повідомляється до руйнівних дій.

**Приймання:** автоматичні fault-injection та migration suites, випадкові послідовності edits/undo/redo/reopen із порівнянням із clean analysis, device lifecycle tests. Нуль відомих відтворюваних втрат підтверджених edits або непомітних stale results.

## 8. UX — завершені щоденні робочі сценарії

- [ ] **UX-01 / P1:** Import без неоднозначності: формат, ISA/mode, slice, byte order, raw base/entry і обмеження. Для unsupported input є діагностика та повернення до робочого workspace.
- [ ] **UX-02 / P1:** Єдина навігація між functions, listing, pseudo-C, CFG, IR, xrefs і source. Back/forward та selection працюють після reanalysis і не ведуть на неіснуючий SSA ID.
- [ ] **UX-03 / P1:** Практичний пошук: symbols, strings, bytes/patterns, addresses, comments; cancellation, результат із контекстом і стабільне повернення зі знайденої функції.
- [ ] **UX-04 / P1:** Rename, comments, bookmarks, type/prototype/local edits, code/data та function boundaries мають validation, preview релевантного впливу й recovery після помилки. Помилковий input не очищає попередню роботу.
- [ ] **UX-05 / P1:** Patch workflow: old/new bytes, address/mode, assembly validation, зміна довжини інструкцій, affected region, undo та patched-copy export. Непідтриманий assembler не генерує приблизні bytes.
- [ ] **UX-06 / P1:** Analysis status: стадія, partial results, cancellation, resource limit, retry/reanalyze. Не використовувати безкінечний spinner як універсальний стан; не показувати 100% до завершення публікації.
- [ ] **UX-07 / P1:** Великі listing/graphs/search results пагінуються або віртуалізуються. Для надто великого CFG є bounded view/filter/explicit export; не створювати всі UI nodes без обмеження.
- [ ] **UX-08 / P1:** Touch і physical keyboard: selection/copy, довгі імена, адреси, zoom/scroll, доступність labels, font scaling, contrast, portrait/landscape. Перевірити українські/англійські тексти, відсутність обрізаних критичних повідомлень.
- [ ] **UX-09 / P1:** Вбудована довідка відповідає фактичній версії, пояснює unknown/fallback, типи evidence, save/backup та limits. Жодних мертвих кнопок або команд, що завершуються лише загальним «not implemented» у production flow.

**Обов’язкові acceptance journeys на пристрої:**

1. Import ELF → function/string search → xrefs → decompile → rename/comment/type → save → cold reopen.
2. Stripped optimized switch → case navigation → tail handler → CFG/IR correspondence → export.
3. Patch code/table → змінений analysis → undo → redo → reopen → порівняння з fresh full analysis.
4. Import debug metadata → prototype/local edit → conflict resolution → export/restore archive.
5. Raw або qualified secondary format → correct mapping/mode → edit → reopen з тією самою identity.
6. Cancel/low-memory/process death/storage failure → відновлення придатного проєкту без ручного ремонту.

Кожен journey має пройти на release build звичайними UI діями. Host-тест відповідного native API не замінює цей доказ.

## 9. PERF — масштаб, ресурси та відсутність зависань

### Реалізація

- [ ] **PERF-01 / P1:** Ввести budget accounting на всіх графових/парсерних етапах: bytes, functions, instructions, edges, SSA links, recursion/iterations, decompression і output size. Ліміти мають бути узгоджені, доступні в diagnostics і не спричиняти хибну повноту.
- [ ] **PERF-02 / P1:** Профілювати cold import, discovery, first decompile, warm reopen, search/xrefs, patches/reanalysis, serialization, JNI copies та UI rendering. Вимірювати wall time, CPU, peak native/Java/PSS memory, temporary disk і cancellation latency.
- [ ] **PERF-03 / P1:** Lazy analysis/indexing і bounded caches: не тримати SSA всіх функцій одночасно; контрольований eviction; background work не витісняє foreground navigation.
- [ ] **PERF-04 / P1:** Розширювати incremental reanalysis лише зі збереженням equivalence з full. Full fallback прийнятний, якщо він видимий, cancellable і вкладається в задекларований профіль.
- [ ] **PERF-05 / P0:** Cancellation доходить до довгих native loops, imports і parser work. Якщо окремий stage не може бути перерваний у встановлений час, потрібна bounded chunking або worker-process boundary.
- [ ] **PERF-06 / P1:** Коректний memory-pressure режим: зменшення caches, відмова від важкого запиту до OOM, збереження роботи. Відмова «цей файл перевищує підтриманий профіль» краща за падіння процесу.

### Початкові числові вимоги, які треба виміряти й зафіксувати

Розмір файла сам по собі не визначає складність. Профіль містить також кількість decoded instructions, functions, relocations/debug bytes і графові budgets.

| Профіль | Reference device | Початкова ціль |
| --- | --- | --- |
| Звичайний | Фізичний ARM64 Android, 4 GiB RAM; native файл до 10 MiB, до 100 тис. instructions | Import/discovery ≤ 15 с; cold selected-function decompile ≤ 3 с для функції до 2 тис. IR ops; warm reopen ≤ 3 с |
| Великий | Фізичний ARM64 Android, 8 GiB RAM; файл до 50 MiB, до 1 млн instructions | Import/discovery ≤ 120 с; warm reopen ≤ 10 с; функція до 10 тис. IR ops ≤ 10 с або явний bounded partial result |
| Stress | Визначений high-memory device; файл до 200 MiB або патологічний граф | Немає обіцянки повного аналізу за короткий час; обов’язкові budgets, cancellation і збереження працездатності |

Спільні цілі: UI input response p95 ≤ 100 мс поза системними діалогами; cancellation p95 ≤ 2 с і max ≤ 5 с у підтриманому профілі; peak PSS ≤ 25% RAM reference device у звичайному та великому профілях; відсутні ANR у приймальних сценаріях. Для операцій із менше ніж 20 вимірюваннями публікувати всі значення, а не статистично слабкий p95.

**PERF-07 / P1:** На етапі baseline визначити точні device models, Android builds, thermal/battery conditions, corpus manifest та заморожені thresholds. Якщо наведені початкові цілі потребують зміни, рішення з причиною приймається до RC, а не після проваленого release test. Підвищення лімітів без контролю пам’яті не є оптимізацією.

**Приймання:** не менше 20 повторів ключових latency-сценаріїв після контрольованого warm-up; cold/warm дані окремо; тривала сесія щонайменше 2 години з повторними edits/decompile/reopen без необмеженого росту пам’яті. Перевірити нижню межу Android API 26, актуальну підтриману версію на момент RC і проміжні API з релевантними storage/lifecycle змінами.

## 10. SECURITY — недовірені файли та extensions

- [ ] **SEC-01 / P0:** Threat model для binary/debug parsers, archives, project files, Lua, native plugins, debugger protocol та exports. Статичний аналіз файла не означає безпечність його запуску.
- [ ] **SEC-02 / P0:** Fuzz targets безпосередньо для loader/debug/project/archive/protocol parsers і stateful edit sequences; coverage feedback, minimized reproducers, time/memory limits. ASan/UBSan findings стають регресіями після виправлення.
- [ ] **SEC-03 / P0:** Untrusted input не запускає код, не завантажує plugins, не відкриває мережу й не читає довільні зовнішні paths автоматично. Source/debug paths — лише suggestions для явного вибору.
- [ ] **SEC-04 / P0:** Чітке розділення trusted native extensions і isolated commands. Native loading потребує явного вибору та пояснення прав; isolated mode не називається повним sandbox для всіх SDK hooks.
- [ ] **SEC-05 / P0:** Перевірити isolated IPC, descriptor access, cancellation, service death та timeout на пристроях. Deadline очікування не видається за CPU/RAM quota. Якщо обіцяється hard resource limit, реалізувати його на відповідній процесній/системній межі й довести тестом.
- [ ] **SEC-06 / P1:** Lua permissions за замовчуванням мінімальні, явні для file/network/modify actions; budgets і cancellation; відмова permission не лишає половину Program edit.
- [ ] **SEC-07 / P0:** Diagnostic/support export не містить binary bytes, private paths, notes або credentials без окремого зрозумілого вибору. Локальні логи також обмежені за розміром.
- [ ] **SEC-08 / P1:** Dependency inventory, licenses/notices, pinned versions/checksums, процедура security updates і контакт для приватного повідомлення про вразливість. Підпис релізу й ключі зберігаються поза репозиторієм.

**Приймання:** нуль відкритих підтверджених memory-safety/доступових проблем у shipping paths; regression corpus для кожної знайденої помилки. Перед RC — мінімум 24 CPU-години coverage-guided fuzzing для кожної основної групи parser surfaces після останньої суттєвої зміни та окремий stateful run. Кількість годин є мінімумом кампанії, не доказом відсутності вразливостей; plateau coverage та непокриті surfaces аналізуються окремо.

## 11. TOOLS — debugger, interpreter, SDK, batch і diff

### Debugger та interpreter

- [ ] **DYN-01 / P1:** Capability-driven UI для реальних RSP/DAP backends: доступні registers, memory, threads/processes, modules, stack, breakpoints, step/continue/interrupt. Unsupported operations вимкнені з причиною.
- [ ] **DYN-02 / P0:** Явний address mapping/ASLR та identity процесу/образу; switch process/exec/reconnect скидає старі mappings і register layouts. Read/write/patch адреси не переносяться між процесами за одним TID.
- [ ] **DYN-03 / P1:** Qualification на реальних GDB-compatible server і LLDB-DAP, а не лише mocks: attach, disconnect, target exit, concurrent events, protocol truncation/timeouts. Публікувати конкретні перевірені backend versions.
- [ ] **DYN-04 / P1:** Runtime evidence має timestamp/process/module identity та статус observed. Один побачений indirect target не доводить повноту static CFG; запис у target memory інвалідує відповідні observations.
- [ ] **DYN-05 / P0:** Interpreter має точні stop reasons, budgets, memory permissions і external-effect boundaries. Tail transfer не виконує зайві stack push/pop. Непідтримана інструкція не стає no-op.

Portable stack unwinding, non-stop/fork debugging і повна OS emulation можуть залишатися поза production-контрактом 1.0. Усі shipping debugger actions мають пройти своє приймання; «experimental» не виправдовує запис за неправильною адресою.

### SDK та plugins

- [ ] **SDK-01 / P1:** Version negotiation, struct sizes, ownership/lifetimes, threading/reentrancy, cancellation і error contracts у C SDK. Несумісний plugin відхиляється до виклику його hooks.
- [ ] **SDK-02 / P1:** Приклади command/pass/decoder/lifter/ABI extension збираються як незалежні зовнішні projects у CI. Conformance tests перевіряють limits, неправильні outputs і invalidation.
- [ ] **SDK-03 / P0:** Plugin-produced IR/types/targets проходять ту саму верифікацію. Trusted native plugin може зламати процес, тому recovery не повинен вимагати знову автоматично його завантажувати.

Marketplace, кілька language bindings та portable sandbox не є умовою 1.0. Автоматичне встановлення стороннього executable code потребуватиме окремого security/product контракту.

### Headless, automation та version tracking

- [ ] **AUTO-01 / P1:** Стабільні versioned JSON schemas, exit codes, machine-readable partial/error/limit statuses, deterministic ordering і compatibility policy. Human pseudo-C не є стабільним API schema.
- [ ] **AUTO-02 / P0:** Batch checkpoint/resume прив’язаний до input snapshot, tool/engine/options/environment та artifacts. Input mutation під час роботи дає явний failure/retry, не змішаний звіт.
- [ ] **AUTO-03 / P1:** Керування child lifetime/process groups, timeout, output caps, memory limits для підтриманого host runner. Після kill runner не лишаються неконтрольовані descendants; платформені обмеження описані явно.
- [ ] **DIFF-01 / P1:** Matching розрізняє candidate, ambiguous, confirmed; semantic diff стійкий до register allocation та простих compiler transformations у прийнятому corpus. Не називати byte difference семантичним доказом.
- [ ] **DIFF-02 / P0:** Annotation transfer має preview, identity binding, conflicts і атомарне apply/undo. Не переносити types/patches на приблизний match без окремого доведеного контракту.

**Приймання:** independent consumer JSON fixtures, interrupted/resumed batch tests, реальні backend sessions і diff/transfer corpus із навмисними неоднозначностями.

## 12. QA — доказова база, CI та production corpus

- [ ] **QA-01 / P0:** Створити єдиний quality entry point і CI на обраному сервісі. Сьогодні наявність окремих test tools не означає, що всі вони обов’язково виконуються на кожному release.
- [ ] **QA-02 / P1:** Розділити fast PR checks, nightly corpus/sanitizers/fuzz та release qualification. Timeout/skipped/unavailable toolchain не вважаються passed; є звіт про непокриті платформи.
- [ ] **QA-03 / P1:** Зберігати manifest corpus: origin/license, checksum, ISA/ABI/format, compiler/linker versions/options, debug/stripped status, expected properties, limits і причина включення. Закриті/користувацькі binaries не потрапляють у публічні artifacts.
- [ ] **QA-04 / P1:** Початковий мінімум production corpus: 200 різних source programs/projects; принаймні 60 для кожної основної ISA та 10 для кожної додаткової production format/ISA/ABI-комбінації. Один source у 20 optimization variants рахується як одна програма; перетини підмножин у manifest позначаються явно. За потреби загальна кількість зростає, щоб виконати всі квоти.
- [ ] **QA-05 / P1:** Окремо compiler matrix: щонайменше два сімейства compiler/linker для основних production цілей, де вони реально доступні; `O0/O1/O2/O3/Os`, LTO і без LTO, PIE/shared, stripped/debug. Для Android/Linux це включає Clang та GCC corpus; для qualified Windows — MSVC/clang-cl.
- [ ] **QA-06 / P0:** Semantic suite охоплює branch/phi/loop/switch edge effects, signed widths, ABI spill/exhaustion, alias, recursion, unknown calls, exceptions/fallback, patches і resource limits. Новий pass не приймається лише за snapshot тексту.
- [ ] **QA-07 / P0:** Stateful Program suite: редагування, prototype/type changes, code/table patches, undo/redo, cache corruptions, migration, archive/reopen та incremental-vs-full equivalence.
- [ ] **QA-08 / P1:** Android unit/JNI/instrumentation та physical-device matrix; обидва shipping app ABIs (`arm64-v8a`, `x86_64`) проходять build/native smoke, ARM64 — фізичні acceptance journeys. Emulated target ISA не плутати з ABI самого Android-застосунку.
- [ ] **QA-09 / P1:** Versioned baselines для coverage, latency/memory і reviewed pseudo-C. Кожне погіршення має пояснення; автоматичне оновлення snapshots не закриває semantic regression.
- [ ] **QA-10 / P1:** Кожен виправлений production bug отримує minimized regression і вказання, чому старі перевірки його пропустили. Flaky tests виправляються або явно блокують gate; тихі reruns до зеленого заборонені.

**Приймання:** один release report показує результати всіх рівнів на одному source revision/engine identity, toolchain versions, failures/skips, sanitizer/fuzz artifacts, device evidence та performance comparisons. Corpus size не замінює семантичне покриття; явно перелічені неперевірені класи сценаріїв.

## 13. RELEASE — збірка, дистрибуція та підтримка

- [ ] **REL-01 / P0:** Відтворювана процедура clean checkout → dependencies/toolchains → host tests → Android unit/JNI/device checks → optimized release APK/AAB. Без прихованих developer-local файлів, окрім signing secrets.
- [ ] **REL-02 / P1:** Release manifest містить source revision, dirty-tree policy, engine identity, dependency versions, build flags, target SDK/NDK та hashes unsigned/signed artifacts. Published release збирається з зафіксованого чистого revision; uncommitted prototype не є релізним джерелом.
- [ ] **REL-03 / P0:** Перевірити саме minified/resource-shrunk release build: JNI names, reflection, services, imports/exports, debugger і plugins. Успішний debug build не закриває цей пункт.
- [ ] **REL-04 / P0:** Update qualification: install старої підтриманої версії → створити реальну роботу → update без clear-data → migration/reopen/edit/export. Downgrade behavior визначений; старий застосунок не має пошкоджувати нові projects.
- [ ] **REL-05 / P1:** Signing-key backup/recovery, monotonic versionCode, distribution-channel procedure, artifact verification і rollback/hotfix plan без небезпечного downgrade Program format.
- [ ] **REL-06 / P1:** User documentation: installation, quick start, support matrix, tutorials, unknown/fallback, backup/recovery, patch limitations, SDK/headless contracts, known issues і changelog.
- [ ] **REL-07 / P1:** Privacy policy та distribution listing відповідають фактичному local analysis, explicit network debugger, plugins і diagnostic exports. Створення юридичних/store artifacts потребує окремої перевірки актуальних вимог перед публікацією.
- [ ] **REL-08 / P1:** Процес bug reports: версія, engine identity, device, steps, safe diagnostic bundle; користувач може повідомити проблему без надсилання приватного binary. Security reports мають приватний канал.
- [ ] **REL-09 / P1:** Визначити підтримувані Android versions/devices, policy оновлень/міграцій і порядок термінового виправлення P0. Документувати, які старі Program versions продовжують читатися.

## 14. Послідовність робіт без прив’язки до номерів preview

| Етап | Що робимо | Вихідний артефакт / gate |
| --- | --- | --- |
| A — Baseline і контракт | SCOPE, повний поточний прогін, inventory дефектів, corpus manifest, reference devices, перші профілі | Підписаний у репозиторії scope; список P0/P1; виміряний baseline; жодних вигаданих відсотків готовності |
| B — Цілісність і коректність | CORE, STATE, parser safety, invalidation, fault injection, CI skeleton | Немає відкритих відомих P0 у базових journeys; edits/reopen/cache equivalence доведені |
| C — Основна якість аналізу | Найчастіші ISA/ABI gaps, CFG/DECOMP/TYPE/MEM, debug evidence | Production corpus виконує semantic/coverage contracts; reviewed псевдокод придатний до роботи |
| D — Продукт і масштаб | UX, PERF, secondary target qualification, debugger/SDK/headless contracts | Завершені physical-device journeys; затверджені SLO; всі shipping features мають статус і докази |
| E — Hardening | Повні stress/fuzz/migration/device campaigns, release builds, документація/дистрибуція | Усі обов’язкові gates зелені; release manifest та known issues готові |
| F — Release candidate | Feature freeze, внутрішня щоденна робота, повторна кваліфікація лише після релевантних змін | Стабільний RC на тому самому artifact; виконані умови розділу 16 |
| G — 1.0 і підтримка | Публікація перевіреного artifact, migration/recovery підтримка, виправлення нових дефектів | Робочий реліз із чітким контрактом, а не запрошення знайти основні поломки |

Залежності: A → B → C → D → E → F → G. Підготовка corpus, CI, security tests і документації починається в A/B та триває паралельно з feature work. Не відкладати перевірки до кінця. Нова можливість, додана після D, повертає відповідні gates на повторне приймання.

### Найближчий етап після 0.5 Preview

**PROD-001 закрито для ревізії `d607c10` (0.6 Preview).** Збережено [матрицю підтримки](docs/production/support-matrix.json), [інвентар дій і сценарії приймання](docs/production/acceptance-journeys.md), [виміряний baseline](quality/releases/0.6-preview/report.md) та [реєстр P0/P1](docs/production/known-issues.md). Звіт містить пройдені й провалені перевірки, а також перевірки, заблоковані відсутністю пристрою. Кваліфікація 1.0 лишається відкритою.

Після baseline фокусуємося на трьох результатах:

1. **Чесний статус декомпіляції (PROD-002).** Android UI та headless показують `complete`, `partial`, `unsupported` або `budget-exhausted` із конкретною причиною. Невідомий термінальний перехід залишається явним у псевдокоді. Перевірка має відрізняти його від справжнього `return 0`.
2. **Актуальність аналізу після правок (PROD-003).** Автоматично порівнюємо інкрементальний і відновлений із кешу результат зі свіжим повним аналізом після patches коду й таблиць, зміни прототипів, undo/redo та повторного відкриття. Порівняння охоплює типи, effects summaries, відповідності case → target і підтверджені tail calls.
3. **Відновлення після збою (PROD-003).** Перевіряємо перерване збереження, нестачу місця, пошкоджений кеш і завершення процесу Android. Після повторного відкриття доступний останній підтверджений стан правок, а пошкоджений кеш можна перебудувати.

Цей етап входить до загального плану до 1.0. Порядок робіт визначають залежності й результати перевірок. Номер наступного preview можна обрати окремо.

### Обмежений обсяг реалізації для 0.6 Preview

- **CFG-02.** Один додатковий ELF64/x86-64 PIC патерн. Без копіювання індексу після guard відновлення дозволене, якщо перед `CMP` у тому самому блоці доведено обнулення старших 32 бітів того самого регістра. Позитивний тест використовує оптимізований Clang ELF64, негативні перевіряють зміну індексу та шлях в обхід його визначення.
- **QA-03.** Перший [зріз корпусу](quality/corpus/README.md) містить AArch64 та x86-64 ELF64 із debug і stripped варіантами. Генератор записує походження, компілятор, прапорці та SHA-256. Перевірка запускає аналіз і звіряє властивості з manifest.
- **UX-02.** Перший напрям навігації з рядка псевдокоду в діапазон listing. Back повертає до попередньої позиції в псевдокоді.

Ці частини обмежують обсяг 0.6. Ширші вимоги CFG-02, QA-03 та UX-02 залишаються в загальному плані.

### Пакети задач до production

1. **PROD-001:** Зафіксувати support matrix й inventory всіх shipping actions, виконати baseline run на поточному коді та зареєструвати P0/P1. **Виконано для 0.6 Preview.** [Результати і відтворення](quality/releases/0.6-preview/report.md).
2. **PROD-002:** Єдиний analysis status/diagnostic contract, включно з unknown terminal transfers і budget exhaustion, через native/JNI/UI/headless.
3. **PROD-003:** Stateful Program fault-injection та incremental/full/cache equivalence harness, включно з останніми SCC/type/switch/tail-call механізмами.
4. **PROD-004:** CI entry point, corpus manifest та independent semantic execution harness для контрольованих compiler fixtures.
5. **PROD-005:** Закрити найчастіші помилки основних ISA/ABI/control-flow за baseline; окремими задачами з counterexamples і semantics tests.
6. **PROD-006:** Physical-device performance baseline, cancellation/memory-pressure fixes і lifecycle acceptance journeys.
7. **PROD-007:** Secondary platform/debugger/SDK/batch qualification; документація, migration та optimized release checks.

Після PROD-001 порядок дефектів визначається ризиком втрати роботи/неправильних висновків і частотою в production corpus. Нову вузьку feature task не обираємо лише тому, що вона цікавіша за надійність збереження.

## 15. Як приймається кожна задача

Для кожного ID створюється issue або окремий запис із:

1. Поточною відтворюваною проблемою, адресами/fixtures і очікуваною поведінкою.
2. Межами підтримки та explicit fallback для решти.
3. Залежностями, budgets, invalidation/serialization наслідками.
4. Семантичними позитивними й негативними тестами.
5. Наскрізною інтеграцією у звичайний Program/UI або задекларований headless flow.
6. Результатами перевірок на точному revision, risk/limits і документацією.

**Definition of Done:** код + інтеграція + актуальність після edits/reopen + належні тести + evidence + документація. Окремий helper, демо, mock-only test або успішна компіляція не закривають задачу. Для documentation-only/інфраструктурних задач застосовуються релевантні пункти без штучних тестів реалізації.

Рекомендована структура evidence, яку ще потрібно створити:

```text
docs/production/support-matrix.json
docs/production/acceptance-journeys.md
docs/production/known-issues.md
docs/production/performance-contract.md
docs/production/migration-policy.md
docs/production/security-model.md
quality/corpus/manifest.json
quality/releases/<candidate>/manifest.json
quality/releases/<candidate>/report.md
```

Великі/private binaries, ключі, machine-local paths і logs з дослідницькими даними не комітяться. Звіти містять checksums та посилання на контрольоване сховище artifacts з відповідними правами.

## 16. Жорсткий gate для 1.0

1. [ ] Остаточний production-контракт зафіксовано; кожна shipping feature має production/experimental статус та чесні limits. У primary journeys немає experimental залежностей.
2. [ ] Немає відкритих P0 і P1 у прийнятому production-контракті. Невирішені P2 мають вплив, workaround і явне рішення; security/data-loss дефект не знижується до P2 заради релізу.
3. [ ] Повні host/unit/JNI/semantic/corpus/Program migration suites пройшли на release revision. Нуль непояснених sanitizer findings, flaky failures або прихованих skips обов’язкової платформи.
4. [ ] Fault injection, corrupt cache/archive recovery та upgrade зі старих підтриманих версій пройшли. Немає відомої втрати підтверджених edits чи непомітного stale analysis.
5. [ ] Physical-device acceptance journeys пройшли на optimized release build; performance/memory/cancellation відповідають замороженому контракту. Обидва shipping app ABIs перевірені.
6. [ ] Parser/stateful fuzz campaigns завершено, findings розібрано й усунуто або безпечно виключено з production path. Не лишилося crashes «тільки на malformed input».
7. [ ] RC пройшов щонайменше 14 календарних днів внутрішнього використання та 50 задокументованих повних acceptance sessions, разом не менше 40 device-hours на щонайменше двох фізичних ARM64 пристроях. Це додаток до автоматичних тестів, а не їх заміна.
8. [ ] В останній RC soak немає невирішених crashes/ANR/втрат роботи в acceptance sessions. Релевантне виправлення повторює пов’язані gates; зміна persistence, JNI, loader або core analysis починає новий фінальний soak для нового RC.
9. [ ] Документація, privacy/distribution artifacts, signing/recovery і support process готові. Опублікований binary точно відповідає перевіреному artifact.
10. [ ] Release report явно пояснює, що гарантовано, що partial і що unsupported. Жодна основна вимога не замінена фразою «користувачі перевірять після 1.0».

Внутрішнє тестування можна доповнити добровільними preview-користувачами. Участь зовнішніх користувачів не є обов’язковим способом знайти базові дефекти та не підміняє жоден gate.

## 17. Що можна залишити після 1.0

Ці напрями не блокують робочу 1.0, якщо вони не включені до затвердженого production-контракту:

- Повна ISA completeness для всіх vector/system/privileged extensions та додаткові big-endian targets.
- Загальний heap/points-to solver, довільні C++ class layouts і повна source-level exception reconstruction.
- Повна OS/process emulation, malware sandbox і debugger parity з кожним backend.
- Безпечний публічний plugin marketplace, portable isolation для всіх hooks і численні language bindings.
- Collaborative/server/team workflows. Вони залишаються поза поточним обсягом; offline annotation merge можна кваліфікувати окремо.
- Повний APK/DEX/multidex/resource analysis: native reversing залишається основною метою Mint.
- Підтримка всіх compiler idioms, максимальна автоматизація inferred types і повне усунення `goto`.

Відкласти можливість можна; відкласти коректну обробку її відсутності, збереження роботи або захист від падіння на вхідному файлі — ні.

## 18. Правило переходу до 1.0

Mint стає 1.0 тоді, коли визначений набір реальних задач можна регулярно виконувати від import до збереження й експорту, результати аналізу мають чесні межі, а відмови не знищують роботу. Випуск не залежить від бажаної дати, номера preview чи кількості доданих features. Невиконаний обов’язковий gate означає наступний preview та продовження робіт.
