// Freestanding linked ELF fixture: no platform headers or C++ runtime needed.
// Undefined __cxa_* / personality/typeinfo imports are intentionally retained.
extern "C" void exception_fixture_sink(int);
struct FixtureError { int code; };
struct Cleanup {
    int value;
    __attribute__((noinline)) ~Cleanup() { exception_fixture_sink(value); }
};
__attribute__((noinline, visibility("hidden"))) static void throw_error(int value) {
    if (value == 1) throw FixtureError{value};
    if (value == 2) throw value;
}
extern "C" __attribute__((noinline, visibility("default"))) int exception_fixture(int value) {
    Cleanup cleanup{value};
    try { throw_error(value); return 3; }
    catch (const FixtureError& error) { return error.code + 4; }
    catch (int error) { return error + 5; }
    catch (...) { return 6; }
}
