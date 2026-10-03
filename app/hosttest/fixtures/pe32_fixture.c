__declspec(dllexport) int native_pe32_fixture(int value) { return value + 7; }
void mainCRTStartup(void) { volatile int result = native_pe32_fixture(3); (void)result; }
