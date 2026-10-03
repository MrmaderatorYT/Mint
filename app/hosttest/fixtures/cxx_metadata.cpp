// Small cross-compiled RTTI/vtable corpus fixture; never linked into Mint.
struct Base {
    virtual int value() { return 10; }
    virtual int twice() { return value() * 2; }
};
struct Derived : Base { int value() override { return 20; } };
struct Other { virtual int other() { return 3; } };
struct Multiple : Base, Other {
    int value() override { return 30; }
    int other() override { return 4; }
};
struct Virtual : virtual Base { int value() override { return 40; } };
Base base;
Derived derived;
Multiple multiple;
Virtual virtualBase;
extern "C" int cxx_fixture(int selector) {
    Base* object = selector == 0 ? &base : selector == 1 ? static_cast<Base*>(&derived)
            : selector == 2 ? static_cast<Base*>(&multiple) : static_cast<Base*>(&virtualBase);
    return object->value() + object->twice();
}
