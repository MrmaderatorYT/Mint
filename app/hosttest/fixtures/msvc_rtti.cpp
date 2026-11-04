// Freestanding Microsoft ABI fixture. Its type_info vtable is an inert storage
// stub; this file is inspected as PE bytes and never executed.
extern "C" int mint_msvc_entry();
extern "C" const void* const mint_type_info_vtable[] asm("??_7type_info@@6B@") = {
    reinterpret_cast<const void*>(&mint_msvc_entry)
};
struct __declspec(dllexport) Base {virtual int base();};
struct __declspec(dllexport) Right {virtual int right();};
struct __declspec(dllexport) Derived:Base {int base() override;};
struct __declspec(dllexport) Multiple:Base,Right {int base() override;int right() override;};
struct __declspec(dllexport) Virtual:virtual Base {int base() override;};
int Base::base(){return 1;} int Right::right(){return 2;} int Derived::base(){return 3;}
int Multiple::base(){return 4;} int Multiple::right(){return 5;} int Virtual::base(){return 6;}
Base mint_base;Derived mint_derived;Multiple mint_multiple;Virtual mint_virtual;
extern "C" int mint_msvc_entry(){return mint_base.base()+mint_derived.base()+mint_multiple.right()+mint_virtual.base();}
