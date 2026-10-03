# Lua dependency

Unmodified official Lua 5.5.1 sources, released 2026-07-24.

- Source: https://www.lua.org/ftp/lua-5.5.1.tar.gz
- SHA-256: `1c4b4068d67061f2a2231ad2b5422e77acea1487ea9890f6320af614f4373dce`
- License: upstream MIT license in `src/lua.h` and `doc/readme.html`.
- Manual: https://www.lua.org/manual/5.5/manual.html

Mint builds the core and base/math/string/table/UTF-8 libraries offline as C++.
The OS, IO, package, debug, coroutine and dynamic-library loaders are not linked.
Scripts are text-only and run only at an explicit user request. There is no
automatic execution of a script discovered beside a binary or project.
