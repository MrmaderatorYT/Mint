# This fixture intentionally targets the checked-in libmintdemo.so.
type DemoHeader=struct{magic:u32;flags:u32}
edit 0x20 data DemoHeader
edit 0x4760 function code
edit 0x4760 name headless_entry
edit 0x4760 comment Persistent headless script comment
edit 0x4760 patch 1f 20 03 d5
undo
redo
search headless_entry
refs 0x4760
provenance 0x4760
types
summary
