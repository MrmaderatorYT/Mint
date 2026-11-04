package com.ccs.mint.ui;

/** Stable action IDs and their destinations in the workspace tools sheet. */
final class ProjectActions {
    static final String[] LABELS = {
        "Global search", "Go to address", "Edit current address", "References at current address",
        "Undo edit", "Redo edit", "Memory blocks", "Data Type Manager", "Function provenance",
        "C++ RTTI / vtables", "Reanalyze", "Export patched copy", "Navigate forward",
        "DWARF / source information", "Assemble patch at current address", "Lua script editor",
        "Open Lua script", "Compare another binary / version tracking", "External debugger",
        "Native plugins", "Interprocedural prototype constraints", "Back up complete project",
        "Restore project archive", "Edit local variables", "Function ABI storage", "Import external / split DWARF"
    };
    static final String[] GROUPS = {"Navigate", "Edit", "Analyze", "Automate & debug", "Project & files"};
    static final int[][] ITEMS = {
        {0, 1, 3, 12}, {2, 4, 5, 14, 23}, {6, 7, 8, 9, 13, 20, 24, 25},
        {15, 16, 18, 19}, {10, 11, 17, 21, 22}
    };
    private ProjectActions() {}
}
