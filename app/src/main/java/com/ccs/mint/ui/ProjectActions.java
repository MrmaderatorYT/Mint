package com.ccs.mint.ui;

import com.ccs.mint.R;

/** Stable action IDs and their destinations in the workspace tools sheet. */
final class ProjectActions {
    static final int[] LABELS = {
        R.string.ws_search, R.string.ws_go_to, R.string.ws_edit_address,
        R.string.ws_current_references, R.string.ws_undo, R.string.ws_redo,
        R.string.ws_memory_blocks, R.string.ws_type_manager, R.string.ws_provenance,
        R.string.ws_rtti, R.string.ws_reanalyze, R.string.ws_export_patched,
        R.string.ws_forward, R.string.ws_dwarf, R.string.ws_assemble_here,
        R.string.ws_lua_editor, R.string.ws_open_lua, R.string.ws_compare,
        R.string.ws_debugger, R.string.ws_plugins, R.string.ws_prototype_constraints,
        R.string.ws_backup, R.string.ws_restore, R.string.ws_edit_locals,
        R.string.ws_abi_storage, R.string.ws_import_debug, R.string.ws_pseudo_export
    };
    static final int[] GROUPS = {
        R.string.ws_group_navigate, R.string.ws_group_edit, R.string.ws_group_analyze,
        R.string.ws_group_automate, R.string.ws_group_project
    };
    static final int[][] ITEMS = {
        {0, 1, 3, 12}, {2, 4, 5, 14, 23}, {6, 7, 8, 9, 13, 20, 24, 25},
        {15, 16, 18, 19}, {10, 11, 17, 21, 22, 26}
    };
    private ProjectActions() {}
}
