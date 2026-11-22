package com.ccs.mint.ui;

/** Bounded line diff for before/after views of an applied Program patch. */
final class PatchComparison {
    private static final long MAX_CELLS = 1_000_000;

    private PatchComparison() {}

    static int byteCount(String hex) {
        String trimmed = hex.trim();
        return trimmed.isEmpty() ? 0 : trimmed.split("\\s+", 1025).length;
    }

    static String status(String report) {
        final String prefix = "/* Decompilation status: ";
        if (report == null || !report.startsWith(prefix)) return "unavailable";
        int end = report.indexOf(" */");
        return end > prefix.length() ? report.substring(prefix.length(), end) : "unavailable";
    }

    static String diff(String before, String after) {
        return diff(before, after, "Comparison unavailable or capture limit reached.",
                "No changes.", "− Before  ·  + After", "Changed span shown as one block (diff limit).");
    }

    static String diff(String before, String after, String unavailable, String unchanged,
                       String legend, String limited) {
        if (before == null || after == null) return unavailable + "\n";
        if (before.equals(after)) return unchanged + "\n";
        String[] oldLines = before.split("\\n", -1);
        String[] newLines = after.split("\\n", -1);
        int first = 0, oldEnd = oldLines.length, newEnd = newLines.length;
        while (first < oldEnd && first < newEnd && oldLines[first].equals(newLines[first])) ++first;
        while (oldEnd > first && newEnd > first && oldLines[oldEnd - 1].equals(newLines[newEnd - 1])) {
            --oldEnd;
            --newEnd;
        }
        int oldCount = oldEnd - first, newCount = newEnd - first;
        StringBuilder result = new StringBuilder();
        result.append(legend).append('\n');
        if ((long) (oldCount + 1) * (newCount + 1) > MAX_CELLS) {
            result.append(limited).append('\n');
            for (int i = first; i < oldEnd; ++i) result.append("− ").append(oldLines[i]).append('\n');
            for (int j = first; j < newEnd; ++j) result.append("+ ").append(newLines[j]).append('\n');
            return result.toString();
        }
        int[][] common = new int[oldCount + 1][newCount + 1];
        for (int i = oldCount - 1; i >= 0; --i) {
            for (int j = newCount - 1; j >= 0; --j) {
                common[i][j] = oldLines[first + i].equals(newLines[first + j])
                        ? 1 + common[i + 1][j + 1] : Math.max(common[i + 1][j], common[i][j + 1]);
            }
        }
        int i = 0, j = 0;
        while (i < oldCount || j < newCount) {
            if (i < oldCount && j < newCount && oldLines[first + i].equals(newLines[first + j])) {
                ++i;
                ++j;
            } else if (i < oldCount && (j == newCount || common[i + 1][j] >= common[i][j + 1])) {
                result.append("− ").append(oldLines[first + i++]).append('\n');
            } else {
                result.append("+ ").append(newLines[first + j++]).append('\n');
            }
        }
        return result.toString();
    }
}
