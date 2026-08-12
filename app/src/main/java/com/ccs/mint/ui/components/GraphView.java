package com.ccs.mint.ui.components;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.GestureDetector;
import android.view.MotionEvent;
import android.view.ScaleGestureDetector;
import android.view.View;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Draws a directed graph: either one function's control flow or the whole
 * program's call graph.
 *
 * <p>Layout is layered — depth downwards, siblings across — because both graphs are
 * read the same way: start at the top and follow the arrows. The previous version
 * placed nodes in two fixed columns, which is not a layout at all; it happened to
 * look plausible for a four-block function and degenerates into a single 1,400-row
 * column once a real binary is loaded.
 *
 * <p>Cycles are expected, not exceptional: every loop is a back edge and recursion
 * is a cycle in the call graph. They are found during layering and drawn in a
 * different colour, so a loop is visible rather than being a line that happens to
 * point upwards.
 *
 * <p>Colours come from the theme. Hard-coding them, as this view used to, means the
 * graph stays dark when the rest of the app turns light.
 */
public final class GraphView extends View {

    /** A vertex. {@code address} is what the caller navigates to when it is tapped. */
    public static final class Node {
        public final int id;
        public final String label;
        public final List<Integer> successors = new ArrayList<>();
        public long address = -1;

        float x, y, width, height;
        int layer = -1;

        public Node(int id, String label) {
            this.id = id;
            this.label = label;
        }
    }

    /** Called when a node is tapped, if it carries an address. */
    public interface OnNodeClickListener {
        void onNodeClick(@NonNull Node node);
    }

    /**
     * Zoom low enough that labels are unreadable anyway. Below it the text is
     * skipped, which is what keeps a few thousand nodes drawable at 60fps: measuring
     * and rasterising glyphs dominates everything else in this view.
     */
    private static final float LABEL_ZOOM = 0.55f;

    /**
     * A very wide layer is wrapped into several rows rather than drawn as one line.
     * A stripped library puts most of its functions at the same depth, and a single
     * row of two thousand boxes is a horizontal scroll nobody completes.
     */
    private static final int LAYER_ASPECT = 3;

    private static final float MIN_ZOOM = 0.02f;
    private static final float MAX_ZOOM = 6f;

    private final Paint fill = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint stroke = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint edge = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint backEdge = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint label = new Paint(Paint.ANTI_ALIAS_FLAG);

    private final List<Node> nodes = new ArrayList<>();
    private final Map<Integer, Node> byId = new HashMap<>();
    /**
     * Edges that close a cycle: loops in a CFG, recursion in a call graph. Keyed as
     * {@code source << 32 | target} and built once during layering — the draw path
     * needs the same answer sixty times a second and must not recompute it.
     */
    private final java.util.Set<Long> backEdges = new java.util.HashSet<>();
    private final List<List<Node>> layers = new ArrayList<>();

    private final ScaleGestureDetector scaleDetector;
    private final GestureDetector tapDetector;
    private final RectF box = new RectF();
    private final Path path = new Path();

    private float zoom = 1f;
    private float panX;
    private float panY;
    private float lastX;
    private float lastY;
    private boolean dragging;
    private boolean fitPending;

    private float graphWidth;
    private float graphHeight;

    private final float density;
    private final float nodeHeight;
    private final float gapX;
    private final float gapY;
    private final float padding;
    private final float minNodeWidth;
    private final float maxNodeWidth;

    private int surface;
    private int nodeFill;
    private int nodeStroke;
    private int nodeText;
    private int edgeColour;
    private int backEdgeColour;

    @Nullable
    private OnNodeClickListener nodeClickListener;

    public GraphView(Context context) {
        this(context, null);
    }

    public GraphView(Context context, @Nullable AttributeSet attrs) {
        super(context, attrs);
        density = getResources().getDisplayMetrics().density;
        nodeHeight = 40 * density;
        gapX = 20 * density;
        gapY = 44 * density;
        padding = 24 * density;
        minNodeWidth = 84 * density;
        maxNodeWidth = 260 * density;

        label.setTextSize(12 * getResources().getDisplayMetrics().scaledDensity);
        label.setTypeface(android.graphics.Typeface.MONOSPACE);
        fill.setStyle(Paint.Style.FILL);
        stroke.setStyle(Paint.Style.STROKE);
        stroke.setStrokeWidth(Math.max(1f, density));
        edge.setStyle(Paint.Style.STROKE);
        edge.setStrokeWidth(1.6f * density);
        edge.setStrokeCap(Paint.Cap.ROUND);
        backEdge.setStyle(Paint.Style.STROKE);
        backEdge.setStrokeWidth(1.6f * density);
        backEdge.setStrokeCap(Paint.Cap.ROUND);

        readTheme();
        scaleDetector = new ScaleGestureDetector(context, new ScaleListener());
        tapDetector = new GestureDetector(context, new TapListener());
        setWillNotDraw(false);
    }

    public void setOnNodeClickListener(@Nullable OnNodeClickListener listener) {
        nodeClickListener = listener;
    }

    /** Replaces the graph and lays it out. Safe to call with an empty list. */
    public void setNodes(@Nullable List<Node> input) {
        nodes.clear();
        byId.clear();
        backEdges.clear();
        if (input != null) nodes.addAll(input);
        for (Node node : nodes) byId.put(node.id, node);
        layout();
        fitPending = true;
        invalidate();
    }

    @NonNull
    public List<Node> nodes() {
        return Collections.unmodifiableList(nodes);
    }

    // ------------------------------------------------------------------- layout

    private void layout() {
        graphWidth = 0;
        graphHeight = 0;
        if (nodes.isEmpty()) return;

        measureNodes();
        assignLayers();
        orderWithinLayers();
        placeNodes();
    }

    private void measureNodes() {
        for (Node node : nodes) {
            float text = label.measureText(node.label == null ? "" : node.label);
            node.width = Math.max(minNodeWidth,
                    Math.min(maxNodeWidth, text + 20 * density));
            node.height = nodeHeight;
        }
    }

    /**
     * Longest-path layering over the graph with its back edges removed.
     *
     * <p>Back edges are found by depth-first search rather than assumed: an edge
     * that reaches a vertex still on the traversal stack closes a cycle, and
     * layering on it would never terminate. Everything else is relaxed in reverse
     * postorder, which visits each vertex only after its forward predecessors, so a
     * single pass gives the longest path.
     */
    private void assignLayers() {
        final int count = nodes.size();
        final Map<Node, Integer> index = new HashMap<>(count * 2);
        for (int i = 0; i < count; i++) index.put(nodes.get(i), i);

        final byte[] state = new byte[count];  // 0 unvisited, 1 on stack, 2 done
        final int[] order = new int[count];    // reverse postorder
        int filled = count;

        final int[] stack = new int[count];
        final int[] cursor = new int[count];

        for (int root = 0; root < count; root++) {
            if (state[root] != 0) continue;
            int top = 0;
            stack[0] = root;
            cursor[0] = 0;
            state[root] = 1;
            while (top >= 0) {
                final Node node = nodes.get(stack[top]);
                if (cursor[top] < node.successors.size()) {
                    final Integer targetId = node.successors.get(cursor[top]++);
                    final Node target = byId.get(targetId);
                    if (target == null) continue;
                    final Integer at = index.get(target);
                    if (at == null) continue;
                    if (state[at] == 1) {
                        // Closes a cycle. Recorded so it can be drawn, skipped for layering.
                        backEdges.add(key(node.id, target.id));
                    } else if (state[at] == 0) {
                        state[at] = 1;
                        stack[++top] = at;
                        cursor[top] = 0;
                    }
                } else {
                    state[stack[top]] = 2;
                    order[--filled] = stack[top];
                    top--;
                }
            }
        }

        for (Node node : nodes) node.layer = 0;
        for (int i = 0; i < count; i++) {
            final Node node = nodes.get(order[i]);
            for (Integer targetId : node.successors) {
                final Node target = byId.get(targetId);
                if (target == null) continue;
                if (backEdges.contains(key(node.id, targetId))) continue;
                if (target.layer < node.layer + 1) target.layer = node.layer + 1;
            }
        }
    }

    private static long key(int source, int target) {
        return ((long) source << 32) ^ (target & 0xffffffffL);
    }

    /**
     * Orders each layer by the average position of its predecessors.
     *
     * <p>Two sweeps of the barycentre heuristic. It does not minimise crossings —
     * that is NP-hard — but it removes the obvious ones cheaply, and the difference
     * between "some crossings" and "every edge crosses every other" is the
     * difference between a readable graph and a ball of wool.
     */
    private void orderWithinLayers() {
        int depth = 0;
        for (Node node : nodes) depth = Math.max(depth, node.layer);

        layers.clear();
        for (int i = 0; i <= depth; i++) layers.add(new ArrayList<>());
        for (Node node : nodes) layers.get(node.layer).add(node);

        // Predecessors are collected once. Scanning every node's successors per layer
        // instead would make ordering quadratic in the graph, which a call graph over
        // a few thousand functions notices immediately.
        final Map<Integer, List<Integer>> predecessors = new HashMap<>(nodes.size() * 2);
        for (Node source : nodes) {
            for (Integer targetId : source.successors) {
                if (!byId.containsKey(targetId)) continue;
                predecessors.computeIfAbsent(targetId, k -> new ArrayList<>()).add(source.id);
            }
        }

        final Map<Integer, Integer> position = new HashMap<>(nodes.size() * 2);
        for (List<Node> layer : layers) {
            for (int i = 0; i < layer.size(); i++) position.put(layer.get(i).id, i);
        }

        for (int pass = 0; pass < 2; pass++) {
            for (int i = 1; i < layers.size(); i++) {
                final List<Node> layer = layers.get(i);
                if (layer.size() < 2) continue;
                final Map<Integer, Float> weight = new HashMap<>(layer.size() * 2);
                for (Node node : layer) {
                    final List<Integer> from = predecessors.get(node.id);
                    if (from == null || from.isEmpty()) {
                        weight.put(node.id, (float) (int) position.get(node.id));
                        continue;
                    }
                    float sum = 0;
                    int seen = 0;
                    for (Integer sourceId : from) {
                        final Integer at = position.get(sourceId);
                        if (at == null) continue;
                        sum += at;
                        seen++;
                    }
                    weight.put(node.id, seen == 0
                            ? (float) (int) position.get(node.id) : sum / seen);
                }
                Collections.sort(layer, (a, b) -> Float.compare(
                        weight.getOrDefault(a.id, 0f), weight.getOrDefault(b.id, 0f)));
                for (int at = 0; at < layer.size(); at++) position.put(layer.get(at).id, at);
            }
        }
    }

    private void placeNodes() {
        float y = padding;
        float widest = 0;
        for (List<Node> layer : layers) {
            if (layer.isEmpty()) continue;
            // A layer wider than LAYER_ASPECT times its height wraps into rows, so a
            // library whose functions all sit at one depth stays roughly rectangular.
            final int columns = Math.max(1,
                    Math.min(layer.size(),
                            (int) Math.ceil(Math.sqrt((double) layer.size() * LAYER_ASPECT))));
            final int rows = (int) Math.ceil(layer.size() / (double) columns);

            for (int i = 0; i < layer.size(); i++) {
                final Node node = layer.get(i);
                final int column = i % columns;
                final int row = i / columns;
                node.x = padding + column * (maxNodeWidth + gapX);
                node.y = y + row * (nodeHeight + gapY * 0.35f);
                widest = Math.max(widest, node.x + node.width);
            }
            y += rows * (nodeHeight + gapY * 0.35f) + gapY;
        }
        graphWidth = widest + padding;
        graphHeight = y + padding;
    }

    // -------------------------------------------------------------------- paint

    private void readTheme() {
        surface = themeColour(com.google.android.material.R.attr.colorSurface, 0xff121212);
        nodeFill = themeColour(
                com.google.android.material.R.attr.colorSurfaceVariant, 0xff26364d);
        nodeStroke = themeColour(
                com.google.android.material.R.attr.colorOutlineVariant, 0xff3a4a63);
        nodeText = themeColour(
                com.google.android.material.R.attr.colorOnSurfaceVariant, 0xffd7e3f5);
        edgeColour = themeColour(com.google.android.material.R.attr.colorOutline, 0xff6f86a8);
        backEdgeColour = themeColour(
                com.google.android.material.R.attr.colorTertiary, 0xffff8a65);

        fill.setColor(nodeFill);
        stroke.setColor(nodeStroke);
        label.setColor(nodeText);
        edge.setColor(edgeColour);
        backEdge.setColor(backEdgeColour);
    }

    private int themeColour(int attribute, int fallback) {
        final TypedValue value = new TypedValue();
        if (!getContext().getTheme().resolveAttribute(attribute, value, true)) return fallback;
        if (value.resourceId != 0) {
            return androidx.core.content.ContextCompat.getColor(getContext(), value.resourceId);
        }
        return value.data;
    }

    @Override
    protected void onConfigurationChanged(android.content.res.Configuration config) {
        // Reached when the system flips light/dark while the view is alive. Without
        // this the graph keeps the palette it was built with and is the only part of
        // the screen that did not change.
        super.onConfigurationChanged(config);
        readTheme();
        invalidate();
    }

    @Override
    protected void onDraw(@NonNull Canvas canvas) {
        super.onDraw(canvas);
        canvas.drawColor(surface);
        if (nodes.isEmpty()) return;
        if (fitPending && getWidth() > 0 && getHeight() > 0) {
            fitToView();
            fitPending = false;
        }

        canvas.save();
        canvas.translate(panX, panY);
        canvas.scale(zoom, zoom);

        // Viewport in graph coordinates, so offscreen work is skipped rather than
        // handed to the canvas to clip. At a few thousand nodes that is the
        // difference between a smooth pan and a slideshow.
        final float left = -panX / zoom;
        final float top = -panY / zoom;
        final float right = left + getWidth() / zoom;
        final float bottom = top + getHeight() / zoom;

        drawEdges(canvas, left, top, right, bottom);
        drawNodes(canvas, left, top, right, bottom);
        canvas.restore();
    }

    private void drawEdges(Canvas canvas, float left, float top, float right, float bottom) {
        for (Node node : nodes) {
            for (Integer targetId : node.successors) {
                final Node target = byId.get(targetId);
                if (target == null) continue;
                final float x1 = node.x + node.width / 2;
                final float y1 = node.y + node.height;
                final float x2 = target.x + target.width / 2;
                final float y2 = target.y;
                if (Math.max(y1, y2) < top || Math.min(y1, y2) > bottom) continue;
                if (Math.max(x1, x2) < left || Math.min(x1, x2) > right) continue;

                path.reset();
                path.moveTo(x1, y1);
                final float midY = (y1 + y2) / 2;
                path.cubicTo(x1, midY, x2, midY, x2, y2);
                canvas.drawPath(path,
                        backEdges.contains(key(node.id, targetId)) ? backEdge : edge);
            }
        }
    }

    private void drawNodes(Canvas canvas, float left, float top, float right, float bottom) {
        final boolean labels = zoom >= LABEL_ZOOM;
        final float radius = 8 * density;
        for (Node node : nodes) {
            if (node.x > right || node.x + node.width < left) continue;
            if (node.y > bottom || node.y + node.height < top) continue;
            box.set(node.x, node.y, node.x + node.width, node.y + node.height);
            canvas.drawRoundRect(box, radius, radius, fill);
            canvas.drawRoundRect(box, radius, radius, stroke);
            if (labels && node.label != null) {
                canvas.save();
                canvas.clipRect(box);
                canvas.drawText(node.label, node.x + 10 * density,
                        node.y + node.height / 2 + label.getTextSize() / 3, label);
                canvas.restore();
            }
        }
    }

    /** Scales and centres so the whole graph is visible when it first appears. */
    private void fitToView() {
        if (graphWidth <= 0 || graphHeight <= 0) return;
        final float scale = Math.min(getWidth() / graphWidth, getHeight() / graphHeight);
        zoom = Math.max(MIN_ZOOM, Math.min(1f, scale));
        panX = (getWidth() - graphWidth * zoom) / 2;
        panY = Math.min(0f, (getHeight() - graphHeight * zoom) / 2);
    }

    // ------------------------------------------------------------------- input

    @Override
    public boolean onTouchEvent(MotionEvent event) {
        scaleDetector.onTouchEvent(event);
        tapDetector.onTouchEvent(event);
        if (event.getPointerCount() == 1 && !scaleDetector.isInProgress()) {
            switch (event.getActionMasked()) {
                case MotionEvent.ACTION_DOWN:
                    lastX = event.getX();
                    lastY = event.getY();
                    dragging = true;
                    getParent().requestDisallowInterceptTouchEvent(true);
                    break;
                case MotionEvent.ACTION_MOVE:
                    if (dragging) {
                        panX += event.getX() - lastX;
                        panY += event.getY() - lastY;
                        lastX = event.getX();
                        lastY = event.getY();
                        invalidate();
                    }
                    break;
                case MotionEvent.ACTION_UP:
                case MotionEvent.ACTION_CANCEL:
                    dragging = false;
                    getParent().requestDisallowInterceptTouchEvent(false);
                    break;
                default:
                    break;
            }
        }
        return true;
    }

    @Override
    public boolean performClick() {
        super.performClick();
        return true;
    }

    @Nullable
    private Node nodeAt(float screenX, float screenY) {
        final float x = (screenX - panX) / zoom;
        final float y = (screenY - panY) / zoom;
        for (Node node : nodes) {
            if (x >= node.x && x <= node.x + node.width
                    && y >= node.y && y <= node.y + node.height) {
                return node;
            }
        }
        return null;
    }

    private final class TapListener extends GestureDetector.SimpleOnGestureListener {
        @Override
        public boolean onSingleTapConfirmed(@NonNull MotionEvent event) {
            final Node node = nodeAt(event.getX(), event.getY());
            if (node != null && nodeClickListener != null) {
                performClick();
                nodeClickListener.onNodeClick(node);
                return true;
            }
            return false;
        }

        @Override
        public boolean onDoubleTap(@NonNull MotionEvent event) {
            fitToView();
            invalidate();
            return true;
        }
    }

    private final class ScaleListener extends ScaleGestureDetector.SimpleOnScaleGestureListener {
        @Override
        public boolean onScale(@NonNull ScaleGestureDetector detector) {
            final float previous = zoom;
            zoom = Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, zoom * detector.getScaleFactor()));
            // Keep the point under the fingers still, otherwise pinching drifts the
            // graph away and the user spends the gesture chasing it back.
            final float factor = zoom / previous;
            panX = detector.getFocusX() - (detector.getFocusX() - panX) * factor;
            panY = detector.getFocusY() - (detector.getFocusY() - panY) * factor;
            invalidate();
            return true;
        }
    }
}
