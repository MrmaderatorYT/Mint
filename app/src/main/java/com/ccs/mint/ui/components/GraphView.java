package com.ccs.mint.ui.components;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.ScaleGestureDetector;
import android.view.View;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Touch-first CFG canvas. Coordinates are deliberately data-driven so JNI can feed real blocks later. */
public class GraphView extends View {
    public static final class Node {
        public final int id;
        public final String label;
        public float x, y, width = 180, height = 64;
        public final List<Integer> successors = new ArrayList<>();
        public Node(int id, String label) { this.id = id; this.label = label; }
    }

    private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final List<Node> nodes = new ArrayList<>();
    private final ScaleGestureDetector scaleDetector;
    private float zoom = 1f, panX, panY, lastX, lastY;
    private boolean dragging;

    public GraphView(Context context, AttributeSet attrs) { super(context, attrs); scaleDetector = new ScaleGestureDetector(context, new ScaleListener()); setWillNotDraw(false); }
    public GraphView(Context context) { this(context, null); }

    public void setNodes(List<Node> input) { nodes.clear(); if (input != null) nodes.addAll(input); requestLayout(); invalidate(); }
    public List<Node> nodes() { return Collections.unmodifiableList(nodes); }

    @Override protected void onDraw(Canvas canvas) {
        super.onDraw(canvas); canvas.drawColor(0xff121212); canvas.save(); canvas.translate(panX, panY); canvas.scale(zoom, zoom);
        paint.setStrokeWidth(2); paint.setStyle(Paint.Style.STROKE); paint.setColor(0xff6f86a8);
        for (Node node : nodes) for (Integer targetId : node.successors) for (Node target : nodes) if (target.id == targetId) { Path path = new Path(); path.moveTo(node.x + node.width / 2, node.y + node.height); path.quadTo(node.x + node.width / 2, target.y, target.x + target.width / 2, target.y); canvas.drawPath(path, paint); }
        paint.setStyle(Paint.Style.FILL); paint.setColor(0xff26364d);
        for (Node node : nodes) { canvas.drawRoundRect(new RectF(node.x, node.y, node.x + node.width, node.y + node.height), 12, 12, paint); paint.setColor(0xffd7e3f5); paint.setTextSize(14); canvas.drawText(node.label, node.x + 12, node.y + 30, paint); paint.setColor(0xff26364d); }
        canvas.restore();
    }

    @Override public boolean onTouchEvent(MotionEvent event) {
        scaleDetector.onTouchEvent(event);
        if (event.getPointerCount() == 1) {
            if (event.getActionMasked() == MotionEvent.ACTION_DOWN) { lastX = event.getX(); lastY = event.getY(); dragging = true; }
            else if (event.getActionMasked() == MotionEvent.ACTION_MOVE && dragging) { panX += event.getX() - lastX; panY += event.getY() - lastY; lastX = event.getX(); lastY = event.getY(); invalidate(); }
            else if (event.getActionMasked() == MotionEvent.ACTION_UP || event.getActionMasked() == MotionEvent.ACTION_CANCEL) dragging = false;
        }
        return true;
    }

    private final class ScaleListener extends ScaleGestureDetector.SimpleOnScaleGestureListener {
        @Override public boolean onScale(ScaleGestureDetector detector) { zoom = Math.max(.25f, Math.min(4f, zoom * detector.getScaleFactor())); invalidate(); return true; }
    }
}
