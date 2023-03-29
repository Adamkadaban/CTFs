package com.google.android.material.timepicker;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.RadialGradient;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Shader;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.AttributeSet;
import android.util.DisplayMetrics;
import android.util.SparseArray;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.TextView;
import androidx.appcompat.content.res.AppCompatResources;
import androidx.constraintlayout.core.widgets.analyzer.BasicMeasure;
import androidx.core.view.AccessibilityDelegateCompat;
import androidx.core.view.ViewCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import com.google.android.material.R;
import com.google.android.material.resources.MaterialResources;
import com.google.android.material.timepicker.ClockHandView;
import java.util.Arrays;
/* loaded from: classes.dex */
class ClockFaceView extends RadialViewGroup implements ClockHandView.OnRotateListener {
    private static final float EPSILON = 0.001f;
    private static final int INITIAL_CAPACITY = 12;
    private static final String VALUE_PLACEHOLDER = "";
    private final int clockHandPadding;
    private final ClockHandView clockHandView;
    private final int clockSize;
    private float currentHandRotation;
    private final int[] gradientColors;
    private final float[] gradientPositions;
    private final int minimumHeight;
    private final int minimumWidth;
    private final RectF scratch;
    private final ColorStateList textColor;
    private final SparseArray<TextView> textViewPool;
    private final Rect textViewRect;
    private final AccessibilityDelegateCompat valueAccessibilityDelegate;
    private String[] values;

    public ClockFaceView(Context context) {
        this(context, null);
    }

    public ClockFaceView(Context context, AttributeSet attrs) {
        this(context, attrs, R.attr.materialClockStyle);
    }

    public ClockFaceView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.textViewRect = new Rect();
        this.scratch = new RectF();
        this.textViewPool = new SparseArray<>();
        this.gradientPositions = new float[]{0.0f, 0.9f, 1.0f};
        TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.ClockFaceView, defStyleAttr, R.style.Widget_MaterialComponents_TimePicker_Clock);
        Resources res = getResources();
        ColorStateList colorStateList = MaterialResources.getColorStateList(context, a, R.styleable.ClockFaceView_clockNumberTextColor);
        this.textColor = colorStateList;
        LayoutInflater.from(context).inflate(R.layout.material_clockface_view, (ViewGroup) this, true);
        ClockHandView clockHandView = (ClockHandView) findViewById(R.id.material_clock_hand);
        this.clockHandView = clockHandView;
        this.clockHandPadding = res.getDimensionPixelSize(R.dimen.material_clock_hand_padding);
        int clockHandTextColor = colorStateList.getColorForState(new int[]{16842913}, colorStateList.getDefaultColor());
        this.gradientColors = new int[]{clockHandTextColor, clockHandTextColor, colorStateList.getDefaultColor()};
        clockHandView.addOnRotateListener(this);
        int defaultBackgroundColor = AppCompatResources.getColorStateList(context, R.color.material_timepicker_clockface).getDefaultColor();
        ColorStateList backgroundColor = MaterialResources.getColorStateList(context, a, R.styleable.ClockFaceView_clockFaceBackgroundColor);
        setBackgroundColor(backgroundColor == null ? defaultBackgroundColor : backgroundColor.getDefaultColor());
        getViewTreeObserver().addOnPreDrawListener(new ViewTreeObserver.OnPreDrawListener() { // from class: com.google.android.material.timepicker.ClockFaceView.1
            @Override // android.view.ViewTreeObserver.OnPreDrawListener
            public boolean onPreDraw() {
                if (ClockFaceView.this.isShown()) {
                    ClockFaceView.this.getViewTreeObserver().removeOnPreDrawListener(this);
                    int circleRadius = ((ClockFaceView.this.getHeight() / 2) - ClockFaceView.this.clockHandView.getSelectorRadius()) - ClockFaceView.this.clockHandPadding;
                    ClockFaceView.this.setRadius(circleRadius);
                    return true;
                }
                return true;
            }
        });
        setFocusable(true);
        a.recycle();
        this.valueAccessibilityDelegate = new AccessibilityDelegateCompat() { // from class: com.google.android.material.timepicker.ClockFaceView.2
            @Override // androidx.core.view.AccessibilityDelegateCompat
            public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfoCompat info) {
                super.onInitializeAccessibilityNodeInfo(host, info);
                int index = ((Integer) host.getTag(R.id.material_value_index)).intValue();
                if (index > 0) {
                    info.setTraversalAfter((View) ClockFaceView.this.textViewPool.get(index - 1));
                }
                info.setCollectionItemInfo(AccessibilityNodeInfoCompat.CollectionItemInfoCompat.obtain(0, 1, index, 1, false, host.isSelected()));
                info.setClickable(true);
                info.addAction(AccessibilityNodeInfoCompat.AccessibilityActionCompat.ACTION_CLICK);
            }

            @Override // androidx.core.view.AccessibilityDelegateCompat
            public boolean performAccessibilityAction(View host, int action, Bundle args) {
                if (action == 16) {
                    long eventTime = SystemClock.uptimeMillis();
                    float x = host.getX() + (host.getWidth() / 2.0f);
                    float y = host.getY() + (host.getHeight() / 2.0f);
                    ClockFaceView.this.clockHandView.onTouchEvent(MotionEvent.obtain(eventTime, eventTime, 0, x, y, 0));
                    ClockFaceView.this.clockHandView.onTouchEvent(MotionEvent.obtain(eventTime, eventTime, 1, x, y, 0));
                    return true;
                }
                return super.performAccessibilityAction(host, action, args);
            }
        };
        String[] initialValues = new String[12];
        Arrays.fill(initialValues, VALUE_PLACEHOLDER);
        setValues(initialValues, 0);
        this.minimumHeight = res.getDimensionPixelSize(R.dimen.material_time_picker_minimum_screen_height);
        this.minimumWidth = res.getDimensionPixelSize(R.dimen.material_time_picker_minimum_screen_width);
        this.clockSize = res.getDimensionPixelSize(R.dimen.material_clock_size);
    }

    public void setValues(String[] values, int contentDescription) {
        this.values = values;
        updateTextViews(contentDescription);
    }

    private void updateTextViews(int contentDescription) {
        LayoutInflater inflater = LayoutInflater.from(getContext());
        int size = this.textViewPool.size();
        for (int i = 0; i < Math.max(this.values.length, size); i++) {
            TextView textView = this.textViewPool.get(i);
            if (i >= this.values.length) {
                removeView(textView);
                this.textViewPool.remove(i);
            } else {
                if (textView == null) {
                    textView = (TextView) inflater.inflate(R.layout.material_clockface_textview, (ViewGroup) this, false);
                    this.textViewPool.put(i, textView);
                    addView(textView);
                }
                textView.setVisibility(0);
                textView.setText(this.values[i]);
                textView.setTag(R.id.material_value_index, Integer.valueOf(i));
                ViewCompat.setAccessibilityDelegate(textView, this.valueAccessibilityDelegate);
                textView.setTextColor(this.textColor);
                if (contentDescription != 0) {
                    Resources res = getResources();
                    textView.setContentDescription(res.getString(contentDescription, this.values[i]));
                }
            }
        }
    }

    @Override // android.view.View
    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
        super.onInitializeAccessibilityNodeInfo(info);
        AccessibilityNodeInfoCompat infoCompat = AccessibilityNodeInfoCompat.wrap(info);
        infoCompat.setCollectionInfo(AccessibilityNodeInfoCompat.CollectionInfoCompat.obtain(1, this.values.length, false, 1));
    }

    @Override // com.google.android.material.timepicker.RadialViewGroup
    public void setRadius(int radius) {
        if (radius != getRadius()) {
            super.setRadius(radius);
            this.clockHandView.setCircleRadius(getRadius());
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.constraintlayout.widget.ConstraintLayout, android.view.ViewGroup, android.view.View
    public void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
        findIntersectingTextView();
    }

    public void setHandRotation(float rotation) {
        this.clockHandView.setHandRotation(rotation);
        findIntersectingTextView();
    }

    private void findIntersectingTextView() {
        RectF selectorBox = this.clockHandView.getCurrentSelectorBox();
        for (int i = 0; i < this.textViewPool.size(); i++) {
            TextView tv = this.textViewPool.get(i);
            if (tv != null) {
                tv.getDrawingRect(this.textViewRect);
                offsetDescendantRectToMyCoords(tv, this.textViewRect);
                tv.setSelected(selectorBox.contains(this.textViewRect.centerX(), this.textViewRect.centerY()));
                RadialGradient radialGradient = getGradientForTextView(selectorBox, this.textViewRect, tv);
                tv.getPaint().setShader(radialGradient);
                tv.invalidate();
            }
        }
    }

    private RadialGradient getGradientForTextView(RectF selectorBox, Rect tvBox, TextView tv) {
        this.scratch.set(tvBox);
        this.scratch.offset(tv.getPaddingLeft(), tv.getPaddingTop());
        if (!RectF.intersects(selectorBox, this.scratch)) {
            return null;
        }
        return new RadialGradient(selectorBox.centerX() - this.scratch.left, selectorBox.centerY() - this.scratch.top, 0.5f * selectorBox.width(), this.gradientColors, this.gradientPositions, Shader.TileMode.CLAMP);
    }

    @Override // com.google.android.material.timepicker.ClockHandView.OnRotateListener
    public void onRotate(float rotation, boolean animating) {
        if (Math.abs(this.currentHandRotation - rotation) > EPSILON) {
            this.currentHandRotation = rotation;
            findIntersectingTextView();
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.constraintlayout.widget.ConstraintLayout, android.view.View
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        Resources r = getResources();
        DisplayMetrics displayMetrics = r.getDisplayMetrics();
        float height = displayMetrics.heightPixels;
        float width = displayMetrics.widthPixels;
        int size = (int) (this.clockSize / max3(this.minimumHeight / height, this.minimumWidth / width, 1.0f));
        int spec = View.MeasureSpec.makeMeasureSpec(size, BasicMeasure.EXACTLY);
        setMeasuredDimension(size, size);
        super.onMeasure(spec, spec);
    }

    private static float max3(float a, float b, float c) {
        return Math.max(Math.max(a, b), c);
    }
}
