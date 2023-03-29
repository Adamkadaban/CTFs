package com.google.android.material.datepicker;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.GridView;
import android.widget.ListAdapter;
import androidx.core.util.Pair;
import androidx.core.view.AccessibilityDelegateCompat;
import androidx.core.view.ViewCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import com.google.android.material.R;
import com.google.android.material.internal.ViewUtils;
import java.util.Calendar;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public final class MaterialCalendarGridView extends GridView {
    private final Calendar dayCompute;
    private final boolean nestedScrollable;

    public MaterialCalendarGridView(Context context) {
        this(context, null);
    }

    public MaterialCalendarGridView(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public MaterialCalendarGridView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.dayCompute = UtcDates.getUtcCalendar();
        if (MaterialDatePicker.isFullscreen(getContext())) {
            setNextFocusLeftId(R.id.cancel_button);
            setNextFocusRightId(R.id.confirm_button);
        }
        this.nestedScrollable = MaterialDatePicker.isNestedScrollable(getContext());
        ViewCompat.setAccessibilityDelegate(this, new AccessibilityDelegateCompat() { // from class: com.google.android.material.datepicker.MaterialCalendarGridView.1
            @Override // androidx.core.view.AccessibilityDelegateCompat
            public void onInitializeAccessibilityNodeInfo(View view, AccessibilityNodeInfoCompat accessibilityNodeInfoCompat) {
                super.onInitializeAccessibilityNodeInfo(view, accessibilityNodeInfoCompat);
                accessibilityNodeInfoCompat.setCollectionInfo(null);
            }
        });
    }

    @Override // android.widget.AbsListView, android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        getAdapter2().notifyDataSetChanged();
    }

    @Override // android.widget.GridView, android.widget.AdapterView
    public void setSelection(int position) {
        if (position < getAdapter2().firstPositionInMonth()) {
            super.setSelection(getAdapter2().firstPositionInMonth());
        } else {
            super.setSelection(position);
        }
    }

    @Override // android.widget.GridView, android.widget.AbsListView, android.view.View, android.view.KeyEvent.Callback
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        boolean result = super.onKeyDown(keyCode, event);
        if (!result) {
            return false;
        }
        if (getSelectedItemPosition() == -1 || getSelectedItemPosition() >= getAdapter2().firstPositionInMonth()) {
            return true;
        }
        if (19 != keyCode) {
            return false;
        }
        setSelection(getAdapter2().firstPositionInMonth());
        return true;
    }

    @Override // android.widget.GridView, android.widget.AdapterView
    /* renamed from: getAdapter */
    public ListAdapter getAdapter2() {
        return (MonthAdapter) super.getAdapter();
    }

    @Override // android.widget.AdapterView
    public final void setAdapter(ListAdapter adapter) {
        if (!(adapter instanceof MonthAdapter)) {
            throw new IllegalArgumentException(String.format("%1$s must have its Adapter set to a %2$s", MaterialCalendarGridView.class.getCanonicalName(), MonthAdapter.class.getCanonicalName()));
        }
        super.setAdapter(adapter);
    }

    @Override // android.view.View
    protected final void onDraw(Canvas canvas) {
        int firstHighlightPosition;
        int rangeHighlightStart;
        int rangeHighlightStart2;
        int firstVisiblePositionInMonth;
        int rangeHighlightStart3;
        int rangeHighlightEnd;
        int left;
        int width;
        MaterialCalendarGridView materialCalendarGridView = this;
        super.onDraw(canvas);
        MonthAdapter monthAdapter = getAdapter2();
        DateSelector<?> dateSelector = monthAdapter.dateSelector;
        CalendarStyle calendarStyle = monthAdapter.calendarStyle;
        int firstVisiblePositionInMonth2 = Math.max(monthAdapter.firstPositionInMonth(), getFirstVisiblePosition());
        int lastVisiblePositionInMonth = Math.min(monthAdapter.lastPositionInMonth(), getLastVisiblePosition());
        Long firstOfMonth = monthAdapter.getItem(firstVisiblePositionInMonth2);
        Long lastOfMonth = monthAdapter.getItem(lastVisiblePositionInMonth);
        for (Pair<Long, Long> range : dateSelector.getSelectedRanges()) {
            if (range.first == null) {
                materialCalendarGridView = this;
            } else if (range.second != null) {
                long startItem = range.first.longValue();
                long endItem = range.second.longValue();
                if (!skipMonth(firstOfMonth, lastOfMonth, Long.valueOf(startItem), Long.valueOf(endItem))) {
                    boolean isRtl = ViewUtils.isLayoutRtl(this);
                    DateSelector<?> dateSelector2 = dateSelector;
                    if (startItem < firstOfMonth.longValue()) {
                        firstHighlightPosition = firstVisiblePositionInMonth2;
                        if (monthAdapter.isFirstInRow(firstHighlightPosition)) {
                            rangeHighlightStart = 0;
                        } else if (!isRtl) {
                            rangeHighlightStart = materialCalendarGridView.getChildAtPosition(firstHighlightPosition - 1).getRight();
                        } else {
                            rangeHighlightStart = materialCalendarGridView.getChildAtPosition(firstHighlightPosition - 1).getLeft();
                        }
                    } else {
                        materialCalendarGridView.dayCompute.setTimeInMillis(startItem);
                        firstHighlightPosition = monthAdapter.dayToPosition(materialCalendarGridView.dayCompute.get(5));
                        rangeHighlightStart = horizontalMidPoint(materialCalendarGridView.getChildAtPosition(firstHighlightPosition));
                    }
                    if (endItem > lastOfMonth.longValue()) {
                        int lastHighlightPosition = lastVisiblePositionInMonth;
                        rangeHighlightStart2 = rangeHighlightStart;
                        rangeHighlightStart3 = lastHighlightPosition;
                        if (monthAdapter.isLastInRow(rangeHighlightStart3)) {
                            rangeHighlightEnd = getWidth();
                        } else if (!isRtl) {
                            rangeHighlightEnd = materialCalendarGridView.getChildAtPosition(rangeHighlightStart3).getRight();
                        } else {
                            rangeHighlightEnd = materialCalendarGridView.getChildAtPosition(rangeHighlightStart3).getLeft();
                        }
                        firstVisiblePositionInMonth = firstVisiblePositionInMonth2;
                    } else {
                        rangeHighlightStart2 = rangeHighlightStart;
                        materialCalendarGridView.dayCompute.setTimeInMillis(endItem);
                        firstVisiblePositionInMonth = firstVisiblePositionInMonth2;
                        rangeHighlightStart3 = monthAdapter.dayToPosition(materialCalendarGridView.dayCompute.get(5));
                        rangeHighlightEnd = horizontalMidPoint(materialCalendarGridView.getChildAtPosition(rangeHighlightStart3));
                    }
                    int lastVisiblePositionInMonth2 = lastVisiblePositionInMonth;
                    int firstRow = (int) monthAdapter.getItemId(firstHighlightPosition);
                    Long firstOfMonth2 = firstOfMonth;
                    Long lastOfMonth2 = lastOfMonth;
                    int lastRow = (int) monthAdapter.getItemId(rangeHighlightStart3);
                    int row = firstRow;
                    while (row <= lastRow) {
                        MonthAdapter monthAdapter2 = monthAdapter;
                        int firstPositionInRow = row * getNumColumns();
                        Long firstOfMonth3 = firstOfMonth2;
                        int lastPositionInRow = (firstPositionInRow + getNumColumns()) - 1;
                        View firstView = materialCalendarGridView.getChildAtPosition(firstPositionInRow);
                        int top = firstView.getTop() + calendarStyle.day.getTopInset();
                        int firstRow2 = firstRow;
                        int bottom = firstView.getBottom() - calendarStyle.day.getBottomInset();
                        if (!isRtl) {
                            left = firstPositionInRow > firstHighlightPosition ? 0 : rangeHighlightStart2;
                            width = rangeHighlightStart3 > lastPositionInRow ? getWidth() : rangeHighlightEnd;
                        } else {
                            left = rangeHighlightStart3 > lastPositionInRow ? 0 : rangeHighlightEnd;
                            width = firstPositionInRow > firstHighlightPosition ? getWidth() : rangeHighlightStart2;
                        }
                        int firstPositionInRow2 = left;
                        int left2 = rangeHighlightStart3;
                        int lastHighlightPosition2 = width;
                        canvas.drawRect(firstPositionInRow2, top, lastHighlightPosition2, bottom, calendarStyle.rangeFill);
                        row++;
                        materialCalendarGridView = this;
                        monthAdapter = monthAdapter2;
                        firstOfMonth2 = firstOfMonth3;
                        rangeHighlightStart3 = left2;
                        firstRow = firstRow2;
                    }
                    Long firstOfMonth4 = firstOfMonth2;
                    materialCalendarGridView = this;
                    dateSelector = dateSelector2;
                    firstVisiblePositionInMonth2 = firstVisiblePositionInMonth;
                    lastVisiblePositionInMonth = lastVisiblePositionInMonth2;
                    lastOfMonth = lastOfMonth2;
                    firstOfMonth = firstOfMonth4;
                }
            }
        }
    }

    @Override // android.widget.GridView, android.widget.AbsListView, android.view.View
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        if (this.nestedScrollable) {
            int expandSpec = View.MeasureSpec.makeMeasureSpec(ViewCompat.MEASURED_SIZE_MASK, Integer.MIN_VALUE);
            super.onMeasure(widthMeasureSpec, expandSpec);
            ViewGroup.LayoutParams params = getLayoutParams();
            params.height = getMeasuredHeight();
            return;
        }
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
    }

    @Override // android.widget.GridView, android.widget.AbsListView, android.view.View
    protected void onFocusChanged(boolean gainFocus, int direction, Rect previouslyFocusedRect) {
        if (gainFocus) {
            gainFocus(direction, previouslyFocusedRect);
        } else {
            super.onFocusChanged(false, direction, previouslyFocusedRect);
        }
    }

    private void gainFocus(int direction, Rect previouslyFocusedRect) {
        if (direction == 33) {
            setSelection(getAdapter2().lastPositionInMonth());
        } else if (direction == 130) {
            setSelection(getAdapter2().firstPositionInMonth());
        } else {
            super.onFocusChanged(true, direction, previouslyFocusedRect);
        }
    }

    private View getChildAtPosition(int position) {
        return getChildAt(position - getFirstVisiblePosition());
    }

    private static boolean skipMonth(Long firstOfMonth, Long lastOfMonth, Long startDay, Long endDay) {
        return firstOfMonth == null || lastOfMonth == null || startDay == null || endDay == null || startDay.longValue() > lastOfMonth.longValue() || endDay.longValue() < firstOfMonth.longValue();
    }

    private static int horizontalMidPoint(View view) {
        return view.getLeft() + (view.getWidth() / 2);
    }
}
