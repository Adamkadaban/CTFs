package androidx.constraintlayout.widget;

import android.content.Context;
import android.graphics.Canvas;
import android.util.AttributeSet;
import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
/* loaded from: classes.dex */
public class Guideline extends View {
    private boolean mFilterRedundantCalls;

    public Guideline(Context context) {
        super(context);
        this.mFilterRedundantCalls = true;
        super.setVisibility(8);
    }

    public Guideline(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.mFilterRedundantCalls = true;
        super.setVisibility(8);
    }

    public Guideline(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.mFilterRedundantCalls = true;
        super.setVisibility(8);
    }

    public Guideline(Context context, AttributeSet attrs, int defStyleAttr, int defStyleRes) {
        super(context, attrs, defStyleAttr);
        this.mFilterRedundantCalls = true;
        super.setVisibility(8);
    }

    @Override // android.view.View
    public void setVisibility(int visibility) {
    }

    @Override // android.view.View
    public void draw(Canvas canvas) {
    }

    @Override // android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        setMeasuredDimension(0, 0);
    }

    public void setGuidelineBegin(int margin) {
        ConstraintLayout.LayoutParams params = (ConstraintLayout.LayoutParams) getLayoutParams();
        if (this.mFilterRedundantCalls && params.guideBegin == margin) {
            return;
        }
        params.guideBegin = margin;
        setLayoutParams(params);
    }

    public void setGuidelineEnd(int margin) {
        ConstraintLayout.LayoutParams params = (ConstraintLayout.LayoutParams) getLayoutParams();
        if (this.mFilterRedundantCalls && params.guideEnd == margin) {
            return;
        }
        params.guideEnd = margin;
        setLayoutParams(params);
    }

    public void setGuidelinePercent(float ratio) {
        ConstraintLayout.LayoutParams params = (ConstraintLayout.LayoutParams) getLayoutParams();
        if (this.mFilterRedundantCalls && params.guidePercent == ratio) {
            return;
        }
        params.guidePercent = ratio;
        setLayoutParams(params);
    }

    public void setFilterRedundantCalls(boolean filter) {
        this.mFilterRedundantCalls = filter;
    }
}
