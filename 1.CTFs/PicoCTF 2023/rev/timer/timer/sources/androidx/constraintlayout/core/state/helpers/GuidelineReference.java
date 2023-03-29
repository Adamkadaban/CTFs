package androidx.constraintlayout.core.state.helpers;

import androidx.constraintlayout.core.state.Reference;
import androidx.constraintlayout.core.state.State;
import androidx.constraintlayout.core.widgets.ConstraintWidget;
import androidx.constraintlayout.core.widgets.Guideline;
/* loaded from: classes.dex */
public class GuidelineReference implements Facade, Reference {
    private Object key;
    private Guideline mGuidelineWidget;
    private int mOrientation;
    final State mState;
    private int mStart = -1;
    private int mEnd = -1;
    private float mPercent = 0.0f;

    @Override // androidx.constraintlayout.core.state.Reference
    public void setKey(Object key) {
        this.key = key;
    }

    @Override // androidx.constraintlayout.core.state.Reference
    public Object getKey() {
        return this.key;
    }

    public GuidelineReference(State state) {
        this.mState = state;
    }

    public GuidelineReference start(Object margin) {
        this.mStart = this.mState.convertDimension(margin);
        this.mEnd = -1;
        this.mPercent = 0.0f;
        return this;
    }

    public GuidelineReference end(Object margin) {
        this.mStart = -1;
        this.mEnd = this.mState.convertDimension(margin);
        this.mPercent = 0.0f;
        return this;
    }

    public GuidelineReference percent(float percent) {
        this.mStart = -1;
        this.mEnd = -1;
        this.mPercent = percent;
        return this;
    }

    public void setOrientation(int orientation) {
        this.mOrientation = orientation;
    }

    public int getOrientation() {
        return this.mOrientation;
    }

    @Override // androidx.constraintlayout.core.state.helpers.Facade, androidx.constraintlayout.core.state.Reference
    public void apply() {
        this.mGuidelineWidget.setOrientation(this.mOrientation);
        int i = this.mStart;
        if (i != -1) {
            this.mGuidelineWidget.setGuideBegin(i);
            return;
        }
        int i2 = this.mEnd;
        if (i2 != -1) {
            this.mGuidelineWidget.setGuideEnd(i2);
        } else {
            this.mGuidelineWidget.setGuidePercent(this.mPercent);
        }
    }

    @Override // androidx.constraintlayout.core.state.Reference
    public Facade getFacade() {
        return null;
    }

    @Override // androidx.constraintlayout.core.state.helpers.Facade, androidx.constraintlayout.core.state.Reference
    public ConstraintWidget getConstraintWidget() {
        if (this.mGuidelineWidget == null) {
            this.mGuidelineWidget = new Guideline();
        }
        return this.mGuidelineWidget;
    }

    @Override // androidx.constraintlayout.core.state.Reference
    public void setConstraintWidget(ConstraintWidget widget) {
        if (widget instanceof Guideline) {
            this.mGuidelineWidget = (Guideline) widget;
        } else {
            this.mGuidelineWidget = null;
        }
    }
}
