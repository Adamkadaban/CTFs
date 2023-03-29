package androidx.constraintlayout.core.widgets;

import androidx.constraintlayout.core.LinearSystem;
import androidx.constraintlayout.core.widgets.ConstraintAnchor;
/* loaded from: classes.dex */
public class Placeholder extends VirtualLayout {
    @Override // androidx.constraintlayout.core.widgets.VirtualLayout
    public void measure(int widthMode, int widthSize, int heightMode, int heightSize) {
        int paddingLeft = getPaddingLeft();
        int paddingRight = getPaddingRight();
        int paddingTop = getPaddingTop();
        int paddingBottom = getPaddingBottom();
        int width = 0 + paddingLeft + paddingRight;
        int height = 0 + paddingTop + paddingBottom;
        if (this.mWidgetsCount > 0) {
            width += this.mWidgets[0].getWidth();
            height += this.mWidgets[0].getHeight();
        }
        int width2 = Math.max(getMinWidth(), width);
        int height2 = Math.max(getMinHeight(), height);
        int measuredWidth = 0;
        int measuredHeight = 0;
        if (widthMode == 1073741824) {
            measuredWidth = widthSize;
        } else if (widthMode == Integer.MIN_VALUE) {
            measuredWidth = Math.min(width2, widthSize);
        } else if (widthMode == 0) {
            measuredWidth = width2;
        }
        if (heightMode == 1073741824) {
            measuredHeight = heightSize;
        } else if (heightMode == Integer.MIN_VALUE) {
            measuredHeight = Math.min(height2, heightSize);
        } else if (heightMode == 0) {
            measuredHeight = height2;
        }
        setMeasure(measuredWidth, measuredHeight);
        setWidth(measuredWidth);
        setHeight(measuredHeight);
        needsCallbackFromSolver(this.mWidgetsCount > 0);
    }

    @Override // androidx.constraintlayout.core.widgets.ConstraintWidget
    public void addToSolver(LinearSystem system, boolean optimize) {
        super.addToSolver(system, optimize);
        if (this.mWidgetsCount > 0) {
            ConstraintWidget widget = this.mWidgets[0];
            widget.resetAllConstraints();
            widget.connect(ConstraintAnchor.Type.LEFT, this, ConstraintAnchor.Type.LEFT);
            widget.connect(ConstraintAnchor.Type.RIGHT, this, ConstraintAnchor.Type.RIGHT);
            widget.connect(ConstraintAnchor.Type.TOP, this, ConstraintAnchor.Type.TOP);
            widget.connect(ConstraintAnchor.Type.BOTTOM, this, ConstraintAnchor.Type.BOTTOM);
        }
    }
}
