package androidx.constraintlayout.core.widgets;

import androidx.constraintlayout.core.LinearSystem;
import androidx.constraintlayout.core.SolverVariable;
import androidx.constraintlayout.core.widgets.ConstraintAnchor;
import androidx.constraintlayout.core.widgets.ConstraintWidget;
import java.util.HashMap;
/* loaded from: classes.dex */
public class Barrier extends HelperWidget {
    public static final int BOTTOM = 3;
    public static final int LEFT = 0;
    public static final int RIGHT = 1;
    public static final int TOP = 2;
    private static final boolean USE_RELAX_GONE = false;
    private static final boolean USE_RESOLUTION = true;
    private int mBarrierType = 0;
    private boolean mAllowsGoneWidget = USE_RESOLUTION;
    private int mMargin = 0;
    boolean resolved = false;

    public Barrier() {
    }

    public Barrier(String debugName) {
        setDebugName(debugName);
    }

    @Override // androidx.constraintlayout.core.widgets.ConstraintWidget
    public boolean allowedInBarrier() {
        return USE_RESOLUTION;
    }

    public int getBarrierType() {
        return this.mBarrierType;
    }

    public void setBarrierType(int barrierType) {
        this.mBarrierType = barrierType;
    }

    public void setAllowsGoneWidget(boolean allowsGoneWidget) {
        this.mAllowsGoneWidget = allowsGoneWidget;
    }

    @Deprecated
    public boolean allowsGoneWidget() {
        return this.mAllowsGoneWidget;
    }

    public boolean getAllowsGoneWidget() {
        return this.mAllowsGoneWidget;
    }

    @Override // androidx.constraintlayout.core.widgets.ConstraintWidget
    public boolean isResolvedHorizontally() {
        return this.resolved;
    }

    @Override // androidx.constraintlayout.core.widgets.ConstraintWidget
    public boolean isResolvedVertically() {
        return this.resolved;
    }

    @Override // androidx.constraintlayout.core.widgets.HelperWidget, androidx.constraintlayout.core.widgets.ConstraintWidget
    public void copy(ConstraintWidget src, HashMap<ConstraintWidget, ConstraintWidget> map) {
        super.copy(src, map);
        Barrier srcBarrier = (Barrier) src;
        this.mBarrierType = srcBarrier.mBarrierType;
        this.mAllowsGoneWidget = srcBarrier.mAllowsGoneWidget;
        this.mMargin = srcBarrier.mMargin;
    }

    @Override // androidx.constraintlayout.core.widgets.ConstraintWidget
    public String toString() {
        String debug = "[Barrier] " + getDebugName() + " {";
        for (int i = 0; i < this.mWidgetsCount; i++) {
            ConstraintWidget widget = this.mWidgets[i];
            if (i > 0) {
                debug = debug + ", ";
            }
            debug = debug + widget.getDebugName();
        }
        return debug + "}";
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void markWidgets() {
        for (int i = 0; i < this.mWidgetsCount; i++) {
            ConstraintWidget widget = this.mWidgets[i];
            if (this.mAllowsGoneWidget || widget.allowedInBarrier()) {
                int i2 = this.mBarrierType;
                if (i2 == 0 || i2 == 1) {
                    widget.setInBarrier(0, USE_RESOLUTION);
                } else if (i2 == 2 || i2 == 3) {
                    widget.setInBarrier(1, USE_RESOLUTION);
                }
            }
        }
    }

    @Override // androidx.constraintlayout.core.widgets.ConstraintWidget
    public void addToSolver(LinearSystem system, boolean optimize) {
        int i;
        this.mListAnchors[0] = this.mLeft;
        this.mListAnchors[2] = this.mTop;
        this.mListAnchors[1] = this.mRight;
        this.mListAnchors[3] = this.mBottom;
        for (int i2 = 0; i2 < this.mListAnchors.length; i2++) {
            this.mListAnchors[i2].mSolverVariable = system.createObjectVariable(this.mListAnchors[i2]);
        }
        int i3 = this.mBarrierType;
        if (i3 >= 0 && i3 < 4) {
            ConstraintAnchor position = this.mListAnchors[this.mBarrierType];
            if (!this.resolved) {
                allSolved();
            }
            if (this.resolved) {
                this.resolved = false;
                int i4 = this.mBarrierType;
                if (i4 == 0 || i4 == 1) {
                    system.addEquality(this.mLeft.mSolverVariable, this.mX);
                    system.addEquality(this.mRight.mSolverVariable, this.mX);
                    return;
                } else if (i4 == 2 || i4 == 3) {
                    system.addEquality(this.mTop.mSolverVariable, this.mY);
                    system.addEquality(this.mBottom.mSolverVariable, this.mY);
                    return;
                } else {
                    return;
                }
            }
            boolean hasMatchConstraintWidgets = false;
            int i5 = 0;
            while (true) {
                if (i5 >= this.mWidgetsCount) {
                    break;
                }
                ConstraintWidget widget = this.mWidgets[i5];
                if (this.mAllowsGoneWidget || widget.allowedInBarrier()) {
                    int i6 = this.mBarrierType;
                    if ((i6 == 0 || i6 == 1) && widget.getHorizontalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT && widget.mLeft.mTarget != null && widget.mRight.mTarget != null) {
                        hasMatchConstraintWidgets = USE_RESOLUTION;
                        break;
                    }
                    int i7 = this.mBarrierType;
                    if ((i7 == 2 || i7 == 3) && widget.getVerticalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT && widget.mTop.mTarget != null && widget.mBottom.mTarget != null) {
                        hasMatchConstraintWidgets = USE_RESOLUTION;
                        break;
                    }
                }
                i5++;
            }
            boolean mHasHorizontalCenteredDependents = (this.mLeft.hasCenteredDependents() || this.mRight.hasCenteredDependents()) ? USE_RESOLUTION : false;
            boolean mHasVerticalCenteredDependents = (this.mTop.hasCenteredDependents() || this.mBottom.hasCenteredDependents()) ? USE_RESOLUTION : false;
            boolean applyEqualityOnReferences = (hasMatchConstraintWidgets || !(((i = this.mBarrierType) == 0 && mHasHorizontalCenteredDependents) || ((i == 2 && mHasVerticalCenteredDependents) || ((i == 1 && mHasHorizontalCenteredDependents) || (i == 3 && mHasVerticalCenteredDependents))))) ? false : USE_RESOLUTION;
            int equalityOnReferencesStrength = 5;
            if (!applyEqualityOnReferences) {
                equalityOnReferencesStrength = 4;
            }
            for (int i8 = 0; i8 < this.mWidgetsCount; i8++) {
                ConstraintWidget widget2 = this.mWidgets[i8];
                if (this.mAllowsGoneWidget || widget2.allowedInBarrier()) {
                    SolverVariable target = system.createObjectVariable(widget2.mListAnchors[this.mBarrierType]);
                    widget2.mListAnchors[this.mBarrierType].mSolverVariable = target;
                    int margin = 0;
                    if (widget2.mListAnchors[this.mBarrierType].mTarget != null && widget2.mListAnchors[this.mBarrierType].mTarget.mOwner == this) {
                        margin = 0 + widget2.mListAnchors[this.mBarrierType].mMargin;
                    }
                    int i9 = this.mBarrierType;
                    if (i9 == 0 || i9 == 2) {
                        system.addLowerBarrier(position.mSolverVariable, target, this.mMargin - margin, hasMatchConstraintWidgets);
                    } else {
                        system.addGreaterBarrier(position.mSolverVariable, target, this.mMargin + margin, hasMatchConstraintWidgets);
                    }
                    system.addEquality(position.mSolverVariable, target, this.mMargin + margin, equalityOnReferencesStrength);
                }
            }
            int i10 = this.mBarrierType;
            if (i10 == 0) {
                system.addEquality(this.mRight.mSolverVariable, this.mLeft.mSolverVariable, 0, 8);
                system.addEquality(this.mLeft.mSolverVariable, this.mParent.mRight.mSolverVariable, 0, 4);
                system.addEquality(this.mLeft.mSolverVariable, this.mParent.mLeft.mSolverVariable, 0, 0);
            } else if (i10 == 1) {
                system.addEquality(this.mLeft.mSolverVariable, this.mRight.mSolverVariable, 0, 8);
                system.addEquality(this.mLeft.mSolverVariable, this.mParent.mLeft.mSolverVariable, 0, 4);
                system.addEquality(this.mLeft.mSolverVariable, this.mParent.mRight.mSolverVariable, 0, 0);
            } else if (i10 == 2) {
                system.addEquality(this.mBottom.mSolverVariable, this.mTop.mSolverVariable, 0, 8);
                system.addEquality(this.mTop.mSolverVariable, this.mParent.mBottom.mSolverVariable, 0, 4);
                system.addEquality(this.mTop.mSolverVariable, this.mParent.mTop.mSolverVariable, 0, 0);
            } else if (i10 == 3) {
                system.addEquality(this.mTop.mSolverVariable, this.mBottom.mSolverVariable, 0, 8);
                system.addEquality(this.mTop.mSolverVariable, this.mParent.mTop.mSolverVariable, 0, 4);
                system.addEquality(this.mTop.mSolverVariable, this.mParent.mBottom.mSolverVariable, 0, 0);
            }
        }
    }

    public void setMargin(int margin) {
        this.mMargin = margin;
    }

    public int getMargin() {
        return this.mMargin;
    }

    public int getOrientation() {
        switch (this.mBarrierType) {
            case 0:
            case 1:
                return 0;
            case 2:
            case 3:
                return 1;
            default:
                return -1;
        }
    }

    public boolean allSolved() {
        boolean hasAllWidgetsResolved = USE_RESOLUTION;
        for (int i = 0; i < this.mWidgetsCount; i++) {
            ConstraintWidget widget = this.mWidgets[i];
            if (this.mAllowsGoneWidget || widget.allowedInBarrier()) {
                int i2 = this.mBarrierType;
                if ((i2 == 0 || i2 == 1) && !widget.isResolvedHorizontally()) {
                    hasAllWidgetsResolved = false;
                } else {
                    int i3 = this.mBarrierType;
                    if ((i3 == 2 || i3 == 3) && !widget.isResolvedVertically()) {
                        hasAllWidgetsResolved = false;
                    }
                }
            }
        }
        if (hasAllWidgetsResolved && this.mWidgetsCount > 0) {
            int barrierPosition = 0;
            boolean initialized = false;
            for (int i4 = 0; i4 < this.mWidgetsCount; i4++) {
                ConstraintWidget widget2 = this.mWidgets[i4];
                if (this.mAllowsGoneWidget || widget2.allowedInBarrier()) {
                    if (!initialized) {
                        int i5 = this.mBarrierType;
                        if (i5 == 0) {
                            barrierPosition = widget2.getAnchor(ConstraintAnchor.Type.LEFT).getFinalValue();
                        } else if (i5 == 1) {
                            barrierPosition = widget2.getAnchor(ConstraintAnchor.Type.RIGHT).getFinalValue();
                        } else if (i5 == 2) {
                            barrierPosition = widget2.getAnchor(ConstraintAnchor.Type.TOP).getFinalValue();
                        } else if (i5 == 3) {
                            barrierPosition = widget2.getAnchor(ConstraintAnchor.Type.BOTTOM).getFinalValue();
                        }
                        initialized = USE_RESOLUTION;
                    }
                    int i6 = this.mBarrierType;
                    if (i6 == 0) {
                        barrierPosition = Math.min(barrierPosition, widget2.getAnchor(ConstraintAnchor.Type.LEFT).getFinalValue());
                    } else if (i6 == 1) {
                        barrierPosition = Math.max(barrierPosition, widget2.getAnchor(ConstraintAnchor.Type.RIGHT).getFinalValue());
                    } else if (i6 == 2) {
                        barrierPosition = Math.min(barrierPosition, widget2.getAnchor(ConstraintAnchor.Type.TOP).getFinalValue());
                    } else if (i6 == 3) {
                        barrierPosition = Math.max(barrierPosition, widget2.getAnchor(ConstraintAnchor.Type.BOTTOM).getFinalValue());
                    }
                }
            }
            int barrierPosition2 = barrierPosition + this.mMargin;
            int i7 = this.mBarrierType;
            if (i7 == 0 || i7 == 1) {
                setFinalHorizontal(barrierPosition2, barrierPosition2);
            } else {
                setFinalVertical(barrierPosition2, barrierPosition2);
            }
            this.resolved = USE_RESOLUTION;
            return USE_RESOLUTION;
        }
        return false;
    }
}
