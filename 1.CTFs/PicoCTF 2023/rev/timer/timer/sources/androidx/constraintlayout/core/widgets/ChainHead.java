package androidx.constraintlayout.core.widgets;

import androidx.constraintlayout.core.widgets.ConstraintWidget;
import java.util.ArrayList;
/* loaded from: classes.dex */
public class ChainHead {
    private boolean mDefined;
    protected ConstraintWidget mFirst;
    protected ConstraintWidget mFirstMatchConstraintWidget;
    protected ConstraintWidget mFirstVisibleWidget;
    protected boolean mHasComplexMatchWeights;
    protected boolean mHasDefinedWeights;
    protected boolean mHasRatio;
    protected boolean mHasUndefinedWeights;
    protected ConstraintWidget mHead;
    private boolean mIsRtl;
    protected ConstraintWidget mLast;
    protected ConstraintWidget mLastMatchConstraintWidget;
    protected ConstraintWidget mLastVisibleWidget;
    boolean mOptimizable;
    private int mOrientation;
    int mTotalMargins;
    int mTotalSize;
    protected float mTotalWeight = 0.0f;
    int mVisibleWidgets;
    protected ArrayList<ConstraintWidget> mWeightedMatchConstraintsWidgets;
    protected int mWidgetsCount;
    protected int mWidgetsMatchCount;

    public ChainHead(ConstraintWidget first, int orientation, boolean isRtl) {
        this.mIsRtl = false;
        this.mFirst = first;
        this.mOrientation = orientation;
        this.mIsRtl = isRtl;
    }

    private static boolean isMatchConstraintEqualityCandidate(ConstraintWidget widget, int orientation) {
        return widget.getVisibility() != 8 && widget.mListDimensionBehaviors[orientation] == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT && (widget.mResolvedMatchConstraintDefault[orientation] == 0 || widget.mResolvedMatchConstraintDefault[orientation] == 3);
    }

    private void defineChainProperties() {
        ConstraintWidget next;
        int offset = this.mOrientation * 2;
        ConstraintWidget lastVisited = this.mFirst;
        boolean z = true;
        this.mOptimizable = true;
        ConstraintWidget widget = this.mFirst;
        ConstraintWidget constraintWidget = this.mFirst;
        boolean done = false;
        while (!done) {
            this.mWidgetsCount++;
            widget.mNextChainWidget[this.mOrientation] = null;
            widget.mListNextMatchConstraintsWidget[this.mOrientation] = null;
            if (widget.getVisibility() != 8) {
                this.mVisibleWidgets++;
                if (widget.getDimensionBehaviour(this.mOrientation) != ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT) {
                    this.mTotalSize += widget.getLength(this.mOrientation);
                }
                int margin = this.mTotalSize + widget.mListAnchors[offset].getMargin();
                this.mTotalSize = margin;
                this.mTotalSize = margin + widget.mListAnchors[offset + 1].getMargin();
                int margin2 = this.mTotalMargins + widget.mListAnchors[offset].getMargin();
                this.mTotalMargins = margin2;
                this.mTotalMargins = margin2 + widget.mListAnchors[offset + 1].getMargin();
                if (this.mFirstVisibleWidget == null) {
                    this.mFirstVisibleWidget = widget;
                }
                this.mLastVisibleWidget = widget;
                if (widget.mListDimensionBehaviors[this.mOrientation] == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT) {
                    if (widget.mResolvedMatchConstraintDefault[this.mOrientation] == 0 || widget.mResolvedMatchConstraintDefault[this.mOrientation] == 3 || widget.mResolvedMatchConstraintDefault[this.mOrientation] == 2) {
                        this.mWidgetsMatchCount++;
                        float weight = widget.mWeight[this.mOrientation];
                        if (weight > 0.0f) {
                            this.mTotalWeight += widget.mWeight[this.mOrientation];
                        }
                        if (isMatchConstraintEqualityCandidate(widget, this.mOrientation)) {
                            if (weight < 0.0f) {
                                this.mHasUndefinedWeights = true;
                            } else {
                                this.mHasDefinedWeights = true;
                            }
                            if (this.mWeightedMatchConstraintsWidgets == null) {
                                this.mWeightedMatchConstraintsWidgets = new ArrayList<>();
                            }
                            this.mWeightedMatchConstraintsWidgets.add(widget);
                        }
                        if (this.mFirstMatchConstraintWidget == null) {
                            this.mFirstMatchConstraintWidget = widget;
                        }
                        ConstraintWidget constraintWidget2 = this.mLastMatchConstraintWidget;
                        if (constraintWidget2 != null) {
                            constraintWidget2.mListNextMatchConstraintsWidget[this.mOrientation] = widget;
                        }
                        this.mLastMatchConstraintWidget = widget;
                    }
                    if (this.mOrientation == 0) {
                        if (widget.mMatchConstraintDefaultWidth != 0) {
                            this.mOptimizable = false;
                        } else if (widget.mMatchConstraintMinWidth != 0 || widget.mMatchConstraintMaxWidth != 0) {
                            this.mOptimizable = false;
                        }
                    } else if (widget.mMatchConstraintDefaultHeight != 0) {
                        this.mOptimizable = false;
                    } else if (widget.mMatchConstraintMinHeight != 0 || widget.mMatchConstraintMaxHeight != 0) {
                        this.mOptimizable = false;
                    }
                    if (widget.mDimensionRatio != 0.0f) {
                        this.mOptimizable = false;
                        this.mHasRatio = true;
                    }
                }
            }
            if (lastVisited != widget) {
                lastVisited.mNextChainWidget[this.mOrientation] = widget;
            }
            lastVisited = widget;
            ConstraintAnchor nextAnchor = widget.mListAnchors[offset + 1].mTarget;
            if (nextAnchor != null) {
                next = nextAnchor.mOwner;
                if (next.mListAnchors[offset].mTarget == null || next.mListAnchors[offset].mTarget.mOwner != widget) {
                    next = null;
                }
            } else {
                next = null;
            }
            if (next != null) {
                widget = next;
            } else {
                done = true;
            }
        }
        ConstraintWidget constraintWidget3 = this.mFirstVisibleWidget;
        if (constraintWidget3 != null) {
            this.mTotalSize -= constraintWidget3.mListAnchors[offset].getMargin();
        }
        ConstraintWidget constraintWidget4 = this.mLastVisibleWidget;
        if (constraintWidget4 != null) {
            this.mTotalSize -= constraintWidget4.mListAnchors[offset + 1].getMargin();
        }
        this.mLast = widget;
        if (this.mOrientation == 0 && this.mIsRtl) {
            this.mHead = widget;
        } else {
            this.mHead = this.mFirst;
        }
        this.mHasComplexMatchWeights = (this.mHasDefinedWeights && this.mHasUndefinedWeights) ? false : false;
    }

    public ConstraintWidget getFirst() {
        return this.mFirst;
    }

    public ConstraintWidget getFirstVisibleWidget() {
        return this.mFirstVisibleWidget;
    }

    public ConstraintWidget getLast() {
        return this.mLast;
    }

    public ConstraintWidget getLastVisibleWidget() {
        return this.mLastVisibleWidget;
    }

    public ConstraintWidget getHead() {
        return this.mHead;
    }

    public ConstraintWidget getFirstMatchConstraintWidget() {
        return this.mFirstMatchConstraintWidget;
    }

    public ConstraintWidget getLastMatchConstraintWidget() {
        return this.mLastMatchConstraintWidget;
    }

    public float getTotalWeight() {
        return this.mTotalWeight;
    }

    public void define() {
        if (!this.mDefined) {
            defineChainProperties();
        }
        this.mDefined = true;
    }
}
