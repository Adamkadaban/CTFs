package androidx.constraintlayout.core.widgets.analyzer;

import androidx.constraintlayout.core.LinearSystem;
import androidx.constraintlayout.core.Metrics;
import androidx.constraintlayout.core.widgets.Barrier;
import androidx.constraintlayout.core.widgets.ConstraintAnchor;
import androidx.constraintlayout.core.widgets.ConstraintWidget;
import androidx.constraintlayout.core.widgets.ConstraintWidgetContainer;
import androidx.constraintlayout.core.widgets.Guideline;
import androidx.constraintlayout.core.widgets.Helper;
import androidx.constraintlayout.core.widgets.Optimizer;
import androidx.constraintlayout.core.widgets.VirtualLayout;
import java.util.ArrayList;
/* loaded from: classes.dex */
public class BasicMeasure {
    public static final int AT_MOST = Integer.MIN_VALUE;
    private static final boolean DEBUG = false;
    public static final int EXACTLY = 1073741824;
    public static final int FIXED = -3;
    public static final int MATCH_PARENT = -1;
    private static final int MODE_SHIFT = 30;
    public static final int UNSPECIFIED = 0;
    public static final int WRAP_CONTENT = -2;
    private ConstraintWidgetContainer constraintWidgetContainer;
    private final ArrayList<ConstraintWidget> mVariableDimensionsWidgets = new ArrayList<>();
    private Measure mMeasure = new Measure();

    /* loaded from: classes.dex */
    public static class Measure {
        public static int SELF_DIMENSIONS = 0;
        public static int TRY_GIVEN_DIMENSIONS = 1;
        public static int USE_GIVEN_DIMENSIONS = 2;
        public ConstraintWidget.DimensionBehaviour horizontalBehavior;
        public int horizontalDimension;
        public int measureStrategy;
        public int measuredBaseline;
        public boolean measuredHasBaseline;
        public int measuredHeight;
        public boolean measuredNeedsSolverPass;
        public int measuredWidth;
        public ConstraintWidget.DimensionBehaviour verticalBehavior;
        public int verticalDimension;
    }

    /* loaded from: classes.dex */
    public interface Measurer {
        void didMeasures();

        void measure(ConstraintWidget constraintWidget, Measure measure);
    }

    public void updateHierarchy(ConstraintWidgetContainer layout) {
        this.mVariableDimensionsWidgets.clear();
        int childCount = layout.mChildren.size();
        for (int i = 0; i < childCount; i++) {
            ConstraintWidget widget = layout.mChildren.get(i);
            if (widget.getHorizontalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT || widget.getVerticalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT) {
                this.mVariableDimensionsWidgets.add(widget);
            }
        }
        layout.invalidateGraph();
    }

    public BasicMeasure(ConstraintWidgetContainer constraintWidgetContainer) {
        this.constraintWidgetContainer = constraintWidgetContainer;
    }

    private void measureChildren(ConstraintWidgetContainer layout) {
        int childCount = layout.mChildren.size();
        boolean optimize = layout.optimizeFor(64);
        Measurer measurer = layout.getMeasurer();
        for (int i = 0; i < childCount; i++) {
            ConstraintWidget child = layout.mChildren.get(i);
            if (!(child instanceof Guideline) && !(child instanceof Barrier) && !child.isInVirtualLayout() && (!optimize || child.horizontalRun == null || child.verticalRun == null || !child.horizontalRun.dimension.resolved || !child.verticalRun.dimension.resolved)) {
                boolean skip = false;
                ConstraintWidget.DimensionBehaviour widthBehavior = child.getDimensionBehaviour(0);
                ConstraintWidget.DimensionBehaviour heightBehavior = child.getDimensionBehaviour(1);
                if (widthBehavior == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT && child.mMatchConstraintDefaultWidth != 1 && heightBehavior == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT && child.mMatchConstraintDefaultHeight != 1) {
                    skip = true;
                }
                if (!skip && layout.optimizeFor(1) && !(child instanceof VirtualLayout)) {
                    if (widthBehavior == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT && child.mMatchConstraintDefaultWidth == 0 && heightBehavior != ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT && !child.isInHorizontalChain()) {
                        skip = true;
                    }
                    if (heightBehavior == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT && child.mMatchConstraintDefaultHeight == 0 && widthBehavior != ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT && !child.isInHorizontalChain()) {
                        skip = true;
                    }
                    if ((widthBehavior == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT || heightBehavior == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT) && child.mDimensionRatio > 0.0f) {
                        skip = true;
                    }
                }
                if (!skip) {
                    measure(measurer, child, Measure.SELF_DIMENSIONS);
                    if (layout.mMetrics != null) {
                        layout.mMetrics.measuredWidgets++;
                    }
                }
            }
        }
        measurer.didMeasures();
    }

    private void solveLinearSystem(ConstraintWidgetContainer layout, String reason, int pass, int w, int h) {
        int minWidth = layout.getMinWidth();
        int minHeight = layout.getMinHeight();
        layout.setMinWidth(0);
        layout.setMinHeight(0);
        layout.setWidth(w);
        layout.setHeight(h);
        layout.setMinWidth(minWidth);
        layout.setMinHeight(minHeight);
        this.constraintWidgetContainer.setPass(pass);
        this.constraintWidgetContainer.layout();
    }

    public long solverMeasure(ConstraintWidgetContainer layout, int optimizationLevel, int paddingX, int paddingY, int widthMode, int widthSize, int heightMode, int heightSize, int lastMeasureWidth, int lastMeasureHeight) {
        boolean optimize;
        boolean matchHeight;
        boolean allSolved;
        int computations;
        int sizeDependentWidgetsCount;
        int optimizations;
        long layoutTime;
        int sizeDependentWidgetsCount2;
        int measureStrategy;
        Measurer measurer;
        boolean needSolverPass;
        int childCount;
        long layoutTime2;
        boolean allSolved2;
        int widthSize2;
        boolean z;
        Measurer measurer2 = layout.getMeasurer();
        long layoutTime3 = 0;
        int childCount2 = layout.mChildren.size();
        int startingWidth = layout.getWidth();
        int startingHeight = layout.getHeight();
        boolean optimizeWrap = Optimizer.enabled(optimizationLevel, 128);
        boolean optimize2 = optimizeWrap || Optimizer.enabled(optimizationLevel, 64);
        if (!optimize2) {
            optimize = optimize2;
        } else {
            int i = 0;
            while (i < childCount2) {
                ConstraintWidget child = layout.mChildren.get(i);
                boolean matchWidth = child.getHorizontalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT;
                boolean optimize3 = optimize2;
                boolean matchHeight2 = child.getVerticalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT;
                boolean ratio = matchWidth && matchHeight2 && child.getDimensionRatio() > 0.0f;
                if (child.isInHorizontalChain() && ratio) {
                    matchHeight = false;
                    break;
                } else if (child.isInVerticalChain() && ratio) {
                    matchHeight = false;
                    break;
                } else {
                    boolean matchHeight3 = child instanceof VirtualLayout;
                    if (matchHeight3) {
                        matchHeight = false;
                        break;
                    }
                    if (!child.isInHorizontalChain() && !child.isInVerticalChain()) {
                        i++;
                        optimize2 = optimize3;
                    } else {
                        matchHeight = false;
                        break;
                    }
                }
            }
            optimize = optimize2;
        }
        matchHeight = optimize;
        if (matchHeight && LinearSystem.sMetrics != null) {
            LinearSystem.sMetrics.measures++;
        }
        boolean optimize4 = matchHeight & ((widthMode == 1073741824 && heightMode == 1073741824) || optimizeWrap);
        int computations2 = 0;
        if (!optimize4) {
            allSolved = false;
            computations = 0;
        } else {
            int widthSize3 = Math.min(layout.getMaxWidth(), widthSize);
            int heightSize2 = Math.min(layout.getMaxHeight(), heightSize);
            if (widthMode == 1073741824 && layout.getWidth() != widthSize3) {
                layout.setWidth(widthSize3);
                layout.invalidateGraph();
            }
            if (heightMode == 1073741824 && layout.getHeight() != heightSize2) {
                layout.setHeight(heightSize2);
                layout.invalidateGraph();
            }
            if (widthMode == 1073741824 && heightMode == 1073741824) {
                allSolved2 = layout.directMeasure(optimizeWrap);
                computations2 = 2;
                widthSize2 = widthSize3;
                z = true;
            } else {
                allSolved2 = layout.directMeasureSetup(optimizeWrap);
                if (widthMode != 1073741824) {
                    widthSize2 = widthSize3;
                } else {
                    widthSize2 = widthSize3;
                    allSolved2 &= layout.directMeasureWithOrientation(optimizeWrap, 0);
                    computations2 = 0 + 1;
                }
                if (heightMode != 1073741824) {
                    z = true;
                } else {
                    z = true;
                    allSolved2 &= layout.directMeasureWithOrientation(optimizeWrap, 1);
                    computations2++;
                }
            }
            if (allSolved2) {
                if (widthMode != 1073741824) {
                    z = false;
                }
                layout.updateFromRuns(z, heightMode == 1073741824);
            }
            computations = computations2;
            allSolved = allSolved2;
        }
        if (allSolved && computations == 2) {
            return 0L;
        }
        int optimizations2 = layout.getOptimizationLevel();
        if (childCount2 > 0) {
            measureChildren(layout);
        }
        updateHierarchy(layout);
        int sizeDependentWidgetsCount3 = this.mVariableDimensionsWidgets.size();
        if (childCount2 <= 0) {
            sizeDependentWidgetsCount = sizeDependentWidgetsCount3;
            optimizations = optimizations2;
        } else {
            sizeDependentWidgetsCount = sizeDependentWidgetsCount3;
            optimizations = optimizations2;
            solveLinearSystem(layout, "First pass", 0, startingWidth, startingHeight);
        }
        int sizeDependentWidgetsCount4 = sizeDependentWidgetsCount;
        if (sizeDependentWidgetsCount4 <= 0) {
            layoutTime = 0;
        } else {
            boolean needSolverPass2 = false;
            boolean containerWrapWidth = layout.getHorizontalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT;
            boolean containerWrapHeight = layout.getVerticalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT;
            int minWidth = Math.max(layout.getWidth(), this.constraintWidgetContainer.getMinWidth());
            int minHeight = Math.max(layout.getHeight(), this.constraintWidgetContainer.getMinHeight());
            int i2 = 0;
            while (i2 < sizeDependentWidgetsCount4) {
                ConstraintWidget widget = this.mVariableDimensionsWidgets.get(i2);
                if (!(widget instanceof VirtualLayout)) {
                    layoutTime2 = layoutTime3;
                    childCount = childCount2;
                } else {
                    int preWidth = widget.getWidth();
                    int preHeight = widget.getHeight();
                    childCount = childCount2;
                    boolean needSolverPass3 = needSolverPass2 | measure(measurer2, widget, Measure.TRY_GIVEN_DIMENSIONS);
                    if (layout.mMetrics == null) {
                        layoutTime2 = layoutTime3;
                    } else {
                        Metrics metrics = layout.mMetrics;
                        layoutTime2 = layoutTime3;
                        long layoutTime4 = metrics.measuredMatchWidgets;
                        metrics.measuredMatchWidgets = layoutTime4 + 1;
                    }
                    int measuredWidth = widget.getWidth();
                    int measuredHeight = widget.getHeight();
                    if (measuredWidth != preWidth) {
                        widget.setWidth(measuredWidth);
                        if (containerWrapWidth && widget.getRight() > minWidth) {
                            int w = widget.getRight() + widget.getAnchor(ConstraintAnchor.Type.RIGHT).getMargin();
                            minWidth = Math.max(minWidth, w);
                        }
                        needSolverPass3 = true;
                    }
                    if (measuredHeight != preHeight) {
                        widget.setHeight(measuredHeight);
                        if (containerWrapHeight && widget.getBottom() > minHeight) {
                            int h = widget.getBottom() + widget.getAnchor(ConstraintAnchor.Type.BOTTOM).getMargin();
                            minHeight = Math.max(minHeight, h);
                        }
                        needSolverPass3 = true;
                    }
                    VirtualLayout virtualLayout = (VirtualLayout) widget;
                    needSolverPass2 = needSolverPass3 | virtualLayout.needSolverPass();
                }
                i2++;
                childCount2 = childCount;
                layoutTime3 = layoutTime2;
            }
            layoutTime = layoutTime3;
            int j = 0;
            while (j < 2) {
                int i3 = 0;
                boolean needSolverPass4 = needSolverPass2;
                int minWidth2 = minWidth;
                int minHeight2 = minHeight;
                while (i3 < sizeDependentWidgetsCount4) {
                    ConstraintWidget widget2 = this.mVariableDimensionsWidgets.get(i3);
                    if (((widget2 instanceof Helper) && !(widget2 instanceof VirtualLayout)) || (widget2 instanceof Guideline) || widget2.getVisibility() == 8 || ((optimize4 && widget2.horizontalRun.dimension.resolved && widget2.verticalRun.dimension.resolved) || (widget2 instanceof VirtualLayout))) {
                        sizeDependentWidgetsCount2 = sizeDependentWidgetsCount4;
                        measurer = measurer2;
                    } else {
                        int preWidth2 = widget2.getWidth();
                        int preHeight2 = widget2.getHeight();
                        int preBaselineDistance = widget2.getBaselineDistance();
                        int measureStrategy2 = Measure.TRY_GIVEN_DIMENSIONS;
                        sizeDependentWidgetsCount2 = sizeDependentWidgetsCount4;
                        if (j != 2 - 1) {
                            measureStrategy = measureStrategy2;
                        } else {
                            int measureStrategy3 = Measure.USE_GIVEN_DIMENSIONS;
                            measureStrategy = measureStrategy3;
                        }
                        boolean hasMeasure = measure(measurer2, widget2, measureStrategy);
                        boolean needSolverPass5 = needSolverPass4 | hasMeasure;
                        if (layout.mMetrics == null) {
                            measurer = measurer2;
                            needSolverPass = needSolverPass5;
                        } else {
                            measurer = measurer2;
                            needSolverPass = needSolverPass5;
                            layout.mMetrics.measuredMatchWidgets++;
                        }
                        int measuredWidth2 = widget2.getWidth();
                        int measuredHeight2 = widget2.getHeight();
                        if (measuredWidth2 != preWidth2) {
                            widget2.setWidth(measuredWidth2);
                            if (containerWrapWidth && widget2.getRight() > minWidth2) {
                                int w2 = widget2.getRight() + widget2.getAnchor(ConstraintAnchor.Type.RIGHT).getMargin();
                                minWidth2 = Math.max(minWidth2, w2);
                            }
                            needSolverPass4 = true;
                        } else {
                            needSolverPass4 = needSolverPass;
                        }
                        if (measuredHeight2 != preHeight2) {
                            widget2.setHeight(measuredHeight2);
                            if (containerWrapHeight && widget2.getBottom() > minHeight2) {
                                int h2 = widget2.getBottom() + widget2.getAnchor(ConstraintAnchor.Type.BOTTOM).getMargin();
                                minHeight2 = Math.max(minHeight2, h2);
                            }
                            needSolverPass4 = true;
                        }
                        if (widget2.hasBaseline() && preBaselineDistance != widget2.getBaselineDistance()) {
                            needSolverPass4 = true;
                        }
                    }
                    i3++;
                    sizeDependentWidgetsCount4 = sizeDependentWidgetsCount2;
                    measurer2 = measurer;
                }
                int sizeDependentWidgetsCount5 = sizeDependentWidgetsCount4;
                Measurer measurer3 = measurer2;
                if (!needSolverPass4) {
                    break;
                }
                solveLinearSystem(layout, "intermediate pass", j + 1, startingWidth, startingHeight);
                needSolverPass2 = false;
                j++;
                sizeDependentWidgetsCount4 = sizeDependentWidgetsCount5;
                minWidth = minWidth2;
                minHeight = minHeight2;
                measurer2 = measurer3;
            }
        }
        layout.setOptimizationLevel(optimizations);
        return layoutTime;
    }

    private boolean measure(Measurer measurer, ConstraintWidget widget, int measureStrategy) {
        this.mMeasure.horizontalBehavior = widget.getHorizontalDimensionBehaviour();
        this.mMeasure.verticalBehavior = widget.getVerticalDimensionBehaviour();
        this.mMeasure.horizontalDimension = widget.getWidth();
        this.mMeasure.verticalDimension = widget.getHeight();
        this.mMeasure.measuredNeedsSolverPass = false;
        this.mMeasure.measureStrategy = measureStrategy;
        boolean horizontalMatchConstraints = this.mMeasure.horizontalBehavior == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT;
        boolean verticalMatchConstraints = this.mMeasure.verticalBehavior == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT;
        boolean horizontalUseRatio = horizontalMatchConstraints && widget.mDimensionRatio > 0.0f;
        boolean verticalUseRatio = verticalMatchConstraints && widget.mDimensionRatio > 0.0f;
        if (horizontalUseRatio && widget.mResolvedMatchConstraintDefault[0] == 4) {
            this.mMeasure.horizontalBehavior = ConstraintWidget.DimensionBehaviour.FIXED;
        }
        if (verticalUseRatio && widget.mResolvedMatchConstraintDefault[1] == 4) {
            this.mMeasure.verticalBehavior = ConstraintWidget.DimensionBehaviour.FIXED;
        }
        measurer.measure(widget, this.mMeasure);
        widget.setWidth(this.mMeasure.measuredWidth);
        widget.setHeight(this.mMeasure.measuredHeight);
        widget.setHasBaseline(this.mMeasure.measuredHasBaseline);
        widget.setBaselineDistance(this.mMeasure.measuredBaseline);
        this.mMeasure.measureStrategy = Measure.SELF_DIMENSIONS;
        return this.mMeasure.measuredNeedsSolverPass;
    }
}
