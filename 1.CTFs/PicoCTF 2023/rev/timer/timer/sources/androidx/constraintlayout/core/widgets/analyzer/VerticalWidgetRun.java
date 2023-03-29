package androidx.constraintlayout.core.widgets.analyzer;

import androidx.constraintlayout.core.widgets.ConstraintAnchor;
import androidx.constraintlayout.core.widgets.ConstraintWidget;
import androidx.constraintlayout.core.widgets.Helper;
import androidx.constraintlayout.core.widgets.analyzer.DependencyNode;
import androidx.constraintlayout.core.widgets.analyzer.WidgetRun;
/* loaded from: classes.dex */
public class VerticalWidgetRun extends WidgetRun {
    public DependencyNode baseline;
    DimensionDependency baselineDimension;

    public VerticalWidgetRun(ConstraintWidget widget) {
        super(widget);
        this.baseline = new DependencyNode(this);
        this.baselineDimension = null;
        this.start.type = DependencyNode.Type.TOP;
        this.end.type = DependencyNode.Type.BOTTOM;
        this.baseline.type = DependencyNode.Type.BASELINE;
        this.orientation = 1;
    }

    public String toString() {
        return "VerticalRun " + this.widget.getDebugName();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // androidx.constraintlayout.core.widgets.analyzer.WidgetRun
    public void clear() {
        this.runGroup = null;
        this.start.clear();
        this.end.clear();
        this.baseline.clear();
        this.dimension.clear();
        this.resolved = false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // androidx.constraintlayout.core.widgets.analyzer.WidgetRun
    public void reset() {
        this.resolved = false;
        this.start.clear();
        this.start.resolved = false;
        this.end.clear();
        this.end.resolved = false;
        this.baseline.clear();
        this.baseline.resolved = false;
        this.dimension.resolved = false;
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.WidgetRun
    boolean supportsWrapComputation() {
        return this.dimensionBehavior != ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT || this.widget.mMatchConstraintDefaultHeight == 0;
    }

    /* renamed from: androidx.constraintlayout.core.widgets.analyzer.VerticalWidgetRun$1  reason: invalid class name */
    /* loaded from: classes.dex */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$androidx$constraintlayout$core$widgets$analyzer$WidgetRun$RunType;

        static {
            int[] iArr = new int[WidgetRun.RunType.values().length];
            $SwitchMap$androidx$constraintlayout$core$widgets$analyzer$WidgetRun$RunType = iArr;
            try {
                iArr[WidgetRun.RunType.START.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$androidx$constraintlayout$core$widgets$analyzer$WidgetRun$RunType[WidgetRun.RunType.END.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$androidx$constraintlayout$core$widgets$analyzer$WidgetRun$RunType[WidgetRun.RunType.CENTER.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
        }
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.WidgetRun, androidx.constraintlayout.core.widgets.analyzer.Dependency
    public void update(Dependency dependency) {
        switch (AnonymousClass1.$SwitchMap$androidx$constraintlayout$core$widgets$analyzer$WidgetRun$RunType[this.mRunType.ordinal()]) {
            case 1:
                updateRunStart(dependency);
                break;
            case 2:
                updateRunEnd(dependency);
                break;
            case 3:
                updateRunCenter(dependency, this.widget.mTop, this.widget.mBottom, 1);
                return;
        }
        if (this.dimension.readyToSolve && !this.dimension.resolved && this.dimensionBehavior == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT) {
            switch (this.widget.mMatchConstraintDefaultHeight) {
                case 2:
                    ConstraintWidget parent = this.widget.getParent();
                    if (parent != null && parent.verticalRun.dimension.resolved) {
                        float percent = this.widget.mMatchConstraintPercentHeight;
                        int targetDimensionValue = parent.verticalRun.dimension.value;
                        int size = (int) ((targetDimensionValue * percent) + 0.5f);
                        this.dimension.resolve(size);
                        break;
                    }
                    break;
                case 3:
                    if (this.widget.horizontalRun.dimension.resolved) {
                        int size2 = 0;
                        int ratioSide = this.widget.getDimensionRatioSide();
                        switch (ratioSide) {
                            case -1:
                                size2 = (int) ((this.widget.horizontalRun.dimension.value / this.widget.getDimensionRatio()) + 0.5f);
                                break;
                            case 0:
                                size2 = (int) ((this.widget.horizontalRun.dimension.value * this.widget.getDimensionRatio()) + 0.5f);
                                break;
                            case 1:
                                size2 = (int) ((this.widget.horizontalRun.dimension.value / this.widget.getDimensionRatio()) + 0.5f);
                                break;
                        }
                        this.dimension.resolve(size2);
                        break;
                    }
                    break;
            }
        }
        if (!this.start.readyToSolve || !this.end.readyToSolve) {
            return;
        }
        if (this.start.resolved && this.end.resolved && this.dimension.resolved) {
            return;
        }
        if (!this.dimension.resolved && this.dimensionBehavior == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT && this.widget.mMatchConstraintDefaultWidth == 0 && !this.widget.isInVerticalChain()) {
            int startPos = this.start.targets.get(0).value + this.start.margin;
            int endPos = this.end.targets.get(0).value + this.end.margin;
            int distance = endPos - startPos;
            this.start.resolve(startPos);
            this.end.resolve(endPos);
            this.dimension.resolve(distance);
            return;
        }
        if (!this.dimension.resolved && this.dimensionBehavior == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT && this.matchConstraintsType == 1 && this.start.targets.size() > 0 && this.end.targets.size() > 0) {
            int startPos2 = this.start.targets.get(0).value + this.start.margin;
            int endPos2 = this.end.targets.get(0).value + this.end.margin;
            int availableSpace = endPos2 - startPos2;
            if (availableSpace < this.dimension.wrapValue) {
                this.dimension.resolve(availableSpace);
            } else {
                this.dimension.resolve(this.dimension.wrapValue);
            }
        }
        if (this.dimension.resolved && this.start.targets.size() > 0 && this.end.targets.size() > 0) {
            DependencyNode startTarget = this.start.targets.get(0);
            DependencyNode endTarget = this.end.targets.get(0);
            int startPos3 = startTarget.value + this.start.margin;
            int endPos3 = endTarget.value + this.end.margin;
            float bias = this.widget.getVerticalBiasPercent();
            if (startTarget == endTarget) {
                startPos3 = startTarget.value;
                endPos3 = endTarget.value;
                bias = 0.5f;
            }
            int distance2 = (endPos3 - startPos3) - this.dimension.value;
            this.start.resolve((int) (startPos3 + 0.5f + (distance2 * bias)));
            this.end.resolve(this.start.value + this.dimension.value);
        }
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.WidgetRun
    void apply() {
        ConstraintWidget parent;
        ConstraintWidget parent2;
        if (this.widget.measured) {
            this.dimension.resolve(this.widget.getHeight());
        }
        if (!this.dimension.resolved) {
            this.dimensionBehavior = this.widget.getVerticalDimensionBehaviour();
            if (this.widget.hasBaseline()) {
                this.baselineDimension = new BaselineDimensionDependency(this);
            }
            if (this.dimensionBehavior != ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT) {
                if (this.dimensionBehavior == ConstraintWidget.DimensionBehaviour.MATCH_PARENT && (parent2 = this.widget.getParent()) != null && parent2.getVerticalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.FIXED) {
                    int resolvedDimension = (parent2.getHeight() - this.widget.mTop.getMargin()) - this.widget.mBottom.getMargin();
                    addTarget(this.start, parent2.verticalRun.start, this.widget.mTop.getMargin());
                    addTarget(this.end, parent2.verticalRun.end, -this.widget.mBottom.getMargin());
                    this.dimension.resolve(resolvedDimension);
                    return;
                } else if (this.dimensionBehavior == ConstraintWidget.DimensionBehaviour.FIXED) {
                    this.dimension.resolve(this.widget.getHeight());
                }
            }
        } else if (this.dimensionBehavior == ConstraintWidget.DimensionBehaviour.MATCH_PARENT && (parent = this.widget.getParent()) != null && parent.getVerticalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.FIXED) {
            addTarget(this.start, parent.verticalRun.start, this.widget.mTop.getMargin());
            addTarget(this.end, parent.verticalRun.end, -this.widget.mBottom.getMargin());
            return;
        }
        if (this.dimension.resolved && this.widget.measured) {
            if (this.widget.mListAnchors[2].mTarget != null && this.widget.mListAnchors[3].mTarget != null) {
                if (this.widget.isInVerticalChain()) {
                    this.start.margin = this.widget.mListAnchors[2].getMargin();
                    this.end.margin = -this.widget.mListAnchors[3].getMargin();
                } else {
                    DependencyNode startTarget = getTarget(this.widget.mListAnchors[2]);
                    if (startTarget != null) {
                        addTarget(this.start, startTarget, this.widget.mListAnchors[2].getMargin());
                    }
                    DependencyNode endTarget = getTarget(this.widget.mListAnchors[3]);
                    if (endTarget != null) {
                        addTarget(this.end, endTarget, -this.widget.mListAnchors[3].getMargin());
                    }
                    this.start.delegateToWidgetRun = true;
                    this.end.delegateToWidgetRun = true;
                }
                if (this.widget.hasBaseline()) {
                    addTarget(this.baseline, this.start, this.widget.getBaselineDistance());
                    return;
                }
                return;
            } else if (this.widget.mListAnchors[2].mTarget != null) {
                DependencyNode target = getTarget(this.widget.mListAnchors[2]);
                if (target != null) {
                    addTarget(this.start, target, this.widget.mListAnchors[2].getMargin());
                    addTarget(this.end, this.start, this.dimension.value);
                    if (this.widget.hasBaseline()) {
                        addTarget(this.baseline, this.start, this.widget.getBaselineDistance());
                        return;
                    }
                    return;
                }
                return;
            } else if (this.widget.mListAnchors[3].mTarget != null) {
                DependencyNode target2 = getTarget(this.widget.mListAnchors[3]);
                if (target2 != null) {
                    addTarget(this.end, target2, -this.widget.mListAnchors[3].getMargin());
                    addTarget(this.start, this.end, -this.dimension.value);
                }
                if (this.widget.hasBaseline()) {
                    addTarget(this.baseline, this.start, this.widget.getBaselineDistance());
                    return;
                }
                return;
            } else if (this.widget.mListAnchors[4].mTarget != null) {
                DependencyNode target3 = getTarget(this.widget.mListAnchors[4]);
                if (target3 != null) {
                    addTarget(this.baseline, target3, 0);
                    addTarget(this.start, this.baseline, -this.widget.getBaselineDistance());
                    addTarget(this.end, this.start, this.dimension.value);
                    return;
                }
                return;
            } else if (!(this.widget instanceof Helper) && this.widget.getParent() != null && this.widget.getAnchor(ConstraintAnchor.Type.CENTER).mTarget == null) {
                DependencyNode top = this.widget.getParent().verticalRun.start;
                addTarget(this.start, top, this.widget.getY());
                addTarget(this.end, this.start, this.dimension.value);
                if (this.widget.hasBaseline()) {
                    addTarget(this.baseline, this.start, this.widget.getBaselineDistance());
                    return;
                }
                return;
            } else {
                return;
            }
        }
        if (!this.dimension.resolved && this.dimensionBehavior == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT) {
            switch (this.widget.mMatchConstraintDefaultHeight) {
                case 2:
                    ConstraintWidget parent3 = this.widget.getParent();
                    if (parent3 != null) {
                        DependencyNode targetDimension = parent3.verticalRun.dimension;
                        this.dimension.targets.add(targetDimension);
                        targetDimension.dependencies.add(this.dimension);
                        this.dimension.delegateToWidgetRun = true;
                        this.dimension.dependencies.add(this.start);
                        this.dimension.dependencies.add(this.end);
                        break;
                    }
                    break;
                case 3:
                    if (!this.widget.isInVerticalChain() && this.widget.mMatchConstraintDefaultWidth != 3) {
                        DependencyNode targetDimension2 = this.widget.horizontalRun.dimension;
                        this.dimension.targets.add(targetDimension2);
                        targetDimension2.dependencies.add(this.dimension);
                        this.dimension.delegateToWidgetRun = true;
                        this.dimension.dependencies.add(this.start);
                        this.dimension.dependencies.add(this.end);
                        break;
                    }
                    break;
            }
        } else {
            this.dimension.addDependency(this);
        }
        if (this.widget.mListAnchors[2].mTarget != null && this.widget.mListAnchors[3].mTarget != null) {
            if (this.widget.isInVerticalChain()) {
                this.start.margin = this.widget.mListAnchors[2].getMargin();
                this.end.margin = -this.widget.mListAnchors[3].getMargin();
            } else {
                DependencyNode startTarget2 = getTarget(this.widget.mListAnchors[2]);
                DependencyNode endTarget2 = getTarget(this.widget.mListAnchors[3]);
                if (startTarget2 != null) {
                    startTarget2.addDependency(this);
                }
                if (endTarget2 != null) {
                    endTarget2.addDependency(this);
                }
                this.mRunType = WidgetRun.RunType.CENTER;
            }
            if (this.widget.hasBaseline()) {
                addTarget(this.baseline, this.start, 1, this.baselineDimension);
            }
        } else if (this.widget.mListAnchors[2].mTarget != null) {
            DependencyNode target4 = getTarget(this.widget.mListAnchors[2]);
            if (target4 != null) {
                addTarget(this.start, target4, this.widget.mListAnchors[2].getMargin());
                addTarget(this.end, this.start, 1, this.dimension);
                if (this.widget.hasBaseline()) {
                    addTarget(this.baseline, this.start, 1, this.baselineDimension);
                }
                if (this.dimensionBehavior == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT && this.widget.getDimensionRatio() > 0.0f && this.widget.horizontalRun.dimensionBehavior == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT) {
                    this.widget.horizontalRun.dimension.dependencies.add(this.dimension);
                    this.dimension.targets.add(this.widget.horizontalRun.dimension);
                    this.dimension.updateDelegate = this;
                }
            }
        } else if (this.widget.mListAnchors[3].mTarget != null) {
            DependencyNode target5 = getTarget(this.widget.mListAnchors[3]);
            if (target5 != null) {
                addTarget(this.end, target5, -this.widget.mListAnchors[3].getMargin());
                addTarget(this.start, this.end, -1, this.dimension);
                if (this.widget.hasBaseline()) {
                    addTarget(this.baseline, this.start, 1, this.baselineDimension);
                }
            }
        } else if (this.widget.mListAnchors[4].mTarget != null) {
            DependencyNode target6 = getTarget(this.widget.mListAnchors[4]);
            if (target6 != null) {
                addTarget(this.baseline, target6, 0);
                addTarget(this.start, this.baseline, -1, this.baselineDimension);
                addTarget(this.end, this.start, 1, this.dimension);
            }
        } else if (!(this.widget instanceof Helper) && this.widget.getParent() != null) {
            DependencyNode top2 = this.widget.getParent().verticalRun.start;
            addTarget(this.start, top2, this.widget.getY());
            addTarget(this.end, this.start, 1, this.dimension);
            if (this.widget.hasBaseline()) {
                addTarget(this.baseline, this.start, 1, this.baselineDimension);
            }
            if (this.dimensionBehavior == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT && this.widget.getDimensionRatio() > 0.0f && this.widget.horizontalRun.dimensionBehavior == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT) {
                this.widget.horizontalRun.dimension.dependencies.add(this.dimension);
                this.dimension.targets.add(this.widget.horizontalRun.dimension);
                this.dimension.updateDelegate = this;
            }
        }
        if (this.dimension.targets.size() == 0) {
            this.dimension.readyToSolve = true;
        }
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.WidgetRun
    public void applyToWidget() {
        if (this.start.resolved) {
            this.widget.setY(this.start.value);
        }
    }
}
