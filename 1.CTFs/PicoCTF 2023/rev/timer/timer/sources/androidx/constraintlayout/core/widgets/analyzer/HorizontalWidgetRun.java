package androidx.constraintlayout.core.widgets.analyzer;

import androidx.constraintlayout.core.widgets.ConstraintAnchor;
import androidx.constraintlayout.core.widgets.ConstraintWidget;
import androidx.constraintlayout.core.widgets.Helper;
import androidx.constraintlayout.core.widgets.analyzer.DependencyNode;
import androidx.constraintlayout.core.widgets.analyzer.WidgetRun;
/* loaded from: classes.dex */
public class HorizontalWidgetRun extends WidgetRun {
    private static int[] tempDimensions = new int[2];

    public HorizontalWidgetRun(ConstraintWidget widget) {
        super(widget);
        this.start.type = DependencyNode.Type.LEFT;
        this.end.type = DependencyNode.Type.RIGHT;
        this.orientation = 0;
    }

    public String toString() {
        return "HorizontalRun " + this.widget.getDebugName();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // androidx.constraintlayout.core.widgets.analyzer.WidgetRun
    public void clear() {
        this.runGroup = null;
        this.start.clear();
        this.end.clear();
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
        this.dimension.resolved = false;
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.WidgetRun
    boolean supportsWrapComputation() {
        return this.dimensionBehavior != ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT || this.widget.mMatchConstraintDefaultWidth == 0;
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.WidgetRun
    void apply() {
        ConstraintWidget parent;
        ConstraintWidget parent2;
        if (this.widget.measured) {
            this.dimension.resolve(this.widget.getWidth());
        }
        if (!this.dimension.resolved) {
            this.dimensionBehavior = this.widget.getHorizontalDimensionBehaviour();
            if (this.dimensionBehavior != ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT) {
                if (this.dimensionBehavior == ConstraintWidget.DimensionBehaviour.MATCH_PARENT && (parent2 = this.widget.getParent()) != null && (parent2.getHorizontalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.FIXED || parent2.getHorizontalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.MATCH_PARENT)) {
                    int resolvedDimension = (parent2.getWidth() - this.widget.mLeft.getMargin()) - this.widget.mRight.getMargin();
                    addTarget(this.start, parent2.horizontalRun.start, this.widget.mLeft.getMargin());
                    addTarget(this.end, parent2.horizontalRun.end, -this.widget.mRight.getMargin());
                    this.dimension.resolve(resolvedDimension);
                    return;
                } else if (this.dimensionBehavior == ConstraintWidget.DimensionBehaviour.FIXED) {
                    this.dimension.resolve(this.widget.getWidth());
                }
            }
        } else if (this.dimensionBehavior == ConstraintWidget.DimensionBehaviour.MATCH_PARENT && (parent = this.widget.getParent()) != null && (parent.getHorizontalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.FIXED || parent.getHorizontalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.MATCH_PARENT)) {
            addTarget(this.start, parent.horizontalRun.start, this.widget.mLeft.getMargin());
            addTarget(this.end, parent.horizontalRun.end, -this.widget.mRight.getMargin());
            return;
        }
        if (this.dimension.resolved && this.widget.measured) {
            if (this.widget.mListAnchors[0].mTarget != null && this.widget.mListAnchors[1].mTarget != null) {
                if (this.widget.isInHorizontalChain()) {
                    this.start.margin = this.widget.mListAnchors[0].getMargin();
                    this.end.margin = -this.widget.mListAnchors[1].getMargin();
                    return;
                }
                DependencyNode startTarget = getTarget(this.widget.mListAnchors[0]);
                if (startTarget != null) {
                    addTarget(this.start, startTarget, this.widget.mListAnchors[0].getMargin());
                }
                DependencyNode endTarget = getTarget(this.widget.mListAnchors[1]);
                if (endTarget != null) {
                    addTarget(this.end, endTarget, -this.widget.mListAnchors[1].getMargin());
                }
                this.start.delegateToWidgetRun = true;
                this.end.delegateToWidgetRun = true;
                return;
            } else if (this.widget.mListAnchors[0].mTarget != null) {
                DependencyNode target = getTarget(this.widget.mListAnchors[0]);
                if (target != null) {
                    addTarget(this.start, target, this.widget.mListAnchors[0].getMargin());
                    addTarget(this.end, this.start, this.dimension.value);
                    return;
                }
                return;
            } else if (this.widget.mListAnchors[1].mTarget != null) {
                DependencyNode target2 = getTarget(this.widget.mListAnchors[1]);
                if (target2 != null) {
                    addTarget(this.end, target2, -this.widget.mListAnchors[1].getMargin());
                    addTarget(this.start, this.end, -this.dimension.value);
                    return;
                }
                return;
            } else if (!(this.widget instanceof Helper) && this.widget.getParent() != null && this.widget.getAnchor(ConstraintAnchor.Type.CENTER).mTarget == null) {
                DependencyNode left = this.widget.getParent().horizontalRun.start;
                addTarget(this.start, left, this.widget.getX());
                addTarget(this.end, this.start, this.dimension.value);
                return;
            } else {
                return;
            }
        }
        if (this.dimensionBehavior == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT) {
            switch (this.widget.mMatchConstraintDefaultWidth) {
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
                    if (this.widget.mMatchConstraintDefaultHeight == 3) {
                        this.start.updateDelegate = this;
                        this.end.updateDelegate = this;
                        this.widget.verticalRun.start.updateDelegate = this;
                        this.widget.verticalRun.end.updateDelegate = this;
                        this.dimension.updateDelegate = this;
                        if (this.widget.isInVerticalChain()) {
                            this.dimension.targets.add(this.widget.verticalRun.dimension);
                            this.widget.verticalRun.dimension.dependencies.add(this.dimension);
                            this.widget.verticalRun.dimension.updateDelegate = this;
                            this.dimension.targets.add(this.widget.verticalRun.start);
                            this.dimension.targets.add(this.widget.verticalRun.end);
                            this.widget.verticalRun.start.dependencies.add(this.dimension);
                            this.widget.verticalRun.end.dependencies.add(this.dimension);
                            break;
                        } else if (this.widget.isInHorizontalChain()) {
                            this.widget.verticalRun.dimension.targets.add(this.dimension);
                            this.dimension.dependencies.add(this.widget.verticalRun.dimension);
                            break;
                        } else {
                            this.widget.verticalRun.dimension.targets.add(this.dimension);
                            break;
                        }
                    } else {
                        DependencyNode targetDimension2 = this.widget.verticalRun.dimension;
                        this.dimension.targets.add(targetDimension2);
                        targetDimension2.dependencies.add(this.dimension);
                        this.widget.verticalRun.start.dependencies.add(this.dimension);
                        this.widget.verticalRun.end.dependencies.add(this.dimension);
                        this.dimension.delegateToWidgetRun = true;
                        this.dimension.dependencies.add(this.start);
                        this.dimension.dependencies.add(this.end);
                        this.start.targets.add(this.dimension);
                        this.end.targets.add(this.dimension);
                        break;
                    }
            }
        }
        if (this.widget.mListAnchors[0].mTarget != null && this.widget.mListAnchors[1].mTarget != null) {
            if (this.widget.isInHorizontalChain()) {
                this.start.margin = this.widget.mListAnchors[0].getMargin();
                this.end.margin = -this.widget.mListAnchors[1].getMargin();
                return;
            }
            DependencyNode startTarget2 = getTarget(this.widget.mListAnchors[0]);
            DependencyNode endTarget2 = getTarget(this.widget.mListAnchors[1]);
            if (startTarget2 != null) {
                startTarget2.addDependency(this);
            }
            if (endTarget2 != null) {
                endTarget2.addDependency(this);
            }
            this.mRunType = WidgetRun.RunType.CENTER;
        } else if (this.widget.mListAnchors[0].mTarget != null) {
            DependencyNode target3 = getTarget(this.widget.mListAnchors[0]);
            if (target3 != null) {
                addTarget(this.start, target3, this.widget.mListAnchors[0].getMargin());
                addTarget(this.end, this.start, 1, this.dimension);
            }
        } else if (this.widget.mListAnchors[1].mTarget != null) {
            DependencyNode target4 = getTarget(this.widget.mListAnchors[1]);
            if (target4 != null) {
                addTarget(this.end, target4, -this.widget.mListAnchors[1].getMargin());
                addTarget(this.start, this.end, -1, this.dimension);
            }
        } else if (!(this.widget instanceof Helper) && this.widget.getParent() != null) {
            DependencyNode left2 = this.widget.getParent().horizontalRun.start;
            addTarget(this.start, left2, this.widget.getX());
            addTarget(this.end, this.start, 1, this.dimension);
        }
    }

    private void computeInsetRatio(int[] dimensions, int x1, int x2, int y1, int y2, float ratio, int side) {
        int dx = x2 - x1;
        int dy = y2 - y1;
        switch (side) {
            case -1:
                int candidateX1 = (int) ((dy * ratio) + 0.5f);
                int candidateY2 = (int) ((dx / ratio) + 0.5f);
                if (candidateX1 <= dx && dy <= dy) {
                    dimensions[0] = candidateX1;
                    dimensions[1] = dy;
                    return;
                } else if (dx <= dx && candidateY2 <= dy) {
                    dimensions[0] = dx;
                    dimensions[1] = candidateY2;
                    return;
                } else {
                    return;
                }
            case 0:
                int horizontalSide = (int) ((dy * ratio) + 0.5f);
                dimensions[0] = horizontalSide;
                dimensions[1] = dy;
                return;
            case 1:
                int verticalSide = (int) ((dx * ratio) + 0.5f);
                dimensions[0] = dx;
                dimensions[1] = verticalSide;
                return;
            default:
                return;
        }
    }

    /* renamed from: androidx.constraintlayout.core.widgets.analyzer.HorizontalWidgetRun$1  reason: invalid class name */
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
                updateRunCenter(dependency, this.widget.mLeft, this.widget.mRight, 0);
                return;
        }
        if (!this.dimension.resolved && this.dimensionBehavior == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT) {
            switch (this.widget.mMatchConstraintDefaultWidth) {
                case 2:
                    ConstraintWidget parent = this.widget.getParent();
                    if (parent != null && parent.horizontalRun.dimension.resolved) {
                        float percent = this.widget.mMatchConstraintPercentWidth;
                        int targetDimensionValue = parent.horizontalRun.dimension.value;
                        int size = (int) ((targetDimensionValue * percent) + 0.5f);
                        this.dimension.resolve(size);
                        break;
                    }
                    break;
                case 3:
                    if (this.widget.mMatchConstraintDefaultHeight == 0 || this.widget.mMatchConstraintDefaultHeight == 3) {
                        DependencyNode secondStart = this.widget.verticalRun.start;
                        DependencyNode secondEnd = this.widget.verticalRun.end;
                        boolean s1 = this.widget.mLeft.mTarget != null;
                        boolean s2 = this.widget.mTop.mTarget != null;
                        boolean e1 = this.widget.mRight.mTarget != null;
                        boolean e2 = this.widget.mBottom.mTarget != null;
                        int definedSide = this.widget.getDimensionRatioSide();
                        if (s1 && s2 && e1 && e2) {
                            float ratio = this.widget.getDimensionRatio();
                            if (secondStart.resolved && secondEnd.resolved) {
                                if (!this.start.readyToSolve || !this.end.readyToSolve) {
                                    return;
                                }
                                computeInsetRatio(tempDimensions, this.start.targets.get(0).value + this.start.margin, this.end.targets.get(0).value - this.end.margin, secondStart.value + secondStart.margin, secondEnd.value - secondEnd.margin, ratio, definedSide);
                                this.dimension.resolve(tempDimensions[0]);
                                this.widget.verticalRun.dimension.resolve(tempDimensions[1]);
                                return;
                            }
                            if (this.start.resolved && this.end.resolved) {
                                if (!secondStart.readyToSolve || !secondEnd.readyToSolve) {
                                    return;
                                }
                                computeInsetRatio(tempDimensions, this.start.value + this.start.margin, this.end.value - this.end.margin, secondStart.targets.get(0).value + secondStart.margin, secondEnd.targets.get(0).value - secondEnd.margin, ratio, definedSide);
                                this.dimension.resolve(tempDimensions[0]);
                                this.widget.verticalRun.dimension.resolve(tempDimensions[1]);
                            }
                            if (!this.start.readyToSolve || !this.end.readyToSolve || !secondStart.readyToSolve || !secondEnd.readyToSolve) {
                                return;
                            }
                            computeInsetRatio(tempDimensions, this.start.targets.get(0).value + this.start.margin, this.end.targets.get(0).value - this.end.margin, secondStart.targets.get(0).value + secondStart.margin, secondEnd.targets.get(0).value - secondEnd.margin, ratio, definedSide);
                            this.dimension.resolve(tempDimensions[0]);
                            this.widget.verticalRun.dimension.resolve(tempDimensions[1]);
                            break;
                        } else if (s1 && e1) {
                            if (!this.start.readyToSolve || !this.end.readyToSolve) {
                                return;
                            }
                            float ratio2 = this.widget.getDimensionRatio();
                            int x1 = this.start.targets.get(0).value + this.start.margin;
                            int x2 = this.end.targets.get(0).value - this.end.margin;
                            switch (definedSide) {
                                case -1:
                                case 0:
                                    int ldx = getLimitedDimension(x2 - x1, 0);
                                    int dy = (int) ((ldx * ratio2) + 0.5f);
                                    int ldy = getLimitedDimension(dy, 1);
                                    if (dy != ldy) {
                                        ldx = (int) ((ldy / ratio2) + 0.5f);
                                    }
                                    this.dimension.resolve(ldx);
                                    this.widget.verticalRun.dimension.resolve(ldy);
                                    break;
                                case 1:
                                    int ldx2 = getLimitedDimension(x2 - x1, 0);
                                    int dy2 = (int) ((ldx2 / ratio2) + 0.5f);
                                    int ldy2 = getLimitedDimension(dy2, 1);
                                    if (dy2 != ldy2) {
                                        ldx2 = (int) ((ldy2 * ratio2) + 0.5f);
                                    }
                                    this.dimension.resolve(ldx2);
                                    this.widget.verticalRun.dimension.resolve(ldy2);
                                    break;
                            }
                        } else if (s2 && e2) {
                            if (!secondStart.readyToSolve || !secondEnd.readyToSolve) {
                                return;
                            }
                            float ratio3 = this.widget.getDimensionRatio();
                            int y1 = secondStart.targets.get(0).value + secondStart.margin;
                            int y2 = secondEnd.targets.get(0).value - secondEnd.margin;
                            switch (definedSide) {
                                case -1:
                                case 1:
                                    int dy3 = y2 - y1;
                                    int ldy3 = getLimitedDimension(dy3, 1);
                                    int dx = (int) ((ldy3 / ratio3) + 0.5f);
                                    int ldx3 = getLimitedDimension(dx, 0);
                                    if (dx != ldx3) {
                                        ldy3 = (int) ((ldx3 * ratio3) + 0.5f);
                                    }
                                    this.dimension.resolve(ldx3);
                                    this.widget.verticalRun.dimension.resolve(ldy3);
                                    break;
                                case 0:
                                    int dy4 = y2 - y1;
                                    int ldy4 = getLimitedDimension(dy4, 1);
                                    int dx2 = (int) ((ldy4 * ratio3) + 0.5f);
                                    int ldx4 = getLimitedDimension(dx2, 0);
                                    if (dx2 != ldx4) {
                                        ldy4 = (int) ((ldx4 / ratio3) + 0.5f);
                                    }
                                    this.dimension.resolve(ldx4);
                                    this.widget.verticalRun.dimension.resolve(ldy4);
                                    break;
                            }
                        }
                    } else {
                        int size2 = 0;
                        int ratioSide = this.widget.getDimensionRatioSide();
                        switch (ratioSide) {
                            case -1:
                                size2 = (int) ((this.widget.verticalRun.dimension.value * this.widget.getDimensionRatio()) + 0.5f);
                                break;
                            case 0:
                                size2 = (int) ((this.widget.verticalRun.dimension.value / this.widget.getDimensionRatio()) + 0.5f);
                                break;
                            case 1:
                                size2 = (int) ((this.widget.verticalRun.dimension.value * this.widget.getDimensionRatio()) + 0.5f);
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
        if (!this.dimension.resolved && this.dimensionBehavior == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT && this.widget.mMatchConstraintDefaultWidth == 0 && !this.widget.isInHorizontalChain()) {
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
            int value = Math.min(availableSpace, this.dimension.wrapValue);
            int max = this.widget.mMatchConstraintMaxWidth;
            int min = this.widget.mMatchConstraintMinWidth;
            int value2 = Math.max(min, value);
            if (max > 0) {
                value2 = Math.min(max, value2);
            }
            this.dimension.resolve(value2);
        }
        if (!this.dimension.resolved) {
            return;
        }
        DependencyNode startTarget = this.start.targets.get(0);
        DependencyNode endTarget = this.end.targets.get(0);
        int startPos3 = startTarget.value + this.start.margin;
        int endPos3 = endTarget.value + this.end.margin;
        float bias = this.widget.getHorizontalBiasPercent();
        if (startTarget == endTarget) {
            startPos3 = startTarget.value;
            endPos3 = endTarget.value;
            bias = 0.5f;
        }
        int distance2 = (endPos3 - startPos3) - this.dimension.value;
        this.start.resolve((int) (startPos3 + 0.5f + (distance2 * bias)));
        this.end.resolve(this.start.value + this.dimension.value);
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.WidgetRun
    public void applyToWidget() {
        if (this.start.resolved) {
            this.widget.setX(this.start.value);
        }
    }
}
