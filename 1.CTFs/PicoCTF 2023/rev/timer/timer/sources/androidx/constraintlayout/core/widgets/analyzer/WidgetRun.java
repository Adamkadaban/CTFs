package androidx.constraintlayout.core.widgets.analyzer;

import androidx.constraintlayout.core.widgets.ConstraintAnchor;
import androidx.constraintlayout.core.widgets.ConstraintWidget;
/* loaded from: classes.dex */
public abstract class WidgetRun implements Dependency {
    protected ConstraintWidget.DimensionBehaviour dimensionBehavior;
    public int matchConstraintsType;
    RunGroup runGroup;
    ConstraintWidget widget;
    DimensionDependency dimension = new DimensionDependency(this);
    public int orientation = 0;
    boolean resolved = false;
    public DependencyNode start = new DependencyNode(this);
    public DependencyNode end = new DependencyNode(this);
    protected RunType mRunType = RunType.NONE;

    /* loaded from: classes.dex */
    enum RunType {
        NONE,
        START,
        END,
        CENTER
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract void apply();

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract void applyToWidget();

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract void clear();

    abstract void reset();

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract boolean supportsWrapComputation();

    public WidgetRun(ConstraintWidget widget) {
        this.widget = widget;
    }

    public boolean isDimensionResolved() {
        return this.dimension.resolved;
    }

    public boolean isCenterConnection() {
        int connections = 0;
        int count = this.start.targets.size();
        for (int i = 0; i < count; i++) {
            DependencyNode dependency = this.start.targets.get(i);
            if (dependency.run != this) {
                connections++;
            }
        }
        int count2 = this.end.targets.size();
        for (int i2 = 0; i2 < count2; i2++) {
            DependencyNode dependency2 = this.end.targets.get(i2);
            if (dependency2.run != this) {
                connections++;
            }
        }
        return connections >= 2;
    }

    public long wrapSize(int direction) {
        if (this.dimension.resolved) {
            long size = this.dimension.value;
            if (isCenterConnection()) {
                return size + (this.start.margin - this.end.margin);
            }
            if (direction == 0) {
                return size + this.start.margin;
            }
            return size - this.end.margin;
        }
        return 0L;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final DependencyNode getTarget(ConstraintAnchor anchor) {
        if (anchor.mTarget == null) {
            return null;
        }
        ConstraintWidget targetWidget = anchor.mTarget.mOwner;
        ConstraintAnchor.Type targetType = anchor.mTarget.mType;
        switch (AnonymousClass1.$SwitchMap$androidx$constraintlayout$core$widgets$ConstraintAnchor$Type[targetType.ordinal()]) {
            case 1:
                HorizontalWidgetRun run = targetWidget.horizontalRun;
                DependencyNode target = run.start;
                return target;
            case 2:
                HorizontalWidgetRun run2 = targetWidget.horizontalRun;
                DependencyNode target2 = run2.end;
                return target2;
            case 3:
                VerticalWidgetRun run3 = targetWidget.verticalRun;
                DependencyNode target3 = run3.start;
                return target3;
            case 4:
                VerticalWidgetRun run4 = targetWidget.verticalRun;
                DependencyNode target4 = run4.baseline;
                return target4;
            case 5:
                VerticalWidgetRun run5 = targetWidget.verticalRun;
                DependencyNode target5 = run5.end;
                return target5;
            default:
                return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: androidx.constraintlayout.core.widgets.analyzer.WidgetRun$1  reason: invalid class name */
    /* loaded from: classes.dex */
    public static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$androidx$constraintlayout$core$widgets$ConstraintAnchor$Type;

        static {
            int[] iArr = new int[ConstraintAnchor.Type.values().length];
            $SwitchMap$androidx$constraintlayout$core$widgets$ConstraintAnchor$Type = iArr;
            try {
                iArr[ConstraintAnchor.Type.LEFT.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$androidx$constraintlayout$core$widgets$ConstraintAnchor$Type[ConstraintAnchor.Type.RIGHT.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$androidx$constraintlayout$core$widgets$ConstraintAnchor$Type[ConstraintAnchor.Type.TOP.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$androidx$constraintlayout$core$widgets$ConstraintAnchor$Type[ConstraintAnchor.Type.BASELINE.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
            try {
                $SwitchMap$androidx$constraintlayout$core$widgets$ConstraintAnchor$Type[ConstraintAnchor.Type.BOTTOM.ordinal()] = 5;
            } catch (NoSuchFieldError e5) {
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void updateRunCenter(Dependency dependency, ConstraintAnchor startAnchor, ConstraintAnchor endAnchor, int orientation) {
        DependencyNode startTarget = getTarget(startAnchor);
        DependencyNode endTarget = getTarget(endAnchor);
        if (!startTarget.resolved || !endTarget.resolved) {
            return;
        }
        int startPos = startTarget.value + startAnchor.getMargin();
        int endPos = endTarget.value - endAnchor.getMargin();
        int distance = endPos - startPos;
        if (!this.dimension.resolved && this.dimensionBehavior == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT) {
            resolveDimension(orientation, distance);
        }
        if (!this.dimension.resolved) {
            return;
        }
        if (this.dimension.value == distance) {
            this.start.resolve(startPos);
            this.end.resolve(endPos);
            return;
        }
        ConstraintWidget constraintWidget = this.widget;
        float bias = orientation == 0 ? constraintWidget.getHorizontalBiasPercent() : constraintWidget.getVerticalBiasPercent();
        if (startTarget == endTarget) {
            startPos = startTarget.value;
            endPos = endTarget.value;
            bias = 0.5f;
        }
        int availableDistance = (endPos - startPos) - this.dimension.value;
        this.start.resolve((int) (startPos + 0.5f + (availableDistance * bias)));
        this.end.resolve(this.start.value + this.dimension.value);
    }

    private void resolveDimension(int orientation, int distance) {
        int value;
        switch (this.matchConstraintsType) {
            case 0:
                this.dimension.resolve(getLimitedDimension(distance, orientation));
                return;
            case 1:
                int wrapValue = getLimitedDimension(this.dimension.wrapValue, orientation);
                this.dimension.resolve(Math.min(wrapValue, distance));
                return;
            case 2:
                ConstraintWidget parent = this.widget.getParent();
                if (parent != null) {
                    WidgetRun run = orientation == 0 ? parent.horizontalRun : parent.verticalRun;
                    if (run.dimension.resolved) {
                        ConstraintWidget constraintWidget = this.widget;
                        float percent = orientation == 0 ? constraintWidget.mMatchConstraintPercentWidth : constraintWidget.mMatchConstraintPercentHeight;
                        int targetDimensionValue = run.dimension.value;
                        int size = (int) ((targetDimensionValue * percent) + 0.5f);
                        this.dimension.resolve(getLimitedDimension(size, orientation));
                        return;
                    }
                    return;
                }
                return;
            case 3:
                if (this.widget.horizontalRun.dimensionBehavior != ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT || this.widget.horizontalRun.matchConstraintsType != 3 || this.widget.verticalRun.dimensionBehavior != ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT || this.widget.verticalRun.matchConstraintsType != 3) {
                    ConstraintWidget constraintWidget2 = this.widget;
                    WidgetRun run2 = orientation == 0 ? constraintWidget2.verticalRun : constraintWidget2.horizontalRun;
                    if (run2.dimension.resolved) {
                        float ratio = this.widget.getDimensionRatio();
                        if (orientation == 1) {
                            value = (int) ((run2.dimension.value / ratio) + 0.5f);
                        } else {
                            value = (int) ((run2.dimension.value * ratio) + 0.5f);
                        }
                        this.dimension.resolve(value);
                        return;
                    }
                    return;
                }
                return;
            default:
                return;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void updateRunStart(Dependency dependency) {
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void updateRunEnd(Dependency dependency) {
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.Dependency
    public void update(Dependency dependency) {
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final int getLimitedDimension(int dimension, int orientation) {
        if (orientation == 0) {
            int max = this.widget.mMatchConstraintMaxWidth;
            int min = this.widget.mMatchConstraintMinWidth;
            int value = Math.max(min, dimension);
            if (max > 0) {
                value = Math.min(max, dimension);
            }
            if (value != dimension) {
                return value;
            }
            return dimension;
        }
        int max2 = this.widget.mMatchConstraintMaxHeight;
        int min2 = this.widget.mMatchConstraintMinHeight;
        int value2 = Math.max(min2, dimension);
        if (max2 > 0) {
            value2 = Math.min(max2, dimension);
        }
        if (value2 != dimension) {
            return value2;
        }
        return dimension;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final DependencyNode getTarget(ConstraintAnchor anchor, int orientation) {
        if (anchor.mTarget == null) {
            return null;
        }
        ConstraintWidget targetWidget = anchor.mTarget.mOwner;
        WidgetRun run = orientation == 0 ? targetWidget.horizontalRun : targetWidget.verticalRun;
        ConstraintAnchor.Type targetType = anchor.mTarget.mType;
        switch (AnonymousClass1.$SwitchMap$androidx$constraintlayout$core$widgets$ConstraintAnchor$Type[targetType.ordinal()]) {
            case 1:
            case 3:
                DependencyNode target = run.start;
                return target;
            case 2:
            case 5:
                DependencyNode target2 = run.end;
                return target2;
            case 4:
            default:
                return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final void addTarget(DependencyNode node, DependencyNode target, int margin) {
        node.targets.add(target);
        node.margin = margin;
        target.dependencies.add(node);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final void addTarget(DependencyNode node, DependencyNode target, int marginFactor, DimensionDependency dimensionDependency) {
        node.targets.add(target);
        node.targets.add(this.dimension);
        node.marginFactor = marginFactor;
        node.marginDependency = dimensionDependency;
        target.dependencies.add(node);
        dimensionDependency.dependencies.add(node);
    }

    public long getWrapDimension() {
        if (this.dimension.resolved) {
            return this.dimension.value;
        }
        return 0L;
    }

    public boolean isResolved() {
        return this.resolved;
    }
}
