package androidx.constraintlayout.core.widgets.analyzer;

import androidx.constraintlayout.core.widgets.Barrier;
import androidx.constraintlayout.core.widgets.ConstraintWidget;
import androidx.constraintlayout.core.widgets.analyzer.DependencyNode;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class HelperReferences extends WidgetRun {
    public HelperReferences(ConstraintWidget widget) {
        super(widget);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // androidx.constraintlayout.core.widgets.analyzer.WidgetRun
    public void clear() {
        this.runGroup = null;
        this.start.clear();
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.WidgetRun
    void reset() {
        this.start.resolved = false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // androidx.constraintlayout.core.widgets.analyzer.WidgetRun
    public boolean supportsWrapComputation() {
        return false;
    }

    private void addDependency(DependencyNode node) {
        this.start.dependencies.add(node);
        node.targets.add(this.start);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // androidx.constraintlayout.core.widgets.analyzer.WidgetRun
    public void apply() {
        if (this.widget instanceof Barrier) {
            this.start.delegateToWidgetRun = true;
            Barrier barrier = (Barrier) this.widget;
            int type = barrier.getBarrierType();
            boolean allowsGoneWidget = barrier.getAllowsGoneWidget();
            switch (type) {
                case 0:
                    this.start.type = DependencyNode.Type.LEFT;
                    for (int i = 0; i < barrier.mWidgetsCount; i++) {
                        ConstraintWidget refWidget = barrier.mWidgets[i];
                        if (allowsGoneWidget || refWidget.getVisibility() != 8) {
                            DependencyNode target = refWidget.horizontalRun.start;
                            target.dependencies.add(this.start);
                            this.start.targets.add(target);
                        }
                    }
                    addDependency(this.widget.horizontalRun.start);
                    addDependency(this.widget.horizontalRun.end);
                    return;
                case 1:
                    this.start.type = DependencyNode.Type.RIGHT;
                    for (int i2 = 0; i2 < barrier.mWidgetsCount; i2++) {
                        ConstraintWidget refWidget2 = barrier.mWidgets[i2];
                        if (allowsGoneWidget || refWidget2.getVisibility() != 8) {
                            DependencyNode target2 = refWidget2.horizontalRun.end;
                            target2.dependencies.add(this.start);
                            this.start.targets.add(target2);
                        }
                    }
                    addDependency(this.widget.horizontalRun.start);
                    addDependency(this.widget.horizontalRun.end);
                    return;
                case 2:
                    this.start.type = DependencyNode.Type.TOP;
                    for (int i3 = 0; i3 < barrier.mWidgetsCount; i3++) {
                        ConstraintWidget refwidget = barrier.mWidgets[i3];
                        if (allowsGoneWidget || refwidget.getVisibility() != 8) {
                            DependencyNode target3 = refwidget.verticalRun.start;
                            target3.dependencies.add(this.start);
                            this.start.targets.add(target3);
                        }
                    }
                    addDependency(this.widget.verticalRun.start);
                    addDependency(this.widget.verticalRun.end);
                    return;
                case 3:
                    this.start.type = DependencyNode.Type.BOTTOM;
                    for (int i4 = 0; i4 < barrier.mWidgetsCount; i4++) {
                        ConstraintWidget refwidget2 = barrier.mWidgets[i4];
                        if (allowsGoneWidget || refwidget2.getVisibility() != 8) {
                            DependencyNode target4 = refwidget2.verticalRun.end;
                            target4.dependencies.add(this.start);
                            this.start.targets.add(target4);
                        }
                    }
                    addDependency(this.widget.verticalRun.start);
                    addDependency(this.widget.verticalRun.end);
                    return;
                default:
                    return;
            }
        }
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.WidgetRun, androidx.constraintlayout.core.widgets.analyzer.Dependency
    public void update(Dependency dependency) {
        Barrier barrier = (Barrier) this.widget;
        int type = barrier.getBarrierType();
        int min = -1;
        int max = 0;
        for (DependencyNode node : this.start.targets) {
            int value = node.value;
            if (min == -1 || value < min) {
                min = value;
            }
            if (max < value) {
                max = value;
            }
        }
        if (type == 0 || type == 2) {
            this.start.resolve(barrier.getMargin() + min);
        } else {
            this.start.resolve(barrier.getMargin() + max);
        }
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.WidgetRun
    public void applyToWidget() {
        if (this.widget instanceof Barrier) {
            Barrier barrier = (Barrier) this.widget;
            int type = barrier.getBarrierType();
            if (type == 0 || type == 1) {
                this.widget.setX(this.start.value);
            } else {
                this.widget.setY(this.start.value);
            }
        }
    }
}
