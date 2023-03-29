package androidx.constraintlayout.core.widgets.analyzer;

import java.util.ArrayList;
import java.util.List;
/* loaded from: classes.dex */
public class DependencyNode implements Dependency {
    int margin;
    WidgetRun run;
    public int value;
    public Dependency updateDelegate = null;
    public boolean delegateToWidgetRun = false;
    public boolean readyToSolve = false;
    Type type = Type.UNKNOWN;
    int marginFactor = 1;
    DimensionDependency marginDependency = null;
    public boolean resolved = false;
    List<Dependency> dependencies = new ArrayList();
    List<DependencyNode> targets = new ArrayList();

    /* loaded from: classes.dex */
    enum Type {
        UNKNOWN,
        HORIZONTAL_DIMENSION,
        VERTICAL_DIMENSION,
        LEFT,
        RIGHT,
        TOP,
        BOTTOM,
        BASELINE
    }

    public DependencyNode(WidgetRun run) {
        this.run = run;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.run.widget.getDebugName());
        sb.append(":");
        sb.append(this.type);
        sb.append("(");
        sb.append(this.resolved ? Integer.valueOf(this.value) : "unresolved");
        sb.append(") <t=");
        sb.append(this.targets.size());
        sb.append(":d=");
        sb.append(this.dependencies.size());
        sb.append(">");
        return sb.toString();
    }

    public void resolve(int value) {
        if (this.resolved) {
            return;
        }
        this.resolved = true;
        this.value = value;
        for (Dependency node : this.dependencies) {
            node.update(node);
        }
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.Dependency
    public void update(Dependency node) {
        for (DependencyNode target : this.targets) {
            if (!target.resolved) {
                return;
            }
        }
        this.readyToSolve = true;
        Dependency dependency = this.updateDelegate;
        if (dependency != null) {
            dependency.update(this);
        }
        if (this.delegateToWidgetRun) {
            this.run.update(this);
            return;
        }
        DependencyNode target2 = null;
        int numTargets = 0;
        for (DependencyNode t : this.targets) {
            if (!(t instanceof DimensionDependency)) {
                target2 = t;
                numTargets++;
            }
        }
        if (target2 != null && numTargets == 1 && target2.resolved) {
            DimensionDependency dimensionDependency = this.marginDependency;
            if (dimensionDependency != null) {
                if (dimensionDependency.resolved) {
                    this.margin = this.marginFactor * this.marginDependency.value;
                } else {
                    return;
                }
            }
            resolve(target2.value + this.margin);
        }
        Dependency dependency2 = this.updateDelegate;
        if (dependency2 != null) {
            dependency2.update(this);
        }
    }

    public void addDependency(Dependency dependency) {
        this.dependencies.add(dependency);
        if (this.resolved) {
            dependency.update(dependency);
        }
    }

    public String name() {
        String definition;
        String definition2 = this.run.widget.getDebugName();
        if (this.type == Type.LEFT || this.type == Type.RIGHT) {
            definition = definition2 + "_HORIZONTAL";
        } else {
            definition = definition2 + "_VERTICAL";
        }
        return definition + ":" + this.type.name();
    }

    public void clear() {
        this.targets.clear();
        this.dependencies.clear();
        this.resolved = false;
        this.value = 0;
        this.readyToSolve = false;
        this.delegateToWidgetRun = false;
    }
}
