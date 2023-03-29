package androidx.constraintlayout.core.widgets.analyzer;

import androidx.constraintlayout.core.LinearSystem;
import androidx.constraintlayout.core.widgets.Chain;
import androidx.constraintlayout.core.widgets.ConstraintWidget;
import androidx.constraintlayout.core.widgets.ConstraintWidgetContainer;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;
/* loaded from: classes.dex */
public class WidgetGroup {
    private static final boolean DEBUG = false;
    static int count = 0;
    int id;
    int orientation;
    ArrayList<ConstraintWidget> widgets = new ArrayList<>();
    boolean authoritative = false;
    ArrayList<MeasureResult> results = null;
    private int moveTo = -1;

    public WidgetGroup(int orientation) {
        this.id = -1;
        this.orientation = 0;
        int i = count;
        count = i + 1;
        this.id = i;
        this.orientation = orientation;
    }

    public int getOrientation() {
        return this.orientation;
    }

    public int getId() {
        return this.id;
    }

    public boolean add(ConstraintWidget widget) {
        if (this.widgets.contains(widget)) {
            return false;
        }
        this.widgets.add(widget);
        return true;
    }

    public void setAuthoritative(boolean isAuthoritative) {
        this.authoritative = isAuthoritative;
    }

    public boolean isAuthoritative() {
        return this.authoritative;
    }

    private String getOrientationString() {
        int i = this.orientation;
        if (i == 0) {
            return "Horizontal";
        }
        if (i == 1) {
            return "Vertical";
        }
        if (i == 2) {
            return "Both";
        }
        return "Unknown";
    }

    public String toString() {
        String ret = getOrientationString() + " [" + this.id + "] <";
        Iterator<ConstraintWidget> it = this.widgets.iterator();
        while (it.hasNext()) {
            ConstraintWidget widget = it.next();
            ret = ret + " " + widget.getDebugName();
        }
        return ret + " >";
    }

    public void moveTo(int orientation, WidgetGroup widgetGroup) {
        Iterator<ConstraintWidget> it = this.widgets.iterator();
        while (it.hasNext()) {
            ConstraintWidget widget = it.next();
            widgetGroup.add(widget);
            if (orientation == 0) {
                widget.horizontalGroup = widgetGroup.getId();
            } else {
                widget.verticalGroup = widgetGroup.getId();
            }
        }
        this.moveTo = widgetGroup.id;
    }

    public void clear() {
        this.widgets.clear();
    }

    private int measureWrap(int orientation, ConstraintWidget widget) {
        ConstraintWidget.DimensionBehaviour behaviour = widget.getDimensionBehaviour(orientation);
        if (behaviour == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT || behaviour == ConstraintWidget.DimensionBehaviour.MATCH_PARENT || behaviour == ConstraintWidget.DimensionBehaviour.FIXED) {
            if (orientation == 0) {
                int dimension = widget.getWidth();
                return dimension;
            }
            int dimension2 = widget.getHeight();
            return dimension2;
        }
        return -1;
    }

    public int measureWrap(LinearSystem system, int orientation) {
        int count2 = this.widgets.size();
        if (count2 == 0) {
            return 0;
        }
        return solverMeasure(system, this.widgets, orientation);
    }

    private int solverMeasure(LinearSystem system, ArrayList<ConstraintWidget> widgets, int orientation) {
        ConstraintWidgetContainer container = (ConstraintWidgetContainer) widgets.get(0).getParent();
        system.reset();
        container.addToSolver(system, false);
        for (int i = 0; i < widgets.size(); i++) {
            ConstraintWidget widget = widgets.get(i);
            widget.addToSolver(system, false);
        }
        if (orientation == 0 && container.mHorizontalChainsSize > 0) {
            Chain.applyChainConstraints(container, system, widgets, 0);
        }
        if (orientation == 1 && container.mVerticalChainsSize > 0) {
            Chain.applyChainConstraints(container, system, widgets, 1);
        }
        try {
            system.minimize();
        } catch (Exception e) {
            e.printStackTrace();
        }
        this.results = new ArrayList<>();
        for (int i2 = 0; i2 < widgets.size(); i2++) {
            ConstraintWidget widget2 = widgets.get(i2);
            MeasureResult result = new MeasureResult(widget2, system, orientation);
            this.results.add(result);
        }
        if (orientation == 0) {
            int left = system.getObjectVariableValue(container.mLeft);
            int right = system.getObjectVariableValue(container.mRight);
            system.reset();
            return right - left;
        }
        int top = system.getObjectVariableValue(container.mTop);
        int bottom = system.getObjectVariableValue(container.mBottom);
        system.reset();
        return bottom - top;
    }

    public void setOrientation(int orientation) {
        this.orientation = orientation;
    }

    public void apply() {
        if (this.results == null || !this.authoritative) {
            return;
        }
        for (int i = 0; i < this.results.size(); i++) {
            MeasureResult result = this.results.get(i);
            result.apply();
        }
    }

    public boolean intersectWith(WidgetGroup group) {
        for (int i = 0; i < this.widgets.size(); i++) {
            ConstraintWidget widget = this.widgets.get(i);
            if (group.contains(widget)) {
                return true;
            }
        }
        return false;
    }

    private boolean contains(ConstraintWidget widget) {
        return this.widgets.contains(widget);
    }

    public int size() {
        return this.widgets.size();
    }

    public void cleanup(ArrayList<WidgetGroup> dependencyLists) {
        int count2 = this.widgets.size();
        if (this.moveTo != -1 && count2 > 0) {
            for (int i = 0; i < dependencyLists.size(); i++) {
                WidgetGroup group = dependencyLists.get(i);
                if (this.moveTo == group.id) {
                    moveTo(this.orientation, group);
                }
            }
        }
        if (count2 == 0) {
            dependencyLists.remove(this);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public class MeasureResult {
        int baseline;
        int bottom;
        int left;
        int orientation;
        int right;
        int top;
        WeakReference<ConstraintWidget> widgetRef;

        public MeasureResult(ConstraintWidget widget, LinearSystem system, int orientation) {
            this.widgetRef = new WeakReference<>(widget);
            this.left = system.getObjectVariableValue(widget.mLeft);
            this.top = system.getObjectVariableValue(widget.mTop);
            this.right = system.getObjectVariableValue(widget.mRight);
            this.bottom = system.getObjectVariableValue(widget.mBottom);
            this.baseline = system.getObjectVariableValue(widget.mBaseline);
            this.orientation = orientation;
        }

        public void apply() {
            ConstraintWidget widget = this.widgetRef.get();
            if (widget != null) {
                widget.setFinalFrame(this.left, this.top, this.right, this.bottom, this.baseline, this.orientation);
            }
        }
    }
}
