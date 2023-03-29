package androidx.constraintlayout.core.widgets.analyzer;

import androidx.constraintlayout.core.widgets.Barrier;
import androidx.constraintlayout.core.widgets.ConstraintAnchor;
import androidx.constraintlayout.core.widgets.ConstraintWidget;
import androidx.constraintlayout.core.widgets.ConstraintWidgetContainer;
import androidx.constraintlayout.core.widgets.Flow;
import androidx.constraintlayout.core.widgets.Guideline;
import androidx.constraintlayout.core.widgets.HelperWidget;
import androidx.constraintlayout.core.widgets.analyzer.BasicMeasure;
import java.util.ArrayList;
import java.util.Iterator;
/* loaded from: classes.dex */
public class Grouping {
    private static final boolean DEBUG = false;
    private static final boolean DEBUG_GROUPING = false;

    public static boolean validInGroup(ConstraintWidget.DimensionBehaviour layoutHorizontal, ConstraintWidget.DimensionBehaviour layoutVertical, ConstraintWidget.DimensionBehaviour widgetHorizontal, ConstraintWidget.DimensionBehaviour widgetVertical) {
        boolean fixedHorizontal = widgetHorizontal == ConstraintWidget.DimensionBehaviour.FIXED || widgetHorizontal == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT || (widgetHorizontal == ConstraintWidget.DimensionBehaviour.MATCH_PARENT && layoutHorizontal != ConstraintWidget.DimensionBehaviour.WRAP_CONTENT);
        boolean fixedVertical = widgetVertical == ConstraintWidget.DimensionBehaviour.FIXED || widgetVertical == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT || (widgetVertical == ConstraintWidget.DimensionBehaviour.MATCH_PARENT && layoutVertical != ConstraintWidget.DimensionBehaviour.WRAP_CONTENT);
        return fixedHorizontal || fixedVertical;
    }

    public static boolean simpleSolvingPass(ConstraintWidgetContainer layout, BasicMeasure.Measurer measurer) {
        ArrayList<ConstraintWidget> children = layout.getChildren();
        int count = children.size();
        ArrayList<Guideline> verticalGuidelines = null;
        ArrayList<Guideline> horizontalGuidelines = null;
        ArrayList<HelperWidget> horizontalBarriers = null;
        ArrayList<HelperWidget> verticalBarriers = null;
        ArrayList<ConstraintWidget> isolatedHorizontalChildren = null;
        ArrayList<ConstraintWidget> isolatedVerticalChildren = null;
        for (int i = 0; i < count; i++) {
            ConstraintWidget child = children.get(i);
            if (!validInGroup(layout.getHorizontalDimensionBehaviour(), layout.getVerticalDimensionBehaviour(), child.getHorizontalDimensionBehaviour(), child.getVerticalDimensionBehaviour()) || (child instanceof Flow)) {
                return false;
            }
        }
        if (layout.mMetrics != null) {
            layout.mMetrics.grouping++;
        }
        for (int i2 = 0; i2 < count; i2++) {
            ConstraintWidget child2 = children.get(i2);
            if (!validInGroup(layout.getHorizontalDimensionBehaviour(), layout.getVerticalDimensionBehaviour(), child2.getHorizontalDimensionBehaviour(), child2.getVerticalDimensionBehaviour())) {
                ConstraintWidgetContainer.measure(0, child2, measurer, layout.mMeasure, BasicMeasure.Measure.SELF_DIMENSIONS);
            }
            if (child2 instanceof Guideline) {
                Guideline guideline = (Guideline) child2;
                if (guideline.getOrientation() == 0) {
                    if (horizontalGuidelines == null) {
                        horizontalGuidelines = new ArrayList<>();
                    }
                    horizontalGuidelines.add(guideline);
                }
                if (guideline.getOrientation() == 1) {
                    if (verticalGuidelines == null) {
                        verticalGuidelines = new ArrayList<>();
                    }
                    verticalGuidelines.add(guideline);
                }
            }
            if (child2 instanceof HelperWidget) {
                if (child2 instanceof Barrier) {
                    Barrier barrier = (Barrier) child2;
                    if (barrier.getOrientation() == 0) {
                        if (horizontalBarriers == null) {
                            horizontalBarriers = new ArrayList<>();
                        }
                        horizontalBarriers.add(barrier);
                    }
                    if (barrier.getOrientation() == 1) {
                        if (verticalBarriers == null) {
                            verticalBarriers = new ArrayList<>();
                        }
                        verticalBarriers.add(barrier);
                    }
                } else {
                    HelperWidget helper = (HelperWidget) child2;
                    if (horizontalBarriers == null) {
                        horizontalBarriers = new ArrayList<>();
                    }
                    horizontalBarriers.add(helper);
                    if (verticalBarriers == null) {
                        verticalBarriers = new ArrayList<>();
                    }
                    verticalBarriers.add(helper);
                }
            }
            if (child2.mLeft.mTarget == null && child2.mRight.mTarget == null && !(child2 instanceof Guideline) && !(child2 instanceof Barrier)) {
                if (isolatedHorizontalChildren == null) {
                    isolatedHorizontalChildren = new ArrayList<>();
                }
                isolatedHorizontalChildren.add(child2);
            }
            if (child2.mTop.mTarget == null && child2.mBottom.mTarget == null && child2.mBaseline.mTarget == null && !(child2 instanceof Guideline) && !(child2 instanceof Barrier)) {
                if (isolatedVerticalChildren == null) {
                    isolatedVerticalChildren = new ArrayList<>();
                }
                isolatedVerticalChildren.add(child2);
            }
        }
        ArrayList<WidgetGroup> allDependencyLists = new ArrayList<>();
        if (verticalGuidelines != null) {
            Iterator<Guideline> it = verticalGuidelines.iterator();
            while (it.hasNext()) {
                Guideline guideline2 = it.next();
                findDependents(guideline2, 0, allDependencyLists, null);
            }
        }
        if (horizontalBarriers != null) {
            Iterator<HelperWidget> it2 = horizontalBarriers.iterator();
            while (it2.hasNext()) {
                HelperWidget barrier2 = it2.next();
                ArrayList<Guideline> verticalGuidelines2 = verticalGuidelines;
                WidgetGroup group = findDependents(barrier2, 0, allDependencyLists, null);
                barrier2.addDependents(allDependencyLists, 0, group);
                group.cleanup(allDependencyLists);
                verticalGuidelines = verticalGuidelines2;
            }
        }
        ConstraintAnchor left = layout.getAnchor(ConstraintAnchor.Type.LEFT);
        if (left.getDependents() != null) {
            Iterator<ConstraintAnchor> it3 = left.getDependents().iterator();
            while (it3.hasNext()) {
                ConstraintAnchor first = it3.next();
                findDependents(first.mOwner, 0, allDependencyLists, null);
                left = left;
            }
        }
        ConstraintAnchor right = layout.getAnchor(ConstraintAnchor.Type.RIGHT);
        if (right.getDependents() != null) {
            Iterator<ConstraintAnchor> it4 = right.getDependents().iterator();
            while (it4.hasNext()) {
                ConstraintAnchor first2 = it4.next();
                findDependents(first2.mOwner, 0, allDependencyLists, null);
                right = right;
            }
        }
        ConstraintAnchor center = layout.getAnchor(ConstraintAnchor.Type.CENTER);
        if (center.getDependents() != null) {
            Iterator<ConstraintAnchor> it5 = center.getDependents().iterator();
            while (it5.hasNext()) {
                ConstraintAnchor first3 = it5.next();
                findDependents(first3.mOwner, 0, allDependencyLists, null);
                center = center;
            }
        }
        if (isolatedHorizontalChildren != null) {
            Iterator<ConstraintWidget> it6 = isolatedHorizontalChildren.iterator();
            while (it6.hasNext()) {
                ConstraintWidget widget = it6.next();
                findDependents(widget, 0, allDependencyLists, null);
            }
        }
        if (horizontalGuidelines != null) {
            Iterator<Guideline> it7 = horizontalGuidelines.iterator();
            while (it7.hasNext()) {
                Guideline guideline3 = it7.next();
                findDependents(guideline3, 1, allDependencyLists, null);
            }
        }
        if (verticalBarriers != null) {
            Iterator<HelperWidget> it8 = verticalBarriers.iterator();
            while (it8.hasNext()) {
                HelperWidget barrier3 = it8.next();
                WidgetGroup group2 = findDependents(barrier3, 1, allDependencyLists, null);
                barrier3.addDependents(allDependencyLists, 1, group2);
                group2.cleanup(allDependencyLists);
            }
        }
        ConstraintAnchor top = layout.getAnchor(ConstraintAnchor.Type.TOP);
        if (top.getDependents() != null) {
            Iterator<ConstraintAnchor> it9 = top.getDependents().iterator();
            while (it9.hasNext()) {
                ConstraintAnchor first4 = it9.next();
                findDependents(first4.mOwner, 1, allDependencyLists, null);
                horizontalGuidelines = horizontalGuidelines;
            }
        }
        ConstraintAnchor baseline = layout.getAnchor(ConstraintAnchor.Type.BASELINE);
        if (baseline.getDependents() != null) {
            Iterator<ConstraintAnchor> it10 = baseline.getDependents().iterator();
            while (it10.hasNext()) {
                ConstraintAnchor first5 = it10.next();
                findDependents(first5.mOwner, 1, allDependencyLists, null);
                baseline = baseline;
            }
        }
        ConstraintAnchor bottom = layout.getAnchor(ConstraintAnchor.Type.BOTTOM);
        if (bottom.getDependents() != null) {
            Iterator<ConstraintAnchor> it11 = bottom.getDependents().iterator();
            while (it11.hasNext()) {
                ConstraintAnchor first6 = it11.next();
                findDependents(first6.mOwner, 1, allDependencyLists, null);
                bottom = bottom;
            }
        }
        ConstraintAnchor center2 = layout.getAnchor(ConstraintAnchor.Type.CENTER);
        if (center2.getDependents() != null) {
            Iterator<ConstraintAnchor> it12 = center2.getDependents().iterator();
            while (it12.hasNext()) {
                ConstraintAnchor first7 = it12.next();
                findDependents(first7.mOwner, 1, allDependencyLists, null);
                center2 = center2;
            }
        }
        if (isolatedVerticalChildren != null) {
            Iterator<ConstraintWidget> it13 = isolatedVerticalChildren.iterator();
            while (it13.hasNext()) {
                ConstraintWidget widget2 = it13.next();
                findDependents(widget2, 1, allDependencyLists, null);
            }
        }
        for (int i3 = 0; i3 < count; i3++) {
            ConstraintWidget child3 = children.get(i3);
            if (child3.oppositeDimensionsTied()) {
                WidgetGroup horizontalGroup = findGroup(allDependencyLists, child3.horizontalGroup);
                WidgetGroup verticalGroup = findGroup(allDependencyLists, child3.verticalGroup);
                if (horizontalGroup != null && verticalGroup != null) {
                    horizontalGroup.moveTo(0, verticalGroup);
                    verticalGroup.setOrientation(2);
                    allDependencyLists.remove(horizontalGroup);
                }
            }
        }
        int i4 = allDependencyLists.size();
        if (i4 <= 1) {
            return false;
        }
        WidgetGroup horizontalPick = null;
        WidgetGroup verticalPick = null;
        if (layout.getHorizontalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT) {
            int maxWrap = 0;
            WidgetGroup picked = null;
            Iterator<WidgetGroup> it14 = allDependencyLists.iterator();
            while (it14.hasNext()) {
                WidgetGroup list = it14.next();
                ArrayList<ConstraintWidget> children2 = children;
                if (list.getOrientation() == 1) {
                    children = children2;
                } else {
                    list.setAuthoritative(false);
                    int wrap = list.measureWrap(layout.getSystem(), 0);
                    if (wrap > maxWrap) {
                        maxWrap = wrap;
                        picked = list;
                    }
                    children = children2;
                }
            }
            if (picked != null) {
                layout.setHorizontalDimensionBehaviour(ConstraintWidget.DimensionBehaviour.FIXED);
                layout.setWidth(maxWrap);
                picked.setAuthoritative(true);
                horizontalPick = picked;
            }
        }
        if (layout.getVerticalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT) {
            int maxWrap2 = 0;
            WidgetGroup picked2 = null;
            Iterator<WidgetGroup> it15 = allDependencyLists.iterator();
            while (it15.hasNext()) {
                WidgetGroup list2 = it15.next();
                if (list2.getOrientation() != 0) {
                    list2.setAuthoritative(false);
                    int wrap2 = list2.measureWrap(layout.getSystem(), 1);
                    if (wrap2 > maxWrap2) {
                        picked2 = list2;
                        maxWrap2 = wrap2;
                    }
                }
            }
            if (picked2 != null) {
                layout.setVerticalDimensionBehaviour(ConstraintWidget.DimensionBehaviour.FIXED);
                layout.setHeight(maxWrap2);
                picked2.setAuthoritative(true);
                verticalPick = picked2;
            }
        }
        return (horizontalPick == null && verticalPick == null) ? false : true;
    }

    private static WidgetGroup findGroup(ArrayList<WidgetGroup> horizontalDependencyLists, int groupId) {
        int count = horizontalDependencyLists.size();
        for (int i = 0; i < count; i++) {
            WidgetGroup group = horizontalDependencyLists.get(i);
            if (groupId == group.id) {
                return group;
            }
        }
        return null;
    }

    public static WidgetGroup findDependents(ConstraintWidget constraintWidget, int orientation, ArrayList<WidgetGroup> list, WidgetGroup group) {
        int groupId;
        if (orientation == 0) {
            groupId = constraintWidget.horizontalGroup;
        } else {
            groupId = constraintWidget.verticalGroup;
        }
        if (groupId != -1 && (group == null || groupId != group.id)) {
            int i = 0;
            while (true) {
                if (i >= list.size()) {
                    break;
                }
                WidgetGroup widgetGroup = list.get(i);
                if (widgetGroup.getId() != groupId) {
                    i++;
                } else {
                    if (group != null) {
                        group.moveTo(orientation, widgetGroup);
                        list.remove(group);
                    }
                    group = widgetGroup;
                }
            }
        } else if (groupId != -1) {
            return group;
        }
        if (group == null) {
            if (constraintWidget instanceof HelperWidget) {
                HelperWidget helper = (HelperWidget) constraintWidget;
                int groupId2 = helper.findGroupInDependents(orientation);
                if (groupId2 != -1) {
                    int i2 = 0;
                    while (true) {
                        if (i2 >= list.size()) {
                            break;
                        }
                        WidgetGroup widgetGroup2 = list.get(i2);
                        if (widgetGroup2.getId() != groupId2) {
                            i2++;
                        } else {
                            group = widgetGroup2;
                            break;
                        }
                    }
                }
            }
            if (group == null) {
                group = new WidgetGroup(orientation);
            }
            list.add(group);
        }
        if (group.add(constraintWidget)) {
            if (constraintWidget instanceof Guideline) {
                Guideline guideline = (Guideline) constraintWidget;
                guideline.getAnchor().findDependents(guideline.getOrientation() == 0 ? 1 : 0, list, group);
            }
            if (orientation == 0) {
                constraintWidget.horizontalGroup = group.getId();
                constraintWidget.mLeft.findDependents(orientation, list, group);
                constraintWidget.mRight.findDependents(orientation, list, group);
            } else {
                constraintWidget.verticalGroup = group.getId();
                constraintWidget.mTop.findDependents(orientation, list, group);
                constraintWidget.mBaseline.findDependents(orientation, list, group);
                constraintWidget.mBottom.findDependents(orientation, list, group);
            }
            constraintWidget.mCenter.findDependents(orientation, list, group);
        }
        return group;
    }
}
