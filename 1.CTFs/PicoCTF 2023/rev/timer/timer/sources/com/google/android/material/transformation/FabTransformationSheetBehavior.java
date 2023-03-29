package com.google.android.material.transformation;

import android.content.Context;
import android.os.Build;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewParent;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.view.ViewCompat;
import com.google.android.material.R;
import com.google.android.material.animation.MotionSpec;
import com.google.android.material.animation.Positioning;
import com.google.android.material.transformation.FabTransformationBehavior;
import java.util.HashMap;
import java.util.Map;
@Deprecated
/* loaded from: classes.dex */
public class FabTransformationSheetBehavior extends FabTransformationBehavior {
    private Map<View, Integer> importantForAccessibilityMap;

    public FabTransformationSheetBehavior() {
    }

    public FabTransformationSheetBehavior(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    @Override // com.google.android.material.transformation.FabTransformationBehavior
    protected FabTransformationBehavior.FabTransformationSpec onCreateMotionSpec(Context context, boolean expanded) {
        int specRes;
        if (expanded) {
            specRes = R.animator.mtrl_fab_transformation_sheet_expand_spec;
        } else {
            specRes = R.animator.mtrl_fab_transformation_sheet_collapse_spec;
        }
        FabTransformationBehavior.FabTransformationSpec spec = new FabTransformationBehavior.FabTransformationSpec();
        spec.timings = MotionSpec.createFromResource(context, specRes);
        spec.positioning = new Positioning(17, 0.0f, 0.0f);
        return spec;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.material.transformation.ExpandableTransformationBehavior, com.google.android.material.transformation.ExpandableBehavior
    public boolean onExpandedStateChange(View dependency, View child, boolean expanded, boolean animated) {
        updateImportantForAccessibility(child, expanded);
        return super.onExpandedStateChange(dependency, child, expanded, animated);
    }

    private void updateImportantForAccessibility(View sheet, boolean expanded) {
        ViewParent viewParent = sheet.getParent();
        if (!(viewParent instanceof CoordinatorLayout)) {
            return;
        }
        CoordinatorLayout parent = (CoordinatorLayout) viewParent;
        int childCount = parent.getChildCount();
        if (Build.VERSION.SDK_INT >= 16 && expanded) {
            this.importantForAccessibilityMap = new HashMap(childCount);
        }
        for (int i = 0; i < childCount; i++) {
            View child = parent.getChildAt(i);
            boolean hasScrimBehavior = (child.getLayoutParams() instanceof CoordinatorLayout.LayoutParams) && (((CoordinatorLayout.LayoutParams) child.getLayoutParams()).getBehavior() instanceof FabTransformationScrimBehavior);
            if (child != sheet && !hasScrimBehavior) {
                if (!expanded) {
                    Map<View, Integer> map = this.importantForAccessibilityMap;
                    if (map != null && map.containsKey(child)) {
                        ViewCompat.setImportantForAccessibility(child, this.importantForAccessibilityMap.get(child).intValue());
                    }
                } else {
                    if (Build.VERSION.SDK_INT >= 16) {
                        this.importantForAccessibilityMap.put(child, Integer.valueOf(child.getImportantForAccessibility()));
                    }
                    ViewCompat.setImportantForAccessibility(child, 4);
                }
            }
        }
        if (!expanded) {
            this.importantForAccessibilityMap = null;
        }
    }
}
