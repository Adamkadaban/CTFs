package androidx.transition;

import android.view.View;
/* loaded from: classes.dex */
public abstract class VisibilityPropagation extends TransitionPropagation {
    private static final String PROPNAME_VISIBILITY = "android:visibilityPropagation:visibility";
    private static final String PROPNAME_VIEW_CENTER = "android:visibilityPropagation:center";
    private static final String[] VISIBILITY_PROPAGATION_VALUES = {PROPNAME_VISIBILITY, PROPNAME_VIEW_CENTER};

    @Override // androidx.transition.TransitionPropagation
    public void captureValues(TransitionValues values) {
        View view = values.view;
        Integer visibility = (Integer) values.values.get("android:visibility:visibility");
        if (visibility == null) {
            visibility = Integer.valueOf(view.getVisibility());
        }
        values.values.put(PROPNAME_VISIBILITY, visibility);
        view.getLocationOnScreen(loc);
        int[] loc = {loc[0] + Math.round(view.getTranslationX())};
        loc[0] = loc[0] + (view.getWidth() / 2);
        loc[1] = loc[1] + Math.round(view.getTranslationY());
        loc[1] = loc[1] + (view.getHeight() / 2);
        values.values.put(PROPNAME_VIEW_CENTER, loc);
    }

    @Override // androidx.transition.TransitionPropagation
    public String[] getPropagationProperties() {
        return VISIBILITY_PROPAGATION_VALUES;
    }

    public int getViewVisibility(TransitionValues values) {
        Integer visibility;
        if (values == null || (visibility = (Integer) values.values.get(PROPNAME_VISIBILITY)) == null) {
            return 8;
        }
        return visibility.intValue();
    }

    public int getViewX(TransitionValues values) {
        return getViewCoordinate(values, 0);
    }

    public int getViewY(TransitionValues values) {
        return getViewCoordinate(values, 1);
    }

    private static int getViewCoordinate(TransitionValues values, int coordinateIndex) {
        int[] coordinates;
        if (values == null || (coordinates = (int[]) values.values.get(PROPNAME_VIEW_CENTER)) == null) {
            return -1;
        }
        return coordinates[coordinateIndex];
    }
}
