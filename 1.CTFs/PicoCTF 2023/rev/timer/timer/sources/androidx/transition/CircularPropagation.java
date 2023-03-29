package androidx.transition;

import android.graphics.Rect;
import android.view.ViewGroup;
/* loaded from: classes.dex */
public class CircularPropagation extends VisibilityPropagation {
    private float mPropagationSpeed = 3.0f;

    public void setPropagationSpeed(float propagationSpeed) {
        if (propagationSpeed == 0.0f) {
            throw new IllegalArgumentException("propagationSpeed may not be 0");
        }
        this.mPropagationSpeed = propagationSpeed;
    }

    @Override // androidx.transition.TransitionPropagation
    public long getStartDelay(ViewGroup sceneRoot, Transition transition, TransitionValues startValues, TransitionValues endValues) {
        TransitionValues positionValues;
        int epicenterY;
        int epicenterX;
        if (startValues == null && endValues == null) {
            return 0L;
        }
        int directionMultiplier = 1;
        if (endValues == null || getViewVisibility(startValues) == 0) {
            positionValues = startValues;
            directionMultiplier = -1;
        } else {
            positionValues = endValues;
        }
        int viewCenterX = getViewX(positionValues);
        int viewCenterY = getViewY(positionValues);
        Rect epicenter = transition.getEpicenter();
        if (epicenter != null) {
            epicenterX = epicenter.centerX();
            epicenterY = epicenter.centerY();
        } else {
            int[] loc = new int[2];
            sceneRoot.getLocationOnScreen(loc);
            int epicenterX2 = Math.round(loc[0] + (sceneRoot.getWidth() / 2) + sceneRoot.getTranslationX());
            epicenterY = Math.round(loc[1] + (sceneRoot.getHeight() / 2) + sceneRoot.getTranslationY());
            epicenterX = epicenterX2;
        }
        float distance = distance(viewCenterX, viewCenterY, epicenterX, epicenterY);
        float maxDistance = distance(0.0f, 0.0f, sceneRoot.getWidth(), sceneRoot.getHeight());
        float distanceFraction = distance / maxDistance;
        long duration = transition.getDuration();
        if (duration < 0) {
            duration = 300;
        }
        return Math.round((((float) (directionMultiplier * duration)) / this.mPropagationSpeed) * distanceFraction);
    }

    private static float distance(float x1, float y1, float x2, float y2) {
        float x = x2 - x1;
        float y = y2 - y1;
        return (float) Math.sqrt((x * x) + (y * y));
    }
}
