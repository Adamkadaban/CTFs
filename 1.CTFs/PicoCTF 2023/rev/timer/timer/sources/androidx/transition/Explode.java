package androidx.transition;

import android.animation.Animator;
import android.animation.TimeInterpolator;
import android.content.Context;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.DecelerateInterpolator;
/* loaded from: classes.dex */
public class Explode extends Visibility {
    private static final String PROPNAME_SCREEN_BOUNDS = "android:explode:screenBounds";
    private int[] mTempLoc;
    private static final TimeInterpolator sDecelerate = new DecelerateInterpolator();
    private static final TimeInterpolator sAccelerate = new AccelerateInterpolator();

    public Explode() {
        this.mTempLoc = new int[2];
        setPropagation(new CircularPropagation());
    }

    public Explode(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.mTempLoc = new int[2];
        setPropagation(new CircularPropagation());
    }

    private void captureValues(TransitionValues transitionValues) {
        View view = transitionValues.view;
        view.getLocationOnScreen(this.mTempLoc);
        int[] iArr = this.mTempLoc;
        int left = iArr[0];
        int top = iArr[1];
        int right = view.getWidth() + left;
        int bottom = view.getHeight() + top;
        transitionValues.values.put(PROPNAME_SCREEN_BOUNDS, new Rect(left, top, right, bottom));
    }

    @Override // androidx.transition.Visibility, androidx.transition.Transition
    public void captureStartValues(TransitionValues transitionValues) {
        super.captureStartValues(transitionValues);
        captureValues(transitionValues);
    }

    @Override // androidx.transition.Visibility, androidx.transition.Transition
    public void captureEndValues(TransitionValues transitionValues) {
        super.captureEndValues(transitionValues);
        captureValues(transitionValues);
    }

    @Override // androidx.transition.Visibility
    public Animator onAppear(ViewGroup sceneRoot, View view, TransitionValues startValues, TransitionValues endValues) {
        if (endValues == null) {
            return null;
        }
        Rect bounds = (Rect) endValues.values.get(PROPNAME_SCREEN_BOUNDS);
        float endX = view.getTranslationX();
        float endY = view.getTranslationY();
        calculateOut(sceneRoot, bounds, this.mTempLoc);
        int[] iArr = this.mTempLoc;
        float startX = endX + iArr[0];
        float startY = endY + iArr[1];
        return TranslationAnimationCreator.createAnimation(view, endValues, bounds.left, bounds.top, startX, startY, endX, endY, sDecelerate, this);
    }

    @Override // androidx.transition.Visibility
    public Animator onDisappear(ViewGroup sceneRoot, View view, TransitionValues startValues, TransitionValues endValues) {
        if (startValues == null) {
            return null;
        }
        Rect bounds = (Rect) startValues.values.get(PROPNAME_SCREEN_BOUNDS);
        int viewPosX = bounds.left;
        int viewPosY = bounds.top;
        float startX = view.getTranslationX();
        float startY = view.getTranslationY();
        float endX = startX;
        float endY = startY;
        int[] interruptedPosition = (int[]) startValues.view.getTag(R.id.transition_position);
        if (interruptedPosition != null) {
            endX += interruptedPosition[0] - bounds.left;
            endY += interruptedPosition[1] - bounds.top;
            bounds.offsetTo(interruptedPosition[0], interruptedPosition[1]);
        }
        calculateOut(sceneRoot, bounds, this.mTempLoc);
        int[] iArr = this.mTempLoc;
        return TranslationAnimationCreator.createAnimation(view, startValues, viewPosX, viewPosY, startX, startY, endX + iArr[0], endY + iArr[1], sAccelerate, this);
    }

    private void calculateOut(View sceneRoot, Rect bounds, int[] outVector) {
        int focalX;
        int focalY;
        sceneRoot.getLocationOnScreen(this.mTempLoc);
        int[] iArr = this.mTempLoc;
        int sceneRootX = iArr[0];
        int sceneRootY = iArr[1];
        Rect epicenter = getEpicenter();
        if (epicenter == null) {
            focalX = (sceneRoot.getWidth() / 2) + sceneRootX + Math.round(sceneRoot.getTranslationX());
            focalY = (sceneRoot.getHeight() / 2) + sceneRootY + Math.round(sceneRoot.getTranslationY());
        } else {
            focalX = epicenter.centerX();
            focalY = epicenter.centerY();
        }
        int centerX = bounds.centerX();
        int centerY = bounds.centerY();
        float xVector = centerX - focalX;
        float yVector = centerY - focalY;
        if (xVector == 0.0f && yVector == 0.0f) {
            xVector = ((float) (Math.random() * 2.0d)) - 1.0f;
            yVector = ((float) (Math.random() * 2.0d)) - 1.0f;
        }
        float vectorSize = calculateDistance(xVector, yVector);
        float maxDistance = calculateMaxDistance(sceneRoot, focalX - sceneRootX, focalY - sceneRootY);
        outVector[0] = Math.round(maxDistance * (xVector / vectorSize));
        outVector[1] = Math.round(maxDistance * (yVector / vectorSize));
    }

    private static float calculateMaxDistance(View sceneRoot, int focalX, int focalY) {
        int maxX = Math.max(focalX, sceneRoot.getWidth() - focalX);
        int maxY = Math.max(focalY, sceneRoot.getHeight() - focalY);
        return calculateDistance(maxX, maxY);
    }

    private static float calculateDistance(float x, float y) {
        return (float) Math.sqrt((x * x) + (y * y));
    }
}
