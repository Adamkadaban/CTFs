package androidx.transition;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ObjectAnimator;
import android.animation.PropertyValuesHolder;
import android.animation.TimeInterpolator;
import android.view.View;
import androidx.transition.Transition;
/* loaded from: classes.dex */
class TranslationAnimationCreator {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static Animator createAnimation(View view, TransitionValues values, int viewPosX, int viewPosY, float startX, float startY, float endX, float endY, TimeInterpolator interpolator, Transition transition) {
        float startX2;
        float startY2;
        float terminalX = view.getTranslationX();
        float terminalY = view.getTranslationY();
        int[] startPosition = (int[]) values.view.getTag(R.id.transition_position);
        if (startPosition == null) {
            startX2 = startX;
            startY2 = startY;
        } else {
            float startX3 = (startPosition[0] - viewPosX) + terminalX;
            startX2 = startX3;
            startY2 = (startPosition[1] - viewPosY) + terminalY;
        }
        int startPosX = viewPosX + Math.round(startX2 - terminalX);
        int startPosY = viewPosY + Math.round(startY2 - terminalY);
        view.setTranslationX(startX2);
        view.setTranslationY(startY2);
        if (startX2 == endX && startY2 == endY) {
            return null;
        }
        ObjectAnimator anim = ObjectAnimator.ofPropertyValuesHolder(view, PropertyValuesHolder.ofFloat(View.TRANSLATION_X, startX2, endX), PropertyValuesHolder.ofFloat(View.TRANSLATION_Y, startY2, endY));
        TransitionPositionListener listener = new TransitionPositionListener(view, values.view, startPosX, startPosY, terminalX, terminalY);
        transition.addListener(listener);
        anim.addListener(listener);
        AnimatorUtils.addPauseListener(anim, listener);
        anim.setInterpolator(interpolator);
        return anim;
    }

    /* loaded from: classes.dex */
    private static class TransitionPositionListener extends AnimatorListenerAdapter implements Transition.TransitionListener {
        private final View mMovingView;
        private float mPausedX;
        private float mPausedY;
        private final int mStartX;
        private final int mStartY;
        private final float mTerminalX;
        private final float mTerminalY;
        private int[] mTransitionPosition;
        private final View mViewInHierarchy;

        TransitionPositionListener(View movingView, View viewInHierarchy, int startX, int startY, float terminalX, float terminalY) {
            this.mMovingView = movingView;
            this.mViewInHierarchy = viewInHierarchy;
            this.mStartX = startX - Math.round(movingView.getTranslationX());
            this.mStartY = startY - Math.round(movingView.getTranslationY());
            this.mTerminalX = terminalX;
            this.mTerminalY = terminalY;
            int[] iArr = (int[]) viewInHierarchy.getTag(R.id.transition_position);
            this.mTransitionPosition = iArr;
            if (iArr != null) {
                viewInHierarchy.setTag(R.id.transition_position, null);
            }
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationCancel(Animator animation) {
            if (this.mTransitionPosition == null) {
                this.mTransitionPosition = new int[2];
            }
            this.mTransitionPosition[0] = Math.round(this.mStartX + this.mMovingView.getTranslationX());
            this.mTransitionPosition[1] = Math.round(this.mStartY + this.mMovingView.getTranslationY());
            this.mViewInHierarchy.setTag(R.id.transition_position, this.mTransitionPosition);
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorPauseListener
        public void onAnimationPause(Animator animator) {
            this.mPausedX = this.mMovingView.getTranslationX();
            this.mPausedY = this.mMovingView.getTranslationY();
            this.mMovingView.setTranslationX(this.mTerminalX);
            this.mMovingView.setTranslationY(this.mTerminalY);
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorPauseListener
        public void onAnimationResume(Animator animator) {
            this.mMovingView.setTranslationX(this.mPausedX);
            this.mMovingView.setTranslationY(this.mPausedY);
        }

        @Override // androidx.transition.Transition.TransitionListener
        public void onTransitionStart(Transition transition) {
        }

        @Override // androidx.transition.Transition.TransitionListener
        public void onTransitionEnd(Transition transition) {
            this.mMovingView.setTranslationX(this.mTerminalX);
            this.mMovingView.setTranslationY(this.mTerminalY);
            transition.removeListener(this);
        }

        @Override // androidx.transition.Transition.TransitionListener
        public void onTransitionCancel(Transition transition) {
        }

        @Override // androidx.transition.Transition.TransitionListener
        public void onTransitionPause(Transition transition) {
        }

        @Override // androidx.transition.Transition.TransitionListener
        public void onTransitionResume(Transition transition) {
        }
    }

    private TranslationAnimationCreator() {
    }
}
