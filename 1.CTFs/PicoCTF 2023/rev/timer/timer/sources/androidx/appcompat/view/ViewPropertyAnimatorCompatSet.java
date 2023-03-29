package androidx.appcompat.view;

import android.view.View;
import android.view.animation.Interpolator;
import androidx.core.view.ViewPropertyAnimatorCompat;
import androidx.core.view.ViewPropertyAnimatorListener;
import androidx.core.view.ViewPropertyAnimatorListenerAdapter;
import java.util.ArrayList;
import java.util.Iterator;
/* loaded from: classes.dex */
public class ViewPropertyAnimatorCompatSet {
    private Interpolator mInterpolator;
    private boolean mIsStarted;
    ViewPropertyAnimatorListener mListener;
    private long mDuration = -1;
    private final ViewPropertyAnimatorListenerAdapter mProxyListener = new ViewPropertyAnimatorListenerAdapter() { // from class: androidx.appcompat.view.ViewPropertyAnimatorCompatSet.1
        private boolean mProxyStarted = false;
        private int mProxyEndCount = 0;

        @Override // androidx.core.view.ViewPropertyAnimatorListenerAdapter, androidx.core.view.ViewPropertyAnimatorListener
        public void onAnimationStart(View view) {
            if (this.mProxyStarted) {
                return;
            }
            this.mProxyStarted = true;
            if (ViewPropertyAnimatorCompatSet.this.mListener != null) {
                ViewPropertyAnimatorCompatSet.this.mListener.onAnimationStart(null);
            }
        }

        void onEnd() {
            this.mProxyEndCount = 0;
            this.mProxyStarted = false;
            ViewPropertyAnimatorCompatSet.this.onAnimationsEnded();
        }

        @Override // androidx.core.view.ViewPropertyAnimatorListenerAdapter, androidx.core.view.ViewPropertyAnimatorListener
        public void onAnimationEnd(View view) {
            int i = this.mProxyEndCount + 1;
            this.mProxyEndCount = i;
            if (i == ViewPropertyAnimatorCompatSet.this.mAnimators.size()) {
                if (ViewPropertyAnimatorCompatSet.this.mListener != null) {
                    ViewPropertyAnimatorCompatSet.this.mListener.onAnimationEnd(null);
                }
                onEnd();
            }
        }
    };
    final ArrayList<ViewPropertyAnimatorCompat> mAnimators = new ArrayList<>();

    public ViewPropertyAnimatorCompatSet play(ViewPropertyAnimatorCompat animator) {
        if (!this.mIsStarted) {
            this.mAnimators.add(animator);
        }
        return this;
    }

    public ViewPropertyAnimatorCompatSet playSequentially(ViewPropertyAnimatorCompat anim1, ViewPropertyAnimatorCompat anim2) {
        this.mAnimators.add(anim1);
        anim2.setStartDelay(anim1.getDuration());
        this.mAnimators.add(anim2);
        return this;
    }

    public void start() {
        if (this.mIsStarted) {
            return;
        }
        Iterator<ViewPropertyAnimatorCompat> it = this.mAnimators.iterator();
        while (it.hasNext()) {
            ViewPropertyAnimatorCompat animator = it.next();
            long j = this.mDuration;
            if (j >= 0) {
                animator.setDuration(j);
            }
            Interpolator interpolator = this.mInterpolator;
            if (interpolator != null) {
                animator.setInterpolator(interpolator);
            }
            if (this.mListener != null) {
                animator.setListener(this.mProxyListener);
            }
            animator.start();
        }
        this.mIsStarted = true;
    }

    void onAnimationsEnded() {
        this.mIsStarted = false;
    }

    public void cancel() {
        if (!this.mIsStarted) {
            return;
        }
        Iterator<ViewPropertyAnimatorCompat> it = this.mAnimators.iterator();
        while (it.hasNext()) {
            ViewPropertyAnimatorCompat animator = it.next();
            animator.cancel();
        }
        this.mIsStarted = false;
    }

    public ViewPropertyAnimatorCompatSet setDuration(long duration) {
        if (!this.mIsStarted) {
            this.mDuration = duration;
        }
        return this;
    }

    public ViewPropertyAnimatorCompatSet setInterpolator(Interpolator interpolator) {
        if (!this.mIsStarted) {
            this.mInterpolator = interpolator;
        }
        return this;
    }

    public ViewPropertyAnimatorCompatSet setListener(ViewPropertyAnimatorListener listener) {
        if (!this.mIsStarted) {
            this.mListener = listener;
        }
        return this;
    }
}
