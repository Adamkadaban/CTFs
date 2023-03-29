package androidx.transition;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.content.Context;
import android.content.res.TypedArray;
import android.content.res.XmlResourceParser;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import androidx.core.content.res.TypedArrayUtils;
import androidx.transition.AnimatorUtils;
import androidx.transition.Transition;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
/* loaded from: classes.dex */
public abstract class Visibility extends Transition {
    public static final int MODE_IN = 1;
    public static final int MODE_OUT = 2;
    private static final String PROPNAME_SCREEN_LOCATION = "android:visibility:screenLocation";
    private int mMode;
    static final String PROPNAME_VISIBILITY = "android:visibility:visibility";
    private static final String PROPNAME_PARENT = "android:visibility:parent";
    private static final String[] sTransitionProperties = {PROPNAME_VISIBILITY, PROPNAME_PARENT};

    @Retention(RetentionPolicy.SOURCE)
    /* loaded from: classes.dex */
    public @interface Mode {
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class VisibilityInfo {
        ViewGroup mEndParent;
        int mEndVisibility;
        boolean mFadeIn;
        ViewGroup mStartParent;
        int mStartVisibility;
        boolean mVisibilityChange;

        VisibilityInfo() {
        }
    }

    public Visibility() {
        this.mMode = 3;
    }

    public Visibility(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.mMode = 3;
        TypedArray a = context.obtainStyledAttributes(attrs, Styleable.VISIBILITY_TRANSITION);
        int mode = TypedArrayUtils.getNamedInt(a, (XmlResourceParser) attrs, "transitionVisibilityMode", 0, 0);
        a.recycle();
        if (mode != 0) {
            setMode(mode);
        }
    }

    public void setMode(int mode) {
        if ((mode & (-4)) != 0) {
            throw new IllegalArgumentException("Only MODE_IN and MODE_OUT flags are allowed");
        }
        this.mMode = mode;
    }

    public int getMode() {
        return this.mMode;
    }

    @Override // androidx.transition.Transition
    public String[] getTransitionProperties() {
        return sTransitionProperties;
    }

    private void captureValues(TransitionValues transitionValues) {
        int visibility = transitionValues.view.getVisibility();
        transitionValues.values.put(PROPNAME_VISIBILITY, Integer.valueOf(visibility));
        transitionValues.values.put(PROPNAME_PARENT, transitionValues.view.getParent());
        int[] loc = new int[2];
        transitionValues.view.getLocationOnScreen(loc);
        transitionValues.values.put(PROPNAME_SCREEN_LOCATION, loc);
    }

    @Override // androidx.transition.Transition
    public void captureStartValues(TransitionValues transitionValues) {
        captureValues(transitionValues);
    }

    @Override // androidx.transition.Transition
    public void captureEndValues(TransitionValues transitionValues) {
        captureValues(transitionValues);
    }

    public boolean isVisible(TransitionValues values) {
        if (values == null) {
            return false;
        }
        int visibility = ((Integer) values.values.get(PROPNAME_VISIBILITY)).intValue();
        View parent = (View) values.values.get(PROPNAME_PARENT);
        return visibility == 0 && parent != null;
    }

    private VisibilityInfo getVisibilityChangeInfo(TransitionValues startValues, TransitionValues endValues) {
        VisibilityInfo visInfo = new VisibilityInfo();
        visInfo.mVisibilityChange = false;
        visInfo.mFadeIn = false;
        if (startValues != null && startValues.values.containsKey(PROPNAME_VISIBILITY)) {
            visInfo.mStartVisibility = ((Integer) startValues.values.get(PROPNAME_VISIBILITY)).intValue();
            visInfo.mStartParent = (ViewGroup) startValues.values.get(PROPNAME_PARENT);
        } else {
            visInfo.mStartVisibility = -1;
            visInfo.mStartParent = null;
        }
        if (endValues != null && endValues.values.containsKey(PROPNAME_VISIBILITY)) {
            visInfo.mEndVisibility = ((Integer) endValues.values.get(PROPNAME_VISIBILITY)).intValue();
            visInfo.mEndParent = (ViewGroup) endValues.values.get(PROPNAME_PARENT);
        } else {
            visInfo.mEndVisibility = -1;
            visInfo.mEndParent = null;
        }
        if (startValues != null && endValues != null) {
            if (visInfo.mStartVisibility == visInfo.mEndVisibility && visInfo.mStartParent == visInfo.mEndParent) {
                return visInfo;
            }
            if (visInfo.mStartVisibility != visInfo.mEndVisibility) {
                if (visInfo.mStartVisibility == 0) {
                    visInfo.mFadeIn = false;
                    visInfo.mVisibilityChange = true;
                } else if (visInfo.mEndVisibility == 0) {
                    visInfo.mFadeIn = true;
                    visInfo.mVisibilityChange = true;
                }
            } else if (visInfo.mEndParent == null) {
                visInfo.mFadeIn = false;
                visInfo.mVisibilityChange = true;
            } else if (visInfo.mStartParent == null) {
                visInfo.mFadeIn = true;
                visInfo.mVisibilityChange = true;
            }
        } else if (startValues == null && visInfo.mEndVisibility == 0) {
            visInfo.mFadeIn = true;
            visInfo.mVisibilityChange = true;
        } else if (endValues == null && visInfo.mStartVisibility == 0) {
            visInfo.mFadeIn = false;
            visInfo.mVisibilityChange = true;
        }
        return visInfo;
    }

    @Override // androidx.transition.Transition
    public Animator createAnimator(ViewGroup sceneRoot, TransitionValues startValues, TransitionValues endValues) {
        VisibilityInfo visInfo = getVisibilityChangeInfo(startValues, endValues);
        if (visInfo.mVisibilityChange) {
            if (visInfo.mStartParent != null || visInfo.mEndParent != null) {
                if (visInfo.mFadeIn) {
                    return onAppear(sceneRoot, startValues, visInfo.mStartVisibility, endValues, visInfo.mEndVisibility);
                }
                return onDisappear(sceneRoot, startValues, visInfo.mStartVisibility, endValues, visInfo.mEndVisibility);
            }
            return null;
        }
        return null;
    }

    public Animator onAppear(ViewGroup sceneRoot, TransitionValues startValues, int startVisibility, TransitionValues endValues, int endVisibility) {
        if ((this.mMode & 1) != 1 || endValues == null) {
            return null;
        }
        if (startValues == null) {
            View endParent = (View) endValues.view.getParent();
            TransitionValues startParentValues = getMatchedTransitionValues(endParent, false);
            TransitionValues endParentValues = getTransitionValues(endParent, false);
            VisibilityInfo parentVisibilityInfo = getVisibilityChangeInfo(startParentValues, endParentValues);
            if (parentVisibilityInfo.mVisibilityChange) {
                return null;
            }
        }
        return onAppear(sceneRoot, endValues.view, startValues, endValues);
    }

    public Animator onAppear(ViewGroup sceneRoot, View view, TransitionValues startValues, TransitionValues endValues) {
        return null;
    }

    public Animator onDisappear(final ViewGroup sceneRoot, TransitionValues startValues, int startVisibility, TransitionValues endValues, int endVisibility) {
        if ((this.mMode & 2) == 2 && startValues != null) {
            final View startView = startValues.view;
            View endView = endValues != null ? endValues.view : null;
            View overlayView = null;
            View viewToKeep = null;
            boolean reusingOverlayView = false;
            View savedOverlayView = (View) startView.getTag(R.id.save_overlay_view);
            if (savedOverlayView != null) {
                overlayView = savedOverlayView;
                reusingOverlayView = true;
            } else {
                boolean needOverlayForStartView = false;
                if (endView == null || endView.getParent() == null) {
                    if (endView != null) {
                        overlayView = endView;
                    } else {
                        needOverlayForStartView = true;
                    }
                } else if (endVisibility == 4) {
                    viewToKeep = endView;
                } else if (startView == endView) {
                    viewToKeep = endView;
                } else {
                    needOverlayForStartView = true;
                }
                if (needOverlayForStartView) {
                    if (startView.getParent() == null) {
                        overlayView = startView;
                    } else if (startView.getParent() instanceof View) {
                        View startParent = (View) startView.getParent();
                        TransitionValues startParentValues = getTransitionValues(startParent, true);
                        TransitionValues endParentValues = getMatchedTransitionValues(startParent, true);
                        VisibilityInfo parentVisibilityInfo = getVisibilityChangeInfo(startParentValues, endParentValues);
                        if (!parentVisibilityInfo.mVisibilityChange) {
                            overlayView = TransitionUtils.copyViewImage(sceneRoot, startView, startParent);
                        } else {
                            int id = startParent.getId();
                            if (startParent.getParent() == null && id != -1 && sceneRoot.findViewById(id) != null && this.mCanRemoveViews) {
                                overlayView = startView;
                            }
                        }
                    }
                }
            }
            if (overlayView != null) {
                if (!reusingOverlayView) {
                    int[] screenLoc = (int[]) startValues.values.get(PROPNAME_SCREEN_LOCATION);
                    int screenX = screenLoc[0];
                    int screenY = screenLoc[1];
                    int[] loc = new int[2];
                    sceneRoot.getLocationOnScreen(loc);
                    overlayView.offsetLeftAndRight((screenX - loc[0]) - overlayView.getLeft());
                    overlayView.offsetTopAndBottom((screenY - loc[1]) - overlayView.getTop());
                    ViewGroupUtils.getOverlay(sceneRoot).add(overlayView);
                }
                Animator animator = onDisappear(sceneRoot, overlayView, startValues, endValues);
                if (!reusingOverlayView) {
                    if (animator == null) {
                        ViewGroupUtils.getOverlay(sceneRoot).remove(overlayView);
                    } else {
                        startView.setTag(R.id.save_overlay_view, overlayView);
                        final View finalOverlayView = overlayView;
                        addListener(new TransitionListenerAdapter() { // from class: androidx.transition.Visibility.1
                            @Override // androidx.transition.TransitionListenerAdapter, androidx.transition.Transition.TransitionListener
                            public void onTransitionPause(Transition transition) {
                                ViewGroupUtils.getOverlay(sceneRoot).remove(finalOverlayView);
                            }

                            @Override // androidx.transition.TransitionListenerAdapter, androidx.transition.Transition.TransitionListener
                            public void onTransitionResume(Transition transition) {
                                if (finalOverlayView.getParent() == null) {
                                    ViewGroupUtils.getOverlay(sceneRoot).add(finalOverlayView);
                                } else {
                                    Visibility.this.cancel();
                                }
                            }

                            @Override // androidx.transition.TransitionListenerAdapter, androidx.transition.Transition.TransitionListener
                            public void onTransitionEnd(Transition transition) {
                                startView.setTag(R.id.save_overlay_view, null);
                                ViewGroupUtils.getOverlay(sceneRoot).remove(finalOverlayView);
                                transition.removeListener(this);
                            }
                        });
                    }
                }
                return animator;
            } else if (viewToKeep != null) {
                int originalVisibility = viewToKeep.getVisibility();
                ViewUtils.setTransitionVisibility(viewToKeep, 0);
                Animator animator2 = onDisappear(sceneRoot, viewToKeep, startValues, endValues);
                if (animator2 != null) {
                    DisappearListener disappearListener = new DisappearListener(viewToKeep, endVisibility, true);
                    animator2.addListener(disappearListener);
                    AnimatorUtils.addPauseListener(animator2, disappearListener);
                    addListener(disappearListener);
                } else {
                    ViewUtils.setTransitionVisibility(viewToKeep, originalVisibility);
                }
                return animator2;
            } else {
                return null;
            }
        }
        return null;
    }

    public Animator onDisappear(ViewGroup sceneRoot, View view, TransitionValues startValues, TransitionValues endValues) {
        return null;
    }

    @Override // androidx.transition.Transition
    public boolean isTransitionRequired(TransitionValues startValues, TransitionValues newValues) {
        if (startValues == null && newValues == null) {
            return false;
        }
        if (startValues != null && newValues != null && newValues.values.containsKey(PROPNAME_VISIBILITY) != startValues.values.containsKey(PROPNAME_VISIBILITY)) {
            return false;
        }
        VisibilityInfo changeInfo = getVisibilityChangeInfo(startValues, newValues);
        if (changeInfo.mVisibilityChange) {
            return changeInfo.mStartVisibility == 0 || changeInfo.mEndVisibility == 0;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class DisappearListener extends AnimatorListenerAdapter implements Transition.TransitionListener, AnimatorUtils.AnimatorPauseListenerCompat {
        boolean mCanceled = false;
        private final int mFinalVisibility;
        private boolean mLayoutSuppressed;
        private final ViewGroup mParent;
        private final boolean mSuppressLayout;
        private final View mView;

        DisappearListener(View view, int finalVisibility, boolean suppressLayout) {
            this.mView = view;
            this.mFinalVisibility = finalVisibility;
            this.mParent = (ViewGroup) view.getParent();
            this.mSuppressLayout = suppressLayout;
            suppressLayout(true);
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorPauseListener, androidx.transition.AnimatorUtils.AnimatorPauseListenerCompat
        public void onAnimationPause(Animator animation) {
            if (!this.mCanceled) {
                ViewUtils.setTransitionVisibility(this.mView, this.mFinalVisibility);
            }
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorPauseListener, androidx.transition.AnimatorUtils.AnimatorPauseListenerCompat
        public void onAnimationResume(Animator animation) {
            if (!this.mCanceled) {
                ViewUtils.setTransitionVisibility(this.mView, 0);
            }
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationCancel(Animator animation) {
            this.mCanceled = true;
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationRepeat(Animator animation) {
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationStart(Animator animation) {
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animation) {
            hideViewWhenNotCanceled();
        }

        @Override // androidx.transition.Transition.TransitionListener
        public void onTransitionStart(Transition transition) {
        }

        @Override // androidx.transition.Transition.TransitionListener
        public void onTransitionEnd(Transition transition) {
            hideViewWhenNotCanceled();
            transition.removeListener(this);
        }

        @Override // androidx.transition.Transition.TransitionListener
        public void onTransitionCancel(Transition transition) {
        }

        @Override // androidx.transition.Transition.TransitionListener
        public void onTransitionPause(Transition transition) {
            suppressLayout(false);
        }

        @Override // androidx.transition.Transition.TransitionListener
        public void onTransitionResume(Transition transition) {
            suppressLayout(true);
        }

        private void hideViewWhenNotCanceled() {
            if (!this.mCanceled) {
                ViewUtils.setTransitionVisibility(this.mView, this.mFinalVisibility);
                ViewGroup viewGroup = this.mParent;
                if (viewGroup != null) {
                    viewGroup.invalidate();
                }
            }
            suppressLayout(false);
        }

        private void suppressLayout(boolean suppress) {
            ViewGroup viewGroup;
            if (this.mSuppressLayout && this.mLayoutSuppressed != suppress && (viewGroup = this.mParent) != null) {
                this.mLayoutSuppressed = suppress;
                ViewGroupUtils.suppressLayout(viewGroup, suppress);
            }
        }
    }
}
