package androidx.transition;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.animation.PropertyValuesHolder;
import android.content.Context;
import android.content.res.TypedArray;
import android.content.res.XmlResourceParser;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Path;
import android.graphics.PointF;
import android.graphics.Rect;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.util.Property;
import android.view.View;
import android.view.ViewGroup;
import androidx.core.content.res.TypedArrayUtils;
import androidx.core.view.ViewCompat;
import androidx.transition.Transition;
import java.util.Map;
/* loaded from: classes.dex */
public class ChangeBounds extends Transition {
    private boolean mReparent;
    private boolean mResizeClip;
    private int[] mTempLocation;
    private static final String PROPNAME_BOUNDS = "android:changeBounds:bounds";
    private static final String PROPNAME_CLIP = "android:changeBounds:clip";
    private static final String PROPNAME_PARENT = "android:changeBounds:parent";
    private static final String PROPNAME_WINDOW_X = "android:changeBounds:windowX";
    private static final String PROPNAME_WINDOW_Y = "android:changeBounds:windowY";
    private static final String[] sTransitionProperties = {PROPNAME_BOUNDS, PROPNAME_CLIP, PROPNAME_PARENT, PROPNAME_WINDOW_X, PROPNAME_WINDOW_Y};
    private static final Property<Drawable, PointF> DRAWABLE_ORIGIN_PROPERTY = new Property<Drawable, PointF>(PointF.class, "boundsOrigin") { // from class: androidx.transition.ChangeBounds.1
        private Rect mBounds = new Rect();

        @Override // android.util.Property
        public void set(Drawable object, PointF value) {
            object.copyBounds(this.mBounds);
            this.mBounds.offsetTo(Math.round(value.x), Math.round(value.y));
            object.setBounds(this.mBounds);
        }

        @Override // android.util.Property
        public PointF get(Drawable object) {
            object.copyBounds(this.mBounds);
            return new PointF(this.mBounds.left, this.mBounds.top);
        }
    };
    private static final Property<ViewBounds, PointF> TOP_LEFT_PROPERTY = new Property<ViewBounds, PointF>(PointF.class, "topLeft") { // from class: androidx.transition.ChangeBounds.2
        @Override // android.util.Property
        public void set(ViewBounds viewBounds, PointF topLeft) {
            viewBounds.setTopLeft(topLeft);
        }

        @Override // android.util.Property
        public PointF get(ViewBounds viewBounds) {
            return null;
        }
    };
    private static final Property<ViewBounds, PointF> BOTTOM_RIGHT_PROPERTY = new Property<ViewBounds, PointF>(PointF.class, "bottomRight") { // from class: androidx.transition.ChangeBounds.3
        @Override // android.util.Property
        public void set(ViewBounds viewBounds, PointF bottomRight) {
            viewBounds.setBottomRight(bottomRight);
        }

        @Override // android.util.Property
        public PointF get(ViewBounds viewBounds) {
            return null;
        }
    };
    private static final Property<View, PointF> BOTTOM_RIGHT_ONLY_PROPERTY = new Property<View, PointF>(PointF.class, "bottomRight") { // from class: androidx.transition.ChangeBounds.4
        @Override // android.util.Property
        public void set(View view, PointF bottomRight) {
            int left = view.getLeft();
            int top = view.getTop();
            int right = Math.round(bottomRight.x);
            int bottom = Math.round(bottomRight.y);
            ViewUtils.setLeftTopRightBottom(view, left, top, right, bottom);
        }

        @Override // android.util.Property
        public PointF get(View view) {
            return null;
        }
    };
    private static final Property<View, PointF> TOP_LEFT_ONLY_PROPERTY = new Property<View, PointF>(PointF.class, "topLeft") { // from class: androidx.transition.ChangeBounds.5
        @Override // android.util.Property
        public void set(View view, PointF topLeft) {
            int left = Math.round(topLeft.x);
            int top = Math.round(topLeft.y);
            int right = view.getRight();
            int bottom = view.getBottom();
            ViewUtils.setLeftTopRightBottom(view, left, top, right, bottom);
        }

        @Override // android.util.Property
        public PointF get(View view) {
            return null;
        }
    };
    private static final Property<View, PointF> POSITION_PROPERTY = new Property<View, PointF>(PointF.class, "position") { // from class: androidx.transition.ChangeBounds.6
        @Override // android.util.Property
        public void set(View view, PointF topLeft) {
            int left = Math.round(topLeft.x);
            int top = Math.round(topLeft.y);
            int right = view.getWidth() + left;
            int bottom = view.getHeight() + top;
            ViewUtils.setLeftTopRightBottom(view, left, top, right, bottom);
        }

        @Override // android.util.Property
        public PointF get(View view) {
            return null;
        }
    };
    private static RectEvaluator sRectEvaluator = new RectEvaluator();

    public ChangeBounds() {
        this.mTempLocation = new int[2];
        this.mResizeClip = false;
        this.mReparent = false;
    }

    public ChangeBounds(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.mTempLocation = new int[2];
        this.mResizeClip = false;
        this.mReparent = false;
        TypedArray a = context.obtainStyledAttributes(attrs, Styleable.CHANGE_BOUNDS);
        boolean resizeClip = TypedArrayUtils.getNamedBoolean(a, (XmlResourceParser) attrs, "resizeClip", 0, false);
        a.recycle();
        setResizeClip(resizeClip);
    }

    @Override // androidx.transition.Transition
    public String[] getTransitionProperties() {
        return sTransitionProperties;
    }

    public void setResizeClip(boolean resizeClip) {
        this.mResizeClip = resizeClip;
    }

    public boolean getResizeClip() {
        return this.mResizeClip;
    }

    private void captureValues(TransitionValues values) {
        View view = values.view;
        if (ViewCompat.isLaidOut(view) || view.getWidth() != 0 || view.getHeight() != 0) {
            values.values.put(PROPNAME_BOUNDS, new Rect(view.getLeft(), view.getTop(), view.getRight(), view.getBottom()));
            values.values.put(PROPNAME_PARENT, values.view.getParent());
            if (this.mReparent) {
                values.view.getLocationInWindow(this.mTempLocation);
                values.values.put(PROPNAME_WINDOW_X, Integer.valueOf(this.mTempLocation[0]));
                values.values.put(PROPNAME_WINDOW_Y, Integer.valueOf(this.mTempLocation[1]));
            }
            if (this.mResizeClip) {
                values.values.put(PROPNAME_CLIP, ViewCompat.getClipBounds(view));
            }
        }
    }

    @Override // androidx.transition.Transition
    public void captureStartValues(TransitionValues transitionValues) {
        captureValues(transitionValues);
    }

    @Override // androidx.transition.Transition
    public void captureEndValues(TransitionValues transitionValues) {
        captureValues(transitionValues);
    }

    private boolean parentMatches(View startParent, View endParent) {
        if (!this.mReparent) {
            return true;
        }
        TransitionValues endValues = getMatchedTransitionValues(startParent, true);
        if (endValues == null) {
            boolean parentMatches = startParent == endParent;
            return parentMatches;
        }
        boolean parentMatches2 = endParent == endValues.view;
        return parentMatches2;
    }

    @Override // androidx.transition.Transition
    public Animator createAnimator(final ViewGroup sceneRoot, TransitionValues startValues, TransitionValues endValues) {
        final View view;
        int startLeft;
        int startTop;
        int endLeft;
        ObjectAnimator positionAnimator;
        int i;
        Rect startClip;
        Rect endClip;
        boolean z;
        Rect startClip2;
        Animator anim;
        if (startValues != null && endValues != null) {
            Map<String, Object> startParentVals = startValues.values;
            Map<String, Object> endParentVals = endValues.values;
            ViewGroup startParent = (ViewGroup) startParentVals.get(PROPNAME_PARENT);
            ViewGroup endParent = (ViewGroup) endParentVals.get(PROPNAME_PARENT);
            if (startParent != null && endParent != null) {
                final View view2 = endValues.view;
                if (parentMatches(startParent, endParent)) {
                    Rect startBounds = (Rect) startValues.values.get(PROPNAME_BOUNDS);
                    Rect endBounds = (Rect) endValues.values.get(PROPNAME_BOUNDS);
                    int startLeft2 = startBounds.left;
                    int endLeft2 = endBounds.left;
                    int startTop2 = startBounds.top;
                    final int endTop = endBounds.top;
                    int startRight = startBounds.right;
                    final int endRight = endBounds.right;
                    int startBottom = startBounds.bottom;
                    final int endBottom = endBounds.bottom;
                    int startWidth = startRight - startLeft2;
                    int startHeight = startBottom - startTop2;
                    int endWidth = endRight - endLeft2;
                    int endHeight = endBottom - endTop;
                    Rect startClip3 = (Rect) startValues.values.get(PROPNAME_CLIP);
                    final Rect endClip2 = (Rect) endValues.values.get(PROPNAME_CLIP);
                    int numChanges = 0;
                    if ((startWidth != 0 && startHeight != 0) || (endWidth != 0 && endHeight != 0)) {
                        if (startLeft2 != endLeft2 || startTop2 != endTop) {
                            numChanges = 0 + 1;
                        }
                        if (startRight != endRight || startBottom != endBottom) {
                            numChanges++;
                        }
                    }
                    if ((startClip3 != null && !startClip3.equals(endClip2)) || (startClip3 == null && endClip2 != null)) {
                        numChanges++;
                    }
                    if (numChanges > 0) {
                        if (this.mResizeClip) {
                            view = view2;
                            int maxWidth = Math.max(startWidth, endWidth);
                            int maxHeight = Math.max(startHeight, endHeight);
                            ViewUtils.setLeftTopRightBottom(view, startLeft2, startTop2, startLeft2 + maxWidth, startTop2 + maxHeight);
                            if (startLeft2 == endLeft2 && startTop2 == endTop) {
                                endLeft = endLeft2;
                                positionAnimator = null;
                                startTop = startTop2;
                                startLeft = startLeft2;
                            } else {
                                startLeft = startLeft2;
                                startTop = startTop2;
                                endLeft = endLeft2;
                                Path topLeftPath = getPathMotion().getPath(startLeft2, startTop2, endLeft2, endTop);
                                positionAnimator = ObjectAnimatorUtils.ofPointF(view, POSITION_PROPERTY, topLeftPath);
                            }
                            if (startClip3 != null) {
                                i = 0;
                                startClip = startClip3;
                            } else {
                                i = 0;
                                startClip = new Rect(0, 0, startWidth, startHeight);
                            }
                            if (endClip2 != null) {
                                endClip = endClip2;
                            } else {
                                endClip = new Rect(i, i, endWidth, endHeight);
                            }
                            ObjectAnimator clipAnimator = null;
                            if (startClip.equals(endClip)) {
                                z = true;
                                startClip2 = startClip;
                            } else {
                                ViewCompat.setClipBounds(view, startClip);
                                ObjectAnimator clipAnimator2 = ObjectAnimator.ofObject(view, "clipBounds", sRectEvaluator, startClip, endClip);
                                startClip2 = startClip;
                                final int i2 = endLeft;
                                z = true;
                                clipAnimator2.addListener(new AnimatorListenerAdapter() { // from class: androidx.transition.ChangeBounds.8
                                    private boolean mIsCanceled;

                                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                                    public void onAnimationCancel(Animator animation) {
                                        this.mIsCanceled = true;
                                    }

                                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                                    public void onAnimationEnd(Animator animation) {
                                        if (!this.mIsCanceled) {
                                            ViewCompat.setClipBounds(view, endClip2);
                                            ViewUtils.setLeftTopRightBottom(view, i2, endTop, endRight, endBottom);
                                        }
                                    }
                                });
                                clipAnimator = clipAnimator2;
                            }
                            anim = TransitionUtils.mergeAnimators(positionAnimator, clipAnimator);
                        } else {
                            ViewUtils.setLeftTopRightBottom(view2, startLeft2, startTop2, startRight, startBottom);
                            if (numChanges == 2) {
                                if (startWidth != endWidth || startHeight != endHeight) {
                                    ViewBounds viewBounds = new ViewBounds(view2);
                                    Path topLeftPath2 = getPathMotion().getPath(startLeft2, startTop2, endLeft2, endTop);
                                    ObjectAnimator topLeftAnimator = ObjectAnimatorUtils.ofPointF(viewBounds, TOP_LEFT_PROPERTY, topLeftPath2);
                                    Path bottomRightPath = getPathMotion().getPath(startRight, startBottom, endRight, endBottom);
                                    ObjectAnimator bottomRightAnimator = ObjectAnimatorUtils.ofPointF(viewBounds, BOTTOM_RIGHT_PROPERTY, bottomRightPath);
                                    AnimatorSet set = new AnimatorSet();
                                    set.playTogether(topLeftAnimator, bottomRightAnimator);
                                    set.addListener(new AnimatorListenerAdapter(viewBounds) { // from class: androidx.transition.ChangeBounds.7
                                        private ViewBounds mViewBounds;
                                        final /* synthetic */ ViewBounds val$viewBounds;

                                        {
                                            this.val$viewBounds = viewBounds;
                                            this.mViewBounds = viewBounds;
                                        }
                                    });
                                    anim = set;
                                    view = view2;
                                    z = true;
                                } else {
                                    Path topLeftPath3 = getPathMotion().getPath(startLeft2, startTop2, endLeft2, endTop);
                                    anim = ObjectAnimatorUtils.ofPointF(view2, POSITION_PROPERTY, topLeftPath3);
                                    view = view2;
                                    z = true;
                                }
                            } else {
                                if (startLeft2 != endLeft2) {
                                    view = view2;
                                } else if (startTop2 != endTop) {
                                    view = view2;
                                } else {
                                    Path bottomRight = getPathMotion().getPath(startRight, startBottom, endRight, endBottom);
                                    view = view2;
                                    anim = ObjectAnimatorUtils.ofPointF(view, BOTTOM_RIGHT_ONLY_PROPERTY, bottomRight);
                                    z = true;
                                }
                                Path topLeftPath4 = getPathMotion().getPath(startLeft2, startTop2, endLeft2, endTop);
                                anim = ObjectAnimatorUtils.ofPointF(view, TOP_LEFT_ONLY_PROPERTY, topLeftPath4);
                                z = true;
                            }
                        }
                        if (view.getParent() instanceof ViewGroup) {
                            final ViewGroup parent = (ViewGroup) view.getParent();
                            ViewGroupUtils.suppressLayout(parent, z);
                            Transition.TransitionListener transitionListener = new TransitionListenerAdapter() { // from class: androidx.transition.ChangeBounds.9
                                boolean mCanceled = false;

                                @Override // androidx.transition.TransitionListenerAdapter, androidx.transition.Transition.TransitionListener
                                public void onTransitionCancel(Transition transition) {
                                    ViewGroupUtils.suppressLayout(parent, false);
                                    this.mCanceled = true;
                                }

                                @Override // androidx.transition.TransitionListenerAdapter, androidx.transition.Transition.TransitionListener
                                public void onTransitionEnd(Transition transition) {
                                    if (!this.mCanceled) {
                                        ViewGroupUtils.suppressLayout(parent, false);
                                    }
                                    transition.removeListener(this);
                                }

                                @Override // androidx.transition.TransitionListenerAdapter, androidx.transition.Transition.TransitionListener
                                public void onTransitionPause(Transition transition) {
                                    ViewGroupUtils.suppressLayout(parent, false);
                                }

                                @Override // androidx.transition.TransitionListenerAdapter, androidx.transition.Transition.TransitionListener
                                public void onTransitionResume(Transition transition) {
                                    ViewGroupUtils.suppressLayout(parent, true);
                                }
                            };
                            addListener(transitionListener);
                        }
                        return anim;
                    }
                    return null;
                }
                int startX = ((Integer) startValues.values.get(PROPNAME_WINDOW_X)).intValue();
                int startY = ((Integer) startValues.values.get(PROPNAME_WINDOW_Y)).intValue();
                int endX = ((Integer) endValues.values.get(PROPNAME_WINDOW_X)).intValue();
                int endY = ((Integer) endValues.values.get(PROPNAME_WINDOW_Y)).intValue();
                if (startX != endX || startY != endY) {
                    sceneRoot.getLocationInWindow(this.mTempLocation);
                    Bitmap bitmap = Bitmap.createBitmap(view2.getWidth(), view2.getHeight(), Bitmap.Config.ARGB_8888);
                    Canvas canvas = new Canvas(bitmap);
                    view2.draw(canvas);
                    final BitmapDrawable drawable = new BitmapDrawable(bitmap);
                    final float transitionAlpha = ViewUtils.getTransitionAlpha(view2);
                    ViewUtils.setTransitionAlpha(view2, 0.0f);
                    ViewUtils.getOverlay(sceneRoot).add(drawable);
                    PathMotion pathMotion = getPathMotion();
                    int[] iArr = this.mTempLocation;
                    Path topLeftPath5 = pathMotion.getPath(startX - iArr[0], startY - iArr[1], endX - iArr[0], endY - iArr[1]);
                    PropertyValuesHolder origin = PropertyValuesHolderUtils.ofPointF(DRAWABLE_ORIGIN_PROPERTY, topLeftPath5);
                    ObjectAnimator anim2 = ObjectAnimator.ofPropertyValuesHolder(drawable, origin);
                    anim2.addListener(new AnimatorListenerAdapter() { // from class: androidx.transition.ChangeBounds.10
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation) {
                            ViewUtils.getOverlay(sceneRoot).remove(drawable);
                            ViewUtils.setTransitionAlpha(view2, transitionAlpha);
                        }
                    });
                    return anim2;
                }
                return null;
            }
            return null;
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class ViewBounds {
        private int mBottom;
        private int mBottomRightCalls;
        private int mLeft;
        private int mRight;
        private int mTop;
        private int mTopLeftCalls;
        private View mView;

        ViewBounds(View view) {
            this.mView = view;
        }

        void setTopLeft(PointF topLeft) {
            this.mLeft = Math.round(topLeft.x);
            this.mTop = Math.round(topLeft.y);
            int i = this.mTopLeftCalls + 1;
            this.mTopLeftCalls = i;
            if (i == this.mBottomRightCalls) {
                setLeftTopRightBottom();
            }
        }

        void setBottomRight(PointF bottomRight) {
            this.mRight = Math.round(bottomRight.x);
            this.mBottom = Math.round(bottomRight.y);
            int i = this.mBottomRightCalls + 1;
            this.mBottomRightCalls = i;
            if (this.mTopLeftCalls == i) {
                setLeftTopRightBottom();
            }
        }

        private void setLeftTopRightBottom() {
            ViewUtils.setLeftTopRightBottom(this.mView, this.mLeft, this.mTop, this.mRight, this.mBottom);
            this.mTopLeftCalls = 0;
            this.mBottomRightCalls = 0;
        }
    }
}
