package androidx.constraintlayout.helper.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.util.Log;
import android.view.View;
import androidx.constraintlayout.motion.widget.MotionHelper;
import androidx.constraintlayout.motion.widget.MotionLayout;
import androidx.constraintlayout.motion.widget.MotionScene;
import androidx.constraintlayout.widget.ConstraintSet;
import androidx.constraintlayout.widget.R;
import androidx.recyclerview.widget.ItemTouchHelper;
import java.util.ArrayList;
import java.util.Iterator;
/* loaded from: classes.dex */
public class Carousel extends MotionHelper {
    private static final boolean DEBUG = false;
    private static final String TAG = "Carousel";
    public static final int TOUCH_UP_CARRY_ON = 2;
    public static final int TOUCH_UP_IMMEDIATE_STOP = 1;
    private int backwardTransition;
    private float dampening;
    private int emptyViewBehavior;
    private int firstViewReference;
    private int forwardTransition;
    private boolean infiniteCarousel;
    private Adapter mAdapter;
    private int mAnimateTargetDelay;
    private int mIndex;
    int mLastStartId;
    private final ArrayList<View> mList;
    private MotionLayout mMotionLayout;
    private int mPreviousIndex;
    private int mTargetIndex;
    Runnable mUpdateRunnable;
    private int nextState;
    private int previousState;
    private int startIndex;
    private int touchUpMode;
    private float velocityThreshold;

    /* loaded from: classes.dex */
    public interface Adapter {
        int count();

        void onNewItem(int index);

        void populate(View view, int index);
    }

    public Carousel(Context context) {
        super(context);
        this.mAdapter = null;
        this.mList = new ArrayList<>();
        this.mPreviousIndex = 0;
        this.mIndex = 0;
        this.firstViewReference = -1;
        this.infiniteCarousel = false;
        this.backwardTransition = -1;
        this.forwardTransition = -1;
        this.previousState = -1;
        this.nextState = -1;
        this.dampening = 0.9f;
        this.startIndex = 0;
        this.emptyViewBehavior = 4;
        this.touchUpMode = 1;
        this.velocityThreshold = 2.0f;
        this.mTargetIndex = -1;
        this.mAnimateTargetDelay = ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION;
        this.mLastStartId = -1;
        this.mUpdateRunnable = new Runnable() { // from class: androidx.constraintlayout.helper.widget.Carousel.1
            @Override // java.lang.Runnable
            public void run() {
                Carousel.this.mMotionLayout.setProgress(0.0f);
                Carousel.this.updateItems();
                Carousel.this.mAdapter.onNewItem(Carousel.this.mIndex);
                float velocity = Carousel.this.mMotionLayout.getVelocity();
                if (Carousel.this.touchUpMode == 2 && velocity > Carousel.this.velocityThreshold && Carousel.this.mIndex < Carousel.this.mAdapter.count() - 1) {
                    final float v = Carousel.this.dampening * velocity;
                    if (Carousel.this.mIndex != 0 || Carousel.this.mPreviousIndex <= Carousel.this.mIndex) {
                        if (Carousel.this.mIndex != Carousel.this.mAdapter.count() - 1 || Carousel.this.mPreviousIndex >= Carousel.this.mIndex) {
                            Carousel.this.mMotionLayout.post(new Runnable() { // from class: androidx.constraintlayout.helper.widget.Carousel.1.1
                                @Override // java.lang.Runnable
                                public void run() {
                                    Carousel.this.mMotionLayout.touchAnimateTo(5, 1.0f, v);
                                }
                            });
                        }
                    }
                }
            }
        };
    }

    public Carousel(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.mAdapter = null;
        this.mList = new ArrayList<>();
        this.mPreviousIndex = 0;
        this.mIndex = 0;
        this.firstViewReference = -1;
        this.infiniteCarousel = false;
        this.backwardTransition = -1;
        this.forwardTransition = -1;
        this.previousState = -1;
        this.nextState = -1;
        this.dampening = 0.9f;
        this.startIndex = 0;
        this.emptyViewBehavior = 4;
        this.touchUpMode = 1;
        this.velocityThreshold = 2.0f;
        this.mTargetIndex = -1;
        this.mAnimateTargetDelay = ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION;
        this.mLastStartId = -1;
        this.mUpdateRunnable = new Runnable() { // from class: androidx.constraintlayout.helper.widget.Carousel.1
            @Override // java.lang.Runnable
            public void run() {
                Carousel.this.mMotionLayout.setProgress(0.0f);
                Carousel.this.updateItems();
                Carousel.this.mAdapter.onNewItem(Carousel.this.mIndex);
                float velocity = Carousel.this.mMotionLayout.getVelocity();
                if (Carousel.this.touchUpMode == 2 && velocity > Carousel.this.velocityThreshold && Carousel.this.mIndex < Carousel.this.mAdapter.count() - 1) {
                    final float v = Carousel.this.dampening * velocity;
                    if (Carousel.this.mIndex != 0 || Carousel.this.mPreviousIndex <= Carousel.this.mIndex) {
                        if (Carousel.this.mIndex != Carousel.this.mAdapter.count() - 1 || Carousel.this.mPreviousIndex >= Carousel.this.mIndex) {
                            Carousel.this.mMotionLayout.post(new Runnable() { // from class: androidx.constraintlayout.helper.widget.Carousel.1.1
                                @Override // java.lang.Runnable
                                public void run() {
                                    Carousel.this.mMotionLayout.touchAnimateTo(5, 1.0f, v);
                                }
                            });
                        }
                    }
                }
            }
        };
        init(context, attrs);
    }

    public Carousel(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.mAdapter = null;
        this.mList = new ArrayList<>();
        this.mPreviousIndex = 0;
        this.mIndex = 0;
        this.firstViewReference = -1;
        this.infiniteCarousel = false;
        this.backwardTransition = -1;
        this.forwardTransition = -1;
        this.previousState = -1;
        this.nextState = -1;
        this.dampening = 0.9f;
        this.startIndex = 0;
        this.emptyViewBehavior = 4;
        this.touchUpMode = 1;
        this.velocityThreshold = 2.0f;
        this.mTargetIndex = -1;
        this.mAnimateTargetDelay = ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION;
        this.mLastStartId = -1;
        this.mUpdateRunnable = new Runnable() { // from class: androidx.constraintlayout.helper.widget.Carousel.1
            @Override // java.lang.Runnable
            public void run() {
                Carousel.this.mMotionLayout.setProgress(0.0f);
                Carousel.this.updateItems();
                Carousel.this.mAdapter.onNewItem(Carousel.this.mIndex);
                float velocity = Carousel.this.mMotionLayout.getVelocity();
                if (Carousel.this.touchUpMode == 2 && velocity > Carousel.this.velocityThreshold && Carousel.this.mIndex < Carousel.this.mAdapter.count() - 1) {
                    final float v = Carousel.this.dampening * velocity;
                    if (Carousel.this.mIndex != 0 || Carousel.this.mPreviousIndex <= Carousel.this.mIndex) {
                        if (Carousel.this.mIndex != Carousel.this.mAdapter.count() - 1 || Carousel.this.mPreviousIndex >= Carousel.this.mIndex) {
                            Carousel.this.mMotionLayout.post(new Runnable() { // from class: androidx.constraintlayout.helper.widget.Carousel.1.1
                                @Override // java.lang.Runnable
                                public void run() {
                                    Carousel.this.mMotionLayout.touchAnimateTo(5, 1.0f, v);
                                }
                            });
                        }
                    }
                }
            }
        };
        init(context, attrs);
    }

    private void init(Context context, AttributeSet attrs) {
        if (attrs != null) {
            TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.Carousel);
            int N = a.getIndexCount();
            for (int i = 0; i < N; i++) {
                int attr = a.getIndex(i);
                if (attr == R.styleable.Carousel_carousel_firstView) {
                    this.firstViewReference = a.getResourceId(attr, this.firstViewReference);
                } else if (attr == R.styleable.Carousel_carousel_backwardTransition) {
                    this.backwardTransition = a.getResourceId(attr, this.backwardTransition);
                } else if (attr == R.styleable.Carousel_carousel_forwardTransition) {
                    this.forwardTransition = a.getResourceId(attr, this.forwardTransition);
                } else if (attr == R.styleable.Carousel_carousel_emptyViewsBehavior) {
                    this.emptyViewBehavior = a.getInt(attr, this.emptyViewBehavior);
                } else if (attr == R.styleable.Carousel_carousel_previousState) {
                    this.previousState = a.getResourceId(attr, this.previousState);
                } else if (attr == R.styleable.Carousel_carousel_nextState) {
                    this.nextState = a.getResourceId(attr, this.nextState);
                } else if (attr == R.styleable.Carousel_carousel_touchUp_dampeningFactor) {
                    this.dampening = a.getFloat(attr, this.dampening);
                } else if (attr == R.styleable.Carousel_carousel_touchUpMode) {
                    this.touchUpMode = a.getInt(attr, this.touchUpMode);
                } else if (attr == R.styleable.Carousel_carousel_touchUp_velocityThreshold) {
                    this.velocityThreshold = a.getFloat(attr, this.velocityThreshold);
                } else if (attr == R.styleable.Carousel_carousel_infinite) {
                    this.infiniteCarousel = a.getBoolean(attr, this.infiniteCarousel);
                }
            }
            a.recycle();
        }
    }

    public void setAdapter(Adapter adapter) {
        this.mAdapter = adapter;
    }

    public int getCount() {
        Adapter adapter = this.mAdapter;
        if (adapter != null) {
            return adapter.count();
        }
        return 0;
    }

    public int getCurrentIndex() {
        return this.mIndex;
    }

    public void transitionToIndex(int index, int delay) {
        this.mTargetIndex = Math.max(0, Math.min(getCount() - 1, index));
        int max = Math.max(0, delay);
        this.mAnimateTargetDelay = max;
        this.mMotionLayout.setTransitionDuration(max);
        if (index < this.mIndex) {
            this.mMotionLayout.transitionToState(this.previousState, this.mAnimateTargetDelay);
        } else {
            this.mMotionLayout.transitionToState(this.nextState, this.mAnimateTargetDelay);
        }
    }

    public void jumpToIndex(int index) {
        this.mIndex = Math.max(0, Math.min(getCount() - 1, index));
        refresh();
    }

    public void refresh() {
        int count = this.mList.size();
        for (int i = 0; i < count; i++) {
            View view = this.mList.get(i);
            if (this.mAdapter.count() == 0) {
                updateViewVisibility(view, this.emptyViewBehavior);
            } else {
                updateViewVisibility(view, 0);
            }
        }
        this.mMotionLayout.rebuildScene();
        updateItems();
    }

    @Override // androidx.constraintlayout.motion.widget.MotionHelper, androidx.constraintlayout.motion.widget.MotionLayout.TransitionListener
    public void onTransitionChange(MotionLayout motionLayout, int startId, int endId, float progress) {
        this.mLastStartId = startId;
    }

    @Override // androidx.constraintlayout.motion.widget.MotionHelper, androidx.constraintlayout.motion.widget.MotionLayout.TransitionListener
    public void onTransitionCompleted(MotionLayout motionLayout, int currentId) {
        int i = this.mIndex;
        this.mPreviousIndex = i;
        if (currentId == this.nextState) {
            this.mIndex = i + 1;
        } else if (currentId == this.previousState) {
            this.mIndex = i - 1;
        }
        if (this.infiniteCarousel) {
            if (this.mIndex >= this.mAdapter.count()) {
                this.mIndex = 0;
            }
            if (this.mIndex < 0) {
                this.mIndex = this.mAdapter.count() - 1;
            }
        } else {
            if (this.mIndex >= this.mAdapter.count()) {
                this.mIndex = this.mAdapter.count() - 1;
            }
            if (this.mIndex < 0) {
                this.mIndex = 0;
            }
        }
        if (this.mPreviousIndex != this.mIndex) {
            this.mMotionLayout.post(this.mUpdateRunnable);
        }
    }

    private void enableAllTransitions(boolean enable) {
        ArrayList<MotionScene.Transition> transitions = this.mMotionLayout.getDefinedTransitions();
        Iterator<MotionScene.Transition> it = transitions.iterator();
        while (it.hasNext()) {
            MotionScene.Transition transition = it.next();
            transition.setEnabled(enable);
        }
    }

    private boolean enableTransition(int transitionID, boolean enable) {
        MotionLayout motionLayout;
        MotionScene.Transition transition;
        if (transitionID == -1 || (motionLayout = this.mMotionLayout) == null || (transition = motionLayout.getTransition(transitionID)) == null || enable == transition.isEnabled()) {
            return false;
        }
        transition.setEnabled(enable);
        return true;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.constraintlayout.widget.ConstraintHelper, android.view.View
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        if (getParent() instanceof MotionLayout) {
            MotionLayout container = (MotionLayout) getParent();
            for (int i = 0; i < this.mCount; i++) {
                int id = this.mIds[i];
                View view = container.getViewById(id);
                if (this.firstViewReference == id) {
                    this.startIndex = i;
                }
                this.mList.add(view);
            }
            this.mMotionLayout = container;
            if (this.touchUpMode == 2) {
                MotionScene.Transition forward = container.getTransition(this.forwardTransition);
                if (forward != null) {
                    forward.setOnTouchUp(5);
                }
                MotionScene.Transition backward = this.mMotionLayout.getTransition(this.backwardTransition);
                if (backward != null) {
                    backward.setOnTouchUp(5);
                }
            }
            updateItems();
        }
    }

    private boolean updateViewVisibility(View view, int visibility) {
        MotionLayout motionLayout = this.mMotionLayout;
        if (motionLayout == null) {
            return false;
        }
        boolean needsMotionSceneRebuild = false;
        int[] constraintSets = motionLayout.getConstraintSetIds();
        for (int i : constraintSets) {
            needsMotionSceneRebuild |= updateViewVisibility(i, view, visibility);
        }
        return needsMotionSceneRebuild;
    }

    private boolean updateViewVisibility(int constraintSetId, View view, int visibility) {
        ConstraintSet.Constraint constraint;
        ConstraintSet constraintSet = this.mMotionLayout.getConstraintSet(constraintSetId);
        if (constraintSet == null || (constraint = constraintSet.getConstraint(view.getId())) == null) {
            return false;
        }
        constraint.propertySet.mVisibilityMode = 1;
        view.setVisibility(visibility);
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateItems() {
        Adapter adapter = this.mAdapter;
        if (adapter == null || this.mMotionLayout == null || adapter.count() == 0) {
            return;
        }
        int viewCount = this.mList.size();
        for (int i = 0; i < viewCount; i++) {
            View view = this.mList.get(i);
            int index = (this.mIndex + i) - this.startIndex;
            if (this.infiniteCarousel) {
                if (index < 0) {
                    int i2 = this.emptyViewBehavior;
                    if (i2 != 4) {
                        updateViewVisibility(view, i2);
                    } else {
                        updateViewVisibility(view, 0);
                    }
                    if (index % this.mAdapter.count() == 0) {
                        this.mAdapter.populate(view, 0);
                    } else {
                        Adapter adapter2 = this.mAdapter;
                        adapter2.populate(view, adapter2.count() + (index % this.mAdapter.count()));
                    }
                } else if (index >= this.mAdapter.count()) {
                    if (index == this.mAdapter.count()) {
                        index = 0;
                    } else if (index > this.mAdapter.count()) {
                        index %= this.mAdapter.count();
                    }
                    int i3 = this.emptyViewBehavior;
                    if (i3 != 4) {
                        updateViewVisibility(view, i3);
                    } else {
                        updateViewVisibility(view, 0);
                    }
                    this.mAdapter.populate(view, index);
                } else {
                    updateViewVisibility(view, 0);
                    this.mAdapter.populate(view, index);
                }
            } else if (index < 0) {
                updateViewVisibility(view, this.emptyViewBehavior);
            } else if (index >= this.mAdapter.count()) {
                updateViewVisibility(view, this.emptyViewBehavior);
            } else {
                updateViewVisibility(view, 0);
                this.mAdapter.populate(view, index);
            }
        }
        int i4 = this.mTargetIndex;
        if (i4 != -1 && i4 != this.mIndex) {
            this.mMotionLayout.post(new Runnable() { // from class: androidx.constraintlayout.helper.widget.Carousel$$ExternalSyntheticLambda0
                @Override // java.lang.Runnable
                public final void run() {
                    Carousel.this.m3xc943cdea();
                }
            });
        } else if (i4 == this.mIndex) {
            this.mTargetIndex = -1;
        }
        if (this.backwardTransition == -1 || this.forwardTransition == -1) {
            Log.w(TAG, "No backward or forward transitions defined for Carousel!");
        } else if (!this.infiniteCarousel) {
            int count = this.mAdapter.count();
            if (this.mIndex == 0) {
                enableTransition(this.backwardTransition, false);
            } else {
                enableTransition(this.backwardTransition, true);
                this.mMotionLayout.setTransition(this.backwardTransition);
            }
            if (this.mIndex == count - 1) {
                enableTransition(this.forwardTransition, false);
                return;
            }
            enableTransition(this.forwardTransition, true);
            this.mMotionLayout.setTransition(this.forwardTransition);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: lambda$updateItems$0$androidx-constraintlayout-helper-widget-Carousel  reason: not valid java name */
    public /* synthetic */ void m3xc943cdea() {
        this.mMotionLayout.setTransitionDuration(this.mAnimateTargetDelay);
        if (this.mTargetIndex < this.mIndex) {
            this.mMotionLayout.transitionToState(this.previousState, this.mAnimateTargetDelay);
        } else {
            this.mMotionLayout.transitionToState(this.nextState, this.mAnimateTargetDelay);
        }
    }
}
