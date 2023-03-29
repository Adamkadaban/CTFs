package androidx.constraintlayout.motion.widget;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.util.Log;
import android.util.SparseArray;
import android.util.SparseIntArray;
import android.util.TypedValue;
import android.util.Xml;
import android.view.MotionEvent;
import android.view.View;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.AnimationUtils;
import android.view.animation.AnticipateInterpolator;
import android.view.animation.BounceInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.Interpolator;
import android.view.animation.OvershootInterpolator;
import androidx.constraintlayout.core.motion.utils.Easing;
import androidx.constraintlayout.core.motion.utils.TypedValues;
import androidx.constraintlayout.motion.widget.MotionLayout;
import androidx.constraintlayout.widget.ConstraintSet;
import androidx.constraintlayout.widget.R;
import androidx.constraintlayout.widget.StateSet;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
/* loaded from: classes.dex */
public class MotionScene {
    static final int ANTICIPATE = 6;
    static final int BOUNCE = 4;
    private static final String CONSTRAINTSET_TAG = "ConstraintSet";
    private static final boolean DEBUG = false;
    static final int EASE_IN = 1;
    static final int EASE_IN_OUT = 0;
    static final int EASE_OUT = 2;
    private static final String INCLUDE_TAG = "include";
    private static final String INCLUDE_TAG_UC = "Include";
    private static final int INTERPOLATOR_REFERENCE_ID = -2;
    private static final String KEYFRAMESET_TAG = "KeyFrameSet";
    public static final int LAYOUT_CALL_MEASURE = 2;
    public static final int LAYOUT_HONOR_REQUEST = 1;
    public static final int LAYOUT_IGNORE_REQUEST = 0;
    static final int LINEAR = 3;
    private static final int MIN_DURATION = 8;
    private static final String MOTIONSCENE_TAG = "MotionScene";
    private static final String ONCLICK_TAG = "OnClick";
    private static final String ONSWIPE_TAG = "OnSwipe";
    static final int OVERSHOOT = 5;
    private static final int SPLINE_STRING = -1;
    private static final String STATESET_TAG = "StateSet";
    private static final String TAG = "MotionScene";
    static final int TRANSITION_BACKWARD = 0;
    static final int TRANSITION_FORWARD = 1;
    private static final String TRANSITION_TAG = "Transition";
    public static final int UNSET = -1;
    private static final String VIEW_TRANSITION = "ViewTransition";
    private MotionEvent mLastTouchDown;
    float mLastTouchX;
    float mLastTouchY;
    private final MotionLayout mMotionLayout;
    private boolean mRtl;
    private MotionLayout.MotionTracker mVelocityTracker;
    final ViewTransitionController mViewTransitionController;
    StateSet mStateSet = null;
    Transition mCurrentTransition = null;
    private boolean mDisableAutoTransition = false;
    private ArrayList<Transition> mTransitionList = new ArrayList<>();
    private Transition mDefaultTransition = null;
    private ArrayList<Transition> mAbstractTransitionList = new ArrayList<>();
    private SparseArray<ConstraintSet> mConstraintSetMap = new SparseArray<>();
    private HashMap<String, Integer> mConstraintSetIdMap = new HashMap<>();
    private SparseIntArray mDeriveMap = new SparseIntArray();
    private boolean DEBUG_DESKTOP = false;
    private int mDefaultDuration = 400;
    private int mLayoutDuringTransition = 0;
    private boolean mIgnoreTouch = false;
    private boolean mMotionOutsideRegion = false;

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setTransition(int beginId, int endId) {
        int start = beginId;
        int end = endId;
        StateSet stateSet = this.mStateSet;
        if (stateSet != null) {
            int tmp = stateSet.stateGetConstraintID(beginId, -1, -1);
            if (tmp != -1) {
                start = tmp;
            }
            int tmp2 = this.mStateSet.stateGetConstraintID(endId, -1, -1);
            if (tmp2 != -1) {
                end = tmp2;
            }
        }
        Transition transition = this.mCurrentTransition;
        if (transition != null && transition.mConstraintSetEnd == endId && this.mCurrentTransition.mConstraintSetStart == beginId) {
            return;
        }
        Iterator<Transition> it = this.mTransitionList.iterator();
        while (it.hasNext()) {
            Transition transition2 = it.next();
            if ((transition2.mConstraintSetEnd == end && transition2.mConstraintSetStart == start) || (transition2.mConstraintSetEnd == endId && transition2.mConstraintSetStart == beginId)) {
                this.mCurrentTransition = transition2;
                if (transition2 == null || transition2.mTouchResponse == null) {
                    return;
                }
                this.mCurrentTransition.mTouchResponse.setRTL(this.mRtl);
                return;
            }
        }
        Transition matchTransition = this.mDefaultTransition;
        Iterator<Transition> it2 = this.mAbstractTransitionList.iterator();
        while (it2.hasNext()) {
            Transition transition3 = it2.next();
            if (transition3.mConstraintSetEnd == endId) {
                matchTransition = transition3;
            }
        }
        Transition t = new Transition(this, matchTransition);
        t.mConstraintSetStart = start;
        t.mConstraintSetEnd = end;
        if (start != -1) {
            this.mTransitionList.add(t);
        }
        this.mCurrentTransition = t;
    }

    public void addTransition(Transition transition) {
        int index = getIndex(transition);
        if (index == -1) {
            this.mTransitionList.add(transition);
        } else {
            this.mTransitionList.set(index, transition);
        }
    }

    public void removeTransition(Transition transition) {
        int index = getIndex(transition);
        if (index != -1) {
            this.mTransitionList.remove(index);
        }
    }

    private int getIndex(Transition transition) {
        int id = transition.mId;
        if (id == -1) {
            throw new IllegalArgumentException("The transition must have an id");
        }
        for (int index = 0; index < this.mTransitionList.size(); index++) {
            if (this.mTransitionList.get(index).mId == id) {
                return index;
            }
        }
        return -1;
    }

    public boolean validateLayout(MotionLayout layout) {
        return layout == this.mMotionLayout && layout.mScene == this;
    }

    public void setTransition(Transition transition) {
        this.mCurrentTransition = transition;
        if (transition == null || transition.mTouchResponse == null) {
            return;
        }
        this.mCurrentTransition.mTouchResponse.setRTL(this.mRtl);
    }

    private int getRealID(int stateId) {
        int tmp;
        StateSet stateSet = this.mStateSet;
        if (stateSet != null && (tmp = stateSet.stateGetConstraintID(stateId, -1, -1)) != -1) {
            return tmp;
        }
        return stateId;
    }

    public List<Transition> getTransitionsWithState(int stateId) {
        int stateId2 = getRealID(stateId);
        ArrayList<Transition> ret = new ArrayList<>();
        Iterator<Transition> it = this.mTransitionList.iterator();
        while (it.hasNext()) {
            Transition transition = it.next();
            if (transition.mConstraintSetStart == stateId2 || transition.mConstraintSetEnd == stateId2) {
                ret.add(transition);
            }
        }
        return ret;
    }

    public void addOnClickListeners(MotionLayout motionLayout, int currentState) {
        Iterator<Transition> it = this.mTransitionList.iterator();
        while (it.hasNext()) {
            Transition transition = it.next();
            if (transition.mOnClicks.size() > 0) {
                Iterator it2 = transition.mOnClicks.iterator();
                while (it2.hasNext()) {
                    Transition.TransitionOnClick onClick = (Transition.TransitionOnClick) it2.next();
                    onClick.removeOnClickListeners(motionLayout);
                }
            }
        }
        Iterator<Transition> it3 = this.mAbstractTransitionList.iterator();
        while (it3.hasNext()) {
            Transition transition2 = it3.next();
            if (transition2.mOnClicks.size() > 0) {
                Iterator it4 = transition2.mOnClicks.iterator();
                while (it4.hasNext()) {
                    Transition.TransitionOnClick onClick2 = (Transition.TransitionOnClick) it4.next();
                    onClick2.removeOnClickListeners(motionLayout);
                }
            }
        }
        Iterator<Transition> it5 = this.mTransitionList.iterator();
        while (it5.hasNext()) {
            Transition transition3 = it5.next();
            if (transition3.mOnClicks.size() > 0) {
                Iterator it6 = transition3.mOnClicks.iterator();
                while (it6.hasNext()) {
                    Transition.TransitionOnClick onClick3 = (Transition.TransitionOnClick) it6.next();
                    onClick3.addOnClickListeners(motionLayout, currentState, transition3);
                }
            }
        }
        Iterator<Transition> it7 = this.mAbstractTransitionList.iterator();
        while (it7.hasNext()) {
            Transition transition4 = it7.next();
            if (transition4.mOnClicks.size() > 0) {
                Iterator it8 = transition4.mOnClicks.iterator();
                while (it8.hasNext()) {
                    Transition.TransitionOnClick onClick4 = (Transition.TransitionOnClick) it8.next();
                    onClick4.addOnClickListeners(motionLayout, currentState, transition4);
                }
            }
        }
    }

    public Transition bestTransitionFor(int currentState, float dx, float dy, MotionEvent lastTouchDown) {
        RectF cache;
        Iterator<Transition> it;
        float val;
        float val2;
        float f = dx;
        float f2 = dy;
        if (currentState != -1) {
            List<Transition> candidates = getTransitionsWithState(currentState);
            float max = 0.0f;
            Transition best = null;
            RectF cache2 = new RectF();
            Iterator<Transition> it2 = candidates.iterator();
            while (it2.hasNext()) {
                Transition transition = it2.next();
                if (!transition.mDisable) {
                    if (transition.mTouchResponse != null) {
                        transition.mTouchResponse.setRTL(this.mRtl);
                        RectF region = transition.mTouchResponse.getTouchRegion(this.mMotionLayout, cache2);
                        if (region == null || lastTouchDown == null || region.contains(lastTouchDown.getX(), lastTouchDown.getY())) {
                            RectF region2 = transition.mTouchResponse.getLimitBoundsTo(this.mMotionLayout, cache2);
                            if (region2 == null || lastTouchDown == null || region2.contains(lastTouchDown.getX(), lastTouchDown.getY())) {
                                float val3 = transition.mTouchResponse.dot(f, f2);
                                if (!transition.mTouchResponse.mIsRotateMode || lastTouchDown == null) {
                                    cache = cache2;
                                    it = it2;
                                    val = val3;
                                } else {
                                    float startX = lastTouchDown.getX() - transition.mTouchResponse.mRotateCenterX;
                                    float startY = lastTouchDown.getY() - transition.mTouchResponse.mRotateCenterY;
                                    float endX = f + startX;
                                    float endY = f2 + startY;
                                    cache = cache2;
                                    it = it2;
                                    double endAngle = Math.atan2(endY, endX);
                                    double startAngle = Math.atan2(startX, startY);
                                    val = 10.0f * ((float) (endAngle - startAngle));
                                }
                                if (transition.mConstraintSetEnd == currentState) {
                                    val2 = val * (-1.0f);
                                } else {
                                    val2 = val * 1.1f;
                                }
                                if (val2 > max) {
                                    float max2 = val2;
                                    max = max2;
                                    best = transition;
                                }
                            }
                        }
                    } else {
                        cache = cache2;
                        it = it2;
                    }
                    f = dx;
                    f2 = dy;
                    cache2 = cache;
                    it2 = it;
                }
            }
            return best;
        }
        return this.mCurrentTransition;
    }

    public ArrayList<Transition> getDefinedTransitions() {
        return this.mTransitionList;
    }

    public Transition getTransitionById(int id) {
        Iterator<Transition> it = this.mTransitionList.iterator();
        while (it.hasNext()) {
            Transition transition = it.next();
            if (transition.mId == id) {
                return transition;
            }
        }
        return null;
    }

    public int[] getConstraintSetIds() {
        int[] ids = new int[this.mConstraintSetMap.size()];
        for (int i = 0; i < ids.length; i++) {
            ids[i] = this.mConstraintSetMap.keyAt(i);
        }
        return ids;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean autoTransition(MotionLayout motionLayout, int currentState) {
        Transition transition;
        if (isProcessingTouch() || this.mDisableAutoTransition) {
            return false;
        }
        Iterator<Transition> it = this.mTransitionList.iterator();
        while (it.hasNext()) {
            Transition transition2 = it.next();
            if (transition2.mAutoTransition != 0 && ((transition = this.mCurrentTransition) != transition2 || !transition.isTransitionFlag(2))) {
                if (currentState == transition2.mConstraintSetStart && (transition2.mAutoTransition == 4 || transition2.mAutoTransition == 2)) {
                    motionLayout.setState(MotionLayout.TransitionState.FINISHED);
                    motionLayout.setTransition(transition2);
                    if (transition2.mAutoTransition == 4) {
                        motionLayout.transitionToEnd();
                        motionLayout.setState(MotionLayout.TransitionState.SETUP);
                        motionLayout.setState(MotionLayout.TransitionState.MOVING);
                    } else {
                        motionLayout.setProgress(1.0f);
                        motionLayout.evaluate(true);
                        motionLayout.setState(MotionLayout.TransitionState.SETUP);
                        motionLayout.setState(MotionLayout.TransitionState.MOVING);
                        motionLayout.setState(MotionLayout.TransitionState.FINISHED);
                        motionLayout.onNewStateAttachHandlers();
                    }
                    return true;
                } else if (currentState == transition2.mConstraintSetEnd && (transition2.mAutoTransition == 3 || transition2.mAutoTransition == 1)) {
                    motionLayout.setState(MotionLayout.TransitionState.FINISHED);
                    motionLayout.setTransition(transition2);
                    if (transition2.mAutoTransition == 3) {
                        motionLayout.transitionToStart();
                        motionLayout.setState(MotionLayout.TransitionState.SETUP);
                        motionLayout.setState(MotionLayout.TransitionState.MOVING);
                    } else {
                        motionLayout.setProgress(0.0f);
                        motionLayout.evaluate(true);
                        motionLayout.setState(MotionLayout.TransitionState.SETUP);
                        motionLayout.setState(MotionLayout.TransitionState.MOVING);
                        motionLayout.setState(MotionLayout.TransitionState.FINISHED);
                        motionLayout.onNewStateAttachHandlers();
                    }
                    return true;
                }
            }
        }
        return false;
    }

    private boolean isProcessingTouch() {
        return this.mVelocityTracker != null;
    }

    public void setRtl(boolean rtl) {
        this.mRtl = rtl;
        Transition transition = this.mCurrentTransition;
        if (transition == null || transition.mTouchResponse == null) {
            return;
        }
        this.mCurrentTransition.mTouchResponse.setRTL(this.mRtl);
    }

    public void viewTransition(int id, View... view) {
        this.mViewTransitionController.viewTransition(id, view);
    }

    public void enableViewTransition(int id, boolean enable) {
        this.mViewTransitionController.enableViewTransition(id, enable);
    }

    public boolean isViewTransitionEnabled(int id) {
        return this.mViewTransitionController.isViewTransitionEnabled(id);
    }

    public boolean applyViewTransition(int viewTransitionId, MotionController motionController) {
        return this.mViewTransitionController.applyViewTransition(viewTransitionId, motionController);
    }

    /* loaded from: classes.dex */
    public static class Transition {
        public static final int AUTO_ANIMATE_TO_END = 4;
        public static final int AUTO_ANIMATE_TO_START = 3;
        public static final int AUTO_JUMP_TO_END = 2;
        public static final int AUTO_JUMP_TO_START = 1;
        public static final int AUTO_NONE = 0;
        public static final int INTERPOLATE_ANTICIPATE = 6;
        public static final int INTERPOLATE_BOUNCE = 4;
        public static final int INTERPOLATE_EASE_IN = 1;
        public static final int INTERPOLATE_EASE_IN_OUT = 0;
        public static final int INTERPOLATE_EASE_OUT = 2;
        public static final int INTERPOLATE_LINEAR = 3;
        public static final int INTERPOLATE_OVERSHOOT = 5;
        public static final int INTERPOLATE_REFERENCE_ID = -2;
        public static final int INTERPOLATE_SPLINE_STRING = -1;
        static final int TRANSITION_FLAG_FIRST_DRAW = 1;
        static final int TRANSITION_FLAG_INTERCEPT_TOUCH = 4;
        static final int TRANSITION_FLAG_INTRA_AUTO = 2;
        private int mAutoTransition;
        private int mConstraintSetEnd;
        private int mConstraintSetStart;
        private int mDefaultInterpolator;
        private int mDefaultInterpolatorID;
        private String mDefaultInterpolatorString;
        private boolean mDisable;
        private int mDuration;
        private int mId;
        private boolean mIsAbstract;
        private ArrayList<KeyFrames> mKeyFramesList;
        private int mLayoutDuringTransition;
        private final MotionScene mMotionScene;
        private ArrayList<TransitionOnClick> mOnClicks;
        private int mPathMotionArc;
        private float mStagger;
        private TouchResponse mTouchResponse;
        private int mTransitionFlags;

        public void setOnSwipe(OnSwipe onSwipe) {
            this.mTouchResponse = onSwipe == null ? null : new TouchResponse(this.mMotionScene.mMotionLayout, onSwipe);
        }

        public void addOnClick(int id, int action) {
            Iterator<TransitionOnClick> it = this.mOnClicks.iterator();
            while (it.hasNext()) {
                TransitionOnClick onClick = it.next();
                if (onClick.mTargetId == id) {
                    onClick.mMode = action;
                    return;
                }
            }
            TransitionOnClick click = new TransitionOnClick(this, id, action);
            this.mOnClicks.add(click);
        }

        public void removeOnClick(int id) {
            TransitionOnClick toRemove = null;
            Iterator<TransitionOnClick> it = this.mOnClicks.iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                TransitionOnClick onClick = it.next();
                if (onClick.mTargetId == id) {
                    toRemove = onClick;
                    break;
                }
            }
            if (toRemove != null) {
                this.mOnClicks.remove(toRemove);
            }
        }

        public int getLayoutDuringTransition() {
            return this.mLayoutDuringTransition;
        }

        public void setLayoutDuringTransition(int mode) {
            this.mLayoutDuringTransition = mode;
        }

        public void addOnClick(Context context, XmlPullParser parser) {
            this.mOnClicks.add(new TransitionOnClick(context, this, parser));
        }

        public void setAutoTransition(int type) {
            this.mAutoTransition = type;
        }

        public int getAutoTransition() {
            return this.mAutoTransition;
        }

        public int getId() {
            return this.mId;
        }

        public int getEndConstraintSetId() {
            return this.mConstraintSetEnd;
        }

        public int getStartConstraintSetId() {
            return this.mConstraintSetStart;
        }

        public void setDuration(int duration) {
            this.mDuration = Math.max(duration, 8);
        }

        public int getDuration() {
            return this.mDuration;
        }

        public float getStagger() {
            return this.mStagger;
        }

        public List<KeyFrames> getKeyFrameList() {
            return this.mKeyFramesList;
        }

        public void addKeyFrame(KeyFrames keyFrames) {
            this.mKeyFramesList.add(keyFrames);
        }

        public List<TransitionOnClick> getOnClickList() {
            return this.mOnClicks;
        }

        public TouchResponse getTouchResponse() {
            return this.mTouchResponse;
        }

        public void setStagger(float stagger) {
            this.mStagger = stagger;
        }

        public void setPathMotionArc(int arcMode) {
            this.mPathMotionArc = arcMode;
        }

        public int getPathMotionArc() {
            return this.mPathMotionArc;
        }

        public boolean isEnabled() {
            return !this.mDisable;
        }

        public void setEnable(boolean enable) {
            setEnabled(enable);
        }

        public void setEnabled(boolean enable) {
            this.mDisable = !enable;
        }

        public String debugString(Context context) {
            String ret;
            if (this.mConstraintSetStart == -1) {
                ret = "null";
            } else {
                ret = context.getResources().getResourceEntryName(this.mConstraintSetStart);
            }
            if (this.mConstraintSetEnd == -1) {
                return ret + " -> null";
            }
            return ret + " -> " + context.getResources().getResourceEntryName(this.mConstraintSetEnd);
        }

        public boolean isTransitionFlag(int flag) {
            return (this.mTransitionFlags & flag) != 0;
        }

        public void setTransitionFlag(int flag) {
            this.mTransitionFlags = flag;
        }

        public void setOnTouchUp(int touchUpMode) {
            TouchResponse touchResponse = getTouchResponse();
            if (touchResponse != null) {
                touchResponse.setTouchUpMode(touchUpMode);
            }
        }

        /* loaded from: classes.dex */
        public static class TransitionOnClick implements View.OnClickListener {
            public static final int ANIM_TOGGLE = 17;
            public static final int ANIM_TO_END = 1;
            public static final int ANIM_TO_START = 16;
            public static final int JUMP_TO_END = 256;
            public static final int JUMP_TO_START = 4096;
            int mMode;
            int mTargetId;
            private final Transition mTransition;

            public TransitionOnClick(Context context, Transition transition, XmlPullParser parser) {
                this.mTargetId = -1;
                this.mMode = 17;
                this.mTransition = transition;
                TypedArray a = context.obtainStyledAttributes(Xml.asAttributeSet(parser), R.styleable.OnClick);
                int N = a.getIndexCount();
                for (int i = 0; i < N; i++) {
                    int attr = a.getIndex(i);
                    if (attr == R.styleable.OnClick_targetId) {
                        this.mTargetId = a.getResourceId(attr, this.mTargetId);
                    } else if (attr == R.styleable.OnClick_clickAction) {
                        this.mMode = a.getInt(attr, this.mMode);
                    }
                }
                a.recycle();
            }

            public TransitionOnClick(Transition transition, int id, int action) {
                this.mTargetId = -1;
                this.mMode = 17;
                this.mTransition = transition;
                this.mTargetId = id;
                this.mMode = action;
            }

            public void addOnClickListeners(MotionLayout motionLayout, int currentState, Transition transition) {
                int i = this.mTargetId;
                View v = i == -1 ? motionLayout : motionLayout.findViewById(i);
                if (v != null) {
                    int start = transition.mConstraintSetStart;
                    int end = transition.mConstraintSetEnd;
                    if (start == -1) {
                        v.setOnClickListener(this);
                        return;
                    }
                    int i2 = this.mMode;
                    boolean z = false;
                    boolean listen = (i2 & 1) != 0 && currentState == start;
                    boolean listen2 = listen | ((i2 & 256) != 0 && currentState == start) | ((i2 & 1) != 0 && currentState == start) | ((i2 & 16) != 0 && currentState == end);
                    if ((i2 & 4096) != 0 && currentState == end) {
                        z = true;
                    }
                    if (listen2 | z) {
                        v.setOnClickListener(this);
                        return;
                    }
                    return;
                }
                Log.e(TypedValues.MotionScene.NAME, "OnClick could not find id " + this.mTargetId);
            }

            public void removeOnClickListeners(MotionLayout motionLayout) {
                int i = this.mTargetId;
                if (i == -1) {
                    return;
                }
                View v = motionLayout.findViewById(i);
                if (v == null) {
                    Log.e(TypedValues.MotionScene.NAME, " (*)  could not find id " + this.mTargetId);
                    return;
                }
                v.setOnClickListener(null);
            }

            boolean isTransitionViable(Transition current, MotionLayout tl) {
                Transition transition = this.mTransition;
                if (transition == current) {
                    return true;
                }
                int dest = transition.mConstraintSetEnd;
                int from = this.mTransition.mConstraintSetStart;
                return from == -1 ? tl.mCurrentState != dest : tl.mCurrentState == from || tl.mCurrentState == dest;
            }

            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                MotionLayout tl = this.mTransition.mMotionScene.mMotionLayout;
                if (tl.isInteractionEnabled()) {
                    if (this.mTransition.mConstraintSetStart != -1) {
                        Transition current = this.mTransition.mMotionScene.mCurrentTransition;
                        int i = this.mMode;
                        boolean bidirectional = false;
                        boolean forward = ((i & 1) == 0 && (i & 256) == 0) ? false : true;
                        boolean backward = ((i & 16) == 0 && (i & 4096) == 0) ? false : true;
                        if (forward && backward) {
                            bidirectional = true;
                        }
                        if (bidirectional) {
                            Transition transition = this.mTransition.mMotionScene.mCurrentTransition;
                            Transition transition2 = this.mTransition;
                            if (transition != transition2) {
                                tl.setTransition(transition2);
                            }
                            if (tl.getCurrentState() == tl.getEndState() || tl.getProgress() > 0.5f) {
                                forward = false;
                            } else {
                                backward = false;
                            }
                        }
                        if (isTransitionViable(current, tl)) {
                            if (forward && (1 & this.mMode) != 0) {
                                tl.setTransition(this.mTransition);
                                tl.transitionToEnd();
                                return;
                            } else if (backward && (this.mMode & 16) != 0) {
                                tl.setTransition(this.mTransition);
                                tl.transitionToStart();
                                return;
                            } else if (forward && (this.mMode & 256) != 0) {
                                tl.setTransition(this.mTransition);
                                tl.setProgress(1.0f);
                                return;
                            } else if (backward && (this.mMode & 4096) != 0) {
                                tl.setTransition(this.mTransition);
                                tl.setProgress(0.0f);
                                return;
                            } else {
                                return;
                            }
                        }
                        return;
                    }
                    int currentState = tl.getCurrentState();
                    if (currentState == -1) {
                        tl.transitionToState(this.mTransition.mConstraintSetEnd);
                        return;
                    }
                    Transition t = new Transition(this.mTransition.mMotionScene, this.mTransition);
                    t.mConstraintSetStart = currentState;
                    t.mConstraintSetEnd = this.mTransition.mConstraintSetEnd;
                    tl.setTransition(t);
                    tl.transitionToEnd();
                }
            }
        }

        Transition(MotionScene motionScene, Transition global) {
            this.mId = -1;
            this.mIsAbstract = false;
            this.mConstraintSetEnd = -1;
            this.mConstraintSetStart = -1;
            this.mDefaultInterpolator = 0;
            this.mDefaultInterpolatorString = null;
            this.mDefaultInterpolatorID = -1;
            this.mDuration = 400;
            this.mStagger = 0.0f;
            this.mKeyFramesList = new ArrayList<>();
            this.mTouchResponse = null;
            this.mOnClicks = new ArrayList<>();
            this.mAutoTransition = 0;
            this.mDisable = false;
            this.mPathMotionArc = -1;
            this.mLayoutDuringTransition = 0;
            this.mTransitionFlags = 0;
            this.mMotionScene = motionScene;
            this.mDuration = motionScene.mDefaultDuration;
            if (global != null) {
                this.mPathMotionArc = global.mPathMotionArc;
                this.mDefaultInterpolator = global.mDefaultInterpolator;
                this.mDefaultInterpolatorString = global.mDefaultInterpolatorString;
                this.mDefaultInterpolatorID = global.mDefaultInterpolatorID;
                this.mDuration = global.mDuration;
                this.mKeyFramesList = global.mKeyFramesList;
                this.mStagger = global.mStagger;
                this.mLayoutDuringTransition = global.mLayoutDuringTransition;
            }
        }

        public Transition(int id, MotionScene motionScene, int constraintSetStartId, int constraintSetEndId) {
            this.mId = -1;
            this.mIsAbstract = false;
            this.mConstraintSetEnd = -1;
            this.mConstraintSetStart = -1;
            this.mDefaultInterpolator = 0;
            this.mDefaultInterpolatorString = null;
            this.mDefaultInterpolatorID = -1;
            this.mDuration = 400;
            this.mStagger = 0.0f;
            this.mKeyFramesList = new ArrayList<>();
            this.mTouchResponse = null;
            this.mOnClicks = new ArrayList<>();
            this.mAutoTransition = 0;
            this.mDisable = false;
            this.mPathMotionArc = -1;
            this.mLayoutDuringTransition = 0;
            this.mTransitionFlags = 0;
            this.mId = id;
            this.mMotionScene = motionScene;
            this.mConstraintSetStart = constraintSetStartId;
            this.mConstraintSetEnd = constraintSetEndId;
            this.mDuration = motionScene.mDefaultDuration;
            this.mLayoutDuringTransition = motionScene.mLayoutDuringTransition;
        }

        Transition(MotionScene motionScene, Context context, XmlPullParser parser) {
            this.mId = -1;
            this.mIsAbstract = false;
            this.mConstraintSetEnd = -1;
            this.mConstraintSetStart = -1;
            this.mDefaultInterpolator = 0;
            this.mDefaultInterpolatorString = null;
            this.mDefaultInterpolatorID = -1;
            this.mDuration = 400;
            this.mStagger = 0.0f;
            this.mKeyFramesList = new ArrayList<>();
            this.mTouchResponse = null;
            this.mOnClicks = new ArrayList<>();
            this.mAutoTransition = 0;
            this.mDisable = false;
            this.mPathMotionArc = -1;
            this.mLayoutDuringTransition = 0;
            this.mTransitionFlags = 0;
            this.mDuration = motionScene.mDefaultDuration;
            this.mLayoutDuringTransition = motionScene.mLayoutDuringTransition;
            this.mMotionScene = motionScene;
            fillFromAttributeList(motionScene, context, Xml.asAttributeSet(parser));
        }

        public void setInterpolatorInfo(int interpolator, String interpolatorString, int interpolatorID) {
            this.mDefaultInterpolator = interpolator;
            this.mDefaultInterpolatorString = interpolatorString;
            this.mDefaultInterpolatorID = interpolatorID;
        }

        private void fillFromAttributeList(MotionScene motionScene, Context context, AttributeSet attrs) {
            TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.Transition);
            fill(motionScene, context, a);
            a.recycle();
        }

        private void fill(MotionScene motionScene, Context context, TypedArray a) {
            int N = a.getIndexCount();
            for (int i = 0; i < N; i++) {
                int attr = a.getIndex(i);
                if (attr == R.styleable.Transition_constraintSetEnd) {
                    this.mConstraintSetEnd = a.getResourceId(attr, -1);
                    String type = context.getResources().getResourceTypeName(this.mConstraintSetEnd);
                    if ("layout".equals(type)) {
                        ConstraintSet cSet = new ConstraintSet();
                        cSet.load(context, this.mConstraintSetEnd);
                        motionScene.mConstraintSetMap.append(this.mConstraintSetEnd, cSet);
                    } else if ("xml".equals(type)) {
                        int id = motionScene.parseInclude(context, this.mConstraintSetEnd);
                        this.mConstraintSetEnd = id;
                    }
                } else if (attr == R.styleable.Transition_constraintSetStart) {
                    this.mConstraintSetStart = a.getResourceId(attr, this.mConstraintSetStart);
                    String type2 = context.getResources().getResourceTypeName(this.mConstraintSetStart);
                    if ("layout".equals(type2)) {
                        ConstraintSet cSet2 = new ConstraintSet();
                        cSet2.load(context, this.mConstraintSetStart);
                        motionScene.mConstraintSetMap.append(this.mConstraintSetStart, cSet2);
                    } else if ("xml".equals(type2)) {
                        int id2 = motionScene.parseInclude(context, this.mConstraintSetStart);
                        this.mConstraintSetStart = id2;
                    }
                } else if (attr == R.styleable.Transition_motionInterpolator) {
                    TypedValue type3 = a.peekValue(attr);
                    if (type3.type == 1) {
                        int resourceId = a.getResourceId(attr, -1);
                        this.mDefaultInterpolatorID = resourceId;
                        if (resourceId != -1) {
                            this.mDefaultInterpolator = -2;
                        }
                    } else if (type3.type == 3) {
                        String string = a.getString(attr);
                        this.mDefaultInterpolatorString = string;
                        if (string != null) {
                            if (string.indexOf("/") > 0) {
                                this.mDefaultInterpolatorID = a.getResourceId(attr, -1);
                                this.mDefaultInterpolator = -2;
                            } else {
                                this.mDefaultInterpolator = -1;
                            }
                        }
                    } else {
                        this.mDefaultInterpolator = a.getInteger(attr, this.mDefaultInterpolator);
                    }
                } else if (attr == R.styleable.Transition_duration) {
                    int i2 = a.getInt(attr, this.mDuration);
                    this.mDuration = i2;
                    if (i2 < 8) {
                        this.mDuration = 8;
                    }
                } else if (attr == R.styleable.Transition_staggered) {
                    this.mStagger = a.getFloat(attr, this.mStagger);
                } else if (attr == R.styleable.Transition_autoTransition) {
                    this.mAutoTransition = a.getInteger(attr, this.mAutoTransition);
                } else if (attr == R.styleable.Transition_android_id) {
                    this.mId = a.getResourceId(attr, this.mId);
                } else if (attr == R.styleable.Transition_transitionDisable) {
                    this.mDisable = a.getBoolean(attr, this.mDisable);
                } else if (attr == R.styleable.Transition_pathMotionArc) {
                    this.mPathMotionArc = a.getInteger(attr, -1);
                } else if (attr == R.styleable.Transition_layoutDuringTransition) {
                    this.mLayoutDuringTransition = a.getInteger(attr, 0);
                } else if (attr == R.styleable.Transition_transitionFlags) {
                    this.mTransitionFlags = a.getInteger(attr, 0);
                }
            }
            int i3 = this.mConstraintSetStart;
            if (i3 == -1) {
                this.mIsAbstract = true;
            }
        }
    }

    public MotionScene(MotionLayout layout) {
        this.mMotionLayout = layout;
        this.mViewTransitionController = new ViewTransitionController(layout);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public MotionScene(Context context, MotionLayout layout, int resourceID) {
        this.mMotionLayout = layout;
        this.mViewTransitionController = new ViewTransitionController(layout);
        load(context, resourceID);
        this.mConstraintSetMap.put(R.id.motion_base, new ConstraintSet());
        this.mConstraintSetIdMap.put("motion_base", Integer.valueOf(R.id.motion_base));
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    private void load(Context context, int resourceId) {
        Resources res = context.getResources();
        XmlPullParser parser = res.getXml(resourceId);
        Transition transition = null;
        try {
            int eventType = parser.getEventType();
            while (true) {
                char c = 1;
                if (eventType != 1) {
                    switch (eventType) {
                        case 0:
                            parser.getName();
                            break;
                        case 2:
                            String tagName = parser.getName();
                            if (this.DEBUG_DESKTOP) {
                                PrintStream printStream = System.out;
                                printStream.println("parsing = " + tagName);
                            }
                            switch (tagName.hashCode()) {
                                case -1349929691:
                                    if (tagName.equals(CONSTRAINTSET_TAG)) {
                                        c = 5;
                                        break;
                                    }
                                    c = 65535;
                                    break;
                                case -1239391468:
                                    if (tagName.equals("KeyFrameSet")) {
                                        c = '\b';
                                        break;
                                    }
                                    c = 65535;
                                    break;
                                case -687739768:
                                    if (tagName.equals(INCLUDE_TAG_UC)) {
                                        c = 7;
                                        break;
                                    }
                                    c = 65535;
                                    break;
                                case 61998586:
                                    if (tagName.equals("ViewTransition")) {
                                        c = '\t';
                                        break;
                                    }
                                    c = 65535;
                                    break;
                                case 269306229:
                                    if (tagName.equals(TRANSITION_TAG)) {
                                        break;
                                    }
                                    c = 65535;
                                    break;
                                case 312750793:
                                    if (tagName.equals(ONCLICK_TAG)) {
                                        c = 3;
                                        break;
                                    }
                                    c = 65535;
                                    break;
                                case 327855227:
                                    if (tagName.equals(ONSWIPE_TAG)) {
                                        c = 2;
                                        break;
                                    }
                                    c = 65535;
                                    break;
                                case 793277014:
                                    if (tagName.equals(TypedValues.MotionScene.NAME)) {
                                        c = 0;
                                        break;
                                    }
                                    c = 65535;
                                    break;
                                case 1382829617:
                                    if (tagName.equals(STATESET_TAG)) {
                                        c = 4;
                                        break;
                                    }
                                    c = 65535;
                                    break;
                                case 1942574248:
                                    if (tagName.equals(INCLUDE_TAG)) {
                                        c = 6;
                                        break;
                                    }
                                    c = 65535;
                                    break;
                                default:
                                    c = 65535;
                                    break;
                            }
                            switch (c) {
                                case 0:
                                    parseMotionSceneTags(context, parser);
                                    break;
                                case 1:
                                    ArrayList<Transition> arrayList = this.mTransitionList;
                                    Transition transition2 = new Transition(this, context, parser);
                                    transition = transition2;
                                    arrayList.add(transition2);
                                    if (this.mCurrentTransition == null && !transition.mIsAbstract) {
                                        this.mCurrentTransition = transition;
                                        if (transition.mTouchResponse != null) {
                                            this.mCurrentTransition.mTouchResponse.setRTL(this.mRtl);
                                        }
                                    }
                                    if (transition.mIsAbstract) {
                                        if (transition.mConstraintSetEnd == -1) {
                                            this.mDefaultTransition = transition;
                                        } else {
                                            this.mAbstractTransitionList.add(transition);
                                        }
                                        this.mTransitionList.remove(transition);
                                        break;
                                    }
                                    break;
                                case 2:
                                    if (transition == null) {
                                        String name = context.getResources().getResourceEntryName(resourceId);
                                        int line = parser.getLineNumber();
                                        Log.v(TypedValues.MotionScene.NAME, " OnSwipe (" + name + ".xml:" + line + ")");
                                    }
                                    if (transition != null) {
                                        transition.mTouchResponse = new TouchResponse(context, this.mMotionLayout, parser);
                                        break;
                                    }
                                    break;
                                case 3:
                                    if (transition != null) {
                                        transition.addOnClick(context, parser);
                                        break;
                                    }
                                    break;
                                case 4:
                                    this.mStateSet = new StateSet(context, parser);
                                    break;
                                case 5:
                                    parseConstraintSet(context, parser);
                                    break;
                                case 6:
                                case 7:
                                    parseInclude(context, parser);
                                    break;
                                case '\b':
                                    KeyFrames keyFrames = new KeyFrames(context, parser);
                                    if (transition != null) {
                                        transition.mKeyFramesList.add(keyFrames);
                                        break;
                                    }
                                    break;
                                case '\t':
                                    ViewTransition viewTransition = new ViewTransition(context, parser);
                                    this.mViewTransitionController.add(viewTransition);
                                    break;
                            }
                            break;
                    }
                    eventType = parser.next();
                } else {
                    return;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (XmlPullParserException e2) {
            e2.printStackTrace();
        }
    }

    private void parseMotionSceneTags(Context context, XmlPullParser parser) {
        AttributeSet attrs = Xml.asAttributeSet(parser);
        TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.MotionScene);
        int count = a.getIndexCount();
        for (int i = 0; i < count; i++) {
            int attr = a.getIndex(i);
            if (attr == R.styleable.MotionScene_defaultDuration) {
                int i2 = a.getInt(attr, this.mDefaultDuration);
                this.mDefaultDuration = i2;
                if (i2 < 8) {
                    this.mDefaultDuration = 8;
                }
            } else if (attr == R.styleable.MotionScene_layoutDuringTransition) {
                this.mLayoutDuringTransition = a.getInteger(attr, 0);
            }
        }
        a.recycle();
    }

    private int getId(Context context, String idString) {
        int id = -1;
        if (idString.contains("/")) {
            String tmp = idString.substring(idString.indexOf(47) + 1);
            id = context.getResources().getIdentifier(tmp, "id", context.getPackageName());
            if (this.DEBUG_DESKTOP) {
                PrintStream printStream = System.out;
                printStream.println("id getMap res = " + id);
            }
        }
        if (id == -1) {
            if (idString != null && idString.length() > 1) {
                int id2 = Integer.parseInt(idString.substring(1));
                return id2;
            }
            Log.e(TypedValues.MotionScene.NAME, "error in parsing id");
            return id;
        }
        return id;
    }

    private void parseInclude(Context context, XmlPullParser mainParser) {
        TypedArray a = context.obtainStyledAttributes(Xml.asAttributeSet(mainParser), R.styleable.include);
        int N = a.getIndexCount();
        for (int i = 0; i < N; i++) {
            int attr = a.getIndex(i);
            if (attr == R.styleable.include_constraintSet) {
                int resourceId = a.getResourceId(attr, -1);
                parseInclude(context, resourceId);
            }
        }
        a.recycle();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int parseInclude(Context context, int resourceId) {
        Resources res = context.getResources();
        XmlPullParser includeParser = res.getXml(resourceId);
        try {
            for (int eventType = includeParser.getEventType(); eventType != 1; eventType = includeParser.next()) {
                String tagName = includeParser.getName();
                if (2 == eventType && CONSTRAINTSET_TAG.equals(tagName)) {
                    return parseConstraintSet(context, includeParser);
                }
            }
            return -1;
        } catch (IOException e) {
            e.printStackTrace();
            return -1;
        } catch (XmlPullParserException e2) {
            e2.printStackTrace();
            return -1;
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    private int parseConstraintSet(Context context, XmlPullParser parser) {
        char c;
        char c2;
        ConstraintSet set = new ConstraintSet();
        set.setForceId(false);
        int count = parser.getAttributeCount();
        int derivedId = -1;
        int derivedId2 = -1;
        for (int i = 0; i < count; i++) {
            String name = parser.getAttributeName(i);
            String value = parser.getAttributeValue(i);
            if (this.DEBUG_DESKTOP) {
                System.out.println("id string = " + value);
            }
            switch (name.hashCode()) {
                case -1496482599:
                    if (name.equals("deriveConstraintsFrom")) {
                        c = 1;
                        break;
                    }
                    c = 65535;
                    break;
                case -1153153640:
                    if (name.equals("constraintRotate")) {
                        c = 2;
                        break;
                    }
                    c = 65535;
                    break;
                case 3355:
                    if (name.equals("id")) {
                        c = 0;
                        break;
                    }
                    c = 65535;
                    break;
                default:
                    c = 65535;
                    break;
            }
            switch (c) {
                case 0:
                    int id = getId(context, value);
                    this.mConstraintSetIdMap.put(stripID(value), Integer.valueOf(id));
                    set.mIdString = Debug.getName(context, id);
                    derivedId2 = id;
                    break;
                case 1:
                    int derivedId3 = getId(context, value);
                    derivedId = derivedId3;
                    break;
                case 2:
                    try {
                        set.mRotate = Integer.parseInt(value);
                        break;
                    } catch (NumberFormatException e) {
                        switch (value.hashCode()) {
                            case -768416914:
                                if (value.equals("x_left")) {
                                    c2 = 4;
                                    break;
                                }
                                c2 = 65535;
                                break;
                            case 3317767:
                                if (value.equals("left")) {
                                    c2 = 2;
                                    break;
                                }
                                c2 = 65535;
                                break;
                            case 3387192:
                                if (value.equals("none")) {
                                    c2 = 0;
                                    break;
                                }
                                c2 = 65535;
                                break;
                            case 108511772:
                                if (value.equals("right")) {
                                    c2 = 1;
                                    break;
                                }
                                c2 = 65535;
                                break;
                            case 1954540437:
                                if (value.equals("x_right")) {
                                    c2 = 3;
                                    break;
                                }
                                c2 = 65535;
                                break;
                            default:
                                c2 = 65535;
                                break;
                        }
                        switch (c2) {
                            case 0:
                                set.mRotate = 0;
                                continue;
                            case 1:
                                set.mRotate = 1;
                                continue;
                            case 2:
                                set.mRotate = 2;
                                continue;
                            case 3:
                                set.mRotate = 3;
                                continue;
                            case 4:
                                set.mRotate = 4;
                                continue;
                            default:
                                continue;
                        }
                    }
            }
        }
        if (derivedId2 != -1) {
            if (this.mMotionLayout.mDebugPath != 0) {
                set.setValidateOnParse(true);
            }
            set.load(context, parser);
            if (derivedId != -1) {
                this.mDeriveMap.put(derivedId2, derivedId);
            }
            this.mConstraintSetMap.put(derivedId2, set);
        }
        return derivedId2;
    }

    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
    }

    public ConstraintSet getConstraintSet(Context context, String id) {
        if (this.DEBUG_DESKTOP) {
            PrintStream printStream = System.out;
            printStream.println("id " + id);
            PrintStream printStream2 = System.out;
            printStream2.println("size " + this.mConstraintSetMap.size());
        }
        for (int i = 0; i < this.mConstraintSetMap.size(); i++) {
            int key = this.mConstraintSetMap.keyAt(i);
            String IdAsString = context.getResources().getResourceName(key);
            if (this.DEBUG_DESKTOP) {
                PrintStream printStream3 = System.out;
                printStream3.println("Id for <" + i + "> is <" + IdAsString + "> looking for <" + id + ">");
            }
            if (id.equals(IdAsString)) {
                return this.mConstraintSetMap.get(key);
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ConstraintSet getConstraintSet(int id) {
        return getConstraintSet(id, -1, -1);
    }

    ConstraintSet getConstraintSet(int id, int width, int height) {
        int cid;
        if (this.DEBUG_DESKTOP) {
            PrintStream printStream = System.out;
            printStream.println("id " + id);
            PrintStream printStream2 = System.out;
            printStream2.println("size " + this.mConstraintSetMap.size());
        }
        StateSet stateSet = this.mStateSet;
        if (stateSet != null && (cid = stateSet.stateGetConstraintID(id, width, height)) != -1) {
            id = cid;
        }
        if (this.mConstraintSetMap.get(id) == null) {
            Log.e(TypedValues.MotionScene.NAME, "Warning could not find ConstraintSet id/" + Debug.getName(this.mMotionLayout.getContext(), id) + " In MotionScene");
            SparseArray<ConstraintSet> sparseArray = this.mConstraintSetMap;
            return sparseArray.get(sparseArray.keyAt(0));
        }
        return this.mConstraintSetMap.get(id);
    }

    public void setConstraintSet(int id, ConstraintSet set) {
        this.mConstraintSetMap.put(id, set);
    }

    public void getKeyFrames(MotionController motionController) {
        Transition transition = this.mCurrentTransition;
        if (transition != null) {
            Iterator it = transition.mKeyFramesList.iterator();
            while (it.hasNext()) {
                KeyFrames keyFrames = (KeyFrames) it.next();
                keyFrames.addFrames(motionController);
            }
            return;
        }
        Transition transition2 = this.mDefaultTransition;
        if (transition2 != null) {
            Iterator it2 = transition2.mKeyFramesList.iterator();
            while (it2.hasNext()) {
                KeyFrames keyFrames2 = (KeyFrames) it2.next();
                keyFrames2.addFrames(motionController);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Key getKeyFrame(Context context, int type, int target, int position) {
        Transition transition = this.mCurrentTransition;
        if (transition == null) {
            return null;
        }
        Iterator it = transition.mKeyFramesList.iterator();
        while (it.hasNext()) {
            KeyFrames keyFrames = (KeyFrames) it.next();
            for (Integer integer : keyFrames.getKeys()) {
                if (target == integer.intValue()) {
                    ArrayList<Key> keys = keyFrames.getKeyFramesForView(integer.intValue());
                    Iterator<Key> it2 = keys.iterator();
                    while (it2.hasNext()) {
                        Key key = it2.next();
                        if (key.mFramePosition == position && key.mType == type) {
                            return key;
                        }
                    }
                    continue;
                }
            }
        }
        return null;
    }

    int getTransitionDirection(int stateId) {
        Iterator<Transition> it = this.mTransitionList.iterator();
        while (it.hasNext()) {
            Transition transition = it.next();
            if (transition.mConstraintSetStart == stateId) {
                return 0;
            }
        }
        return 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean hasKeyFramePosition(View view, int position) {
        Transition transition = this.mCurrentTransition;
        if (transition == null) {
            return false;
        }
        Iterator it = transition.mKeyFramesList.iterator();
        while (it.hasNext()) {
            KeyFrames keyFrames = (KeyFrames) it.next();
            ArrayList<Key> framePoints = keyFrames.getKeyFramesForView(view.getId());
            Iterator<Key> it2 = framePoints.iterator();
            while (it2.hasNext()) {
                Key framePoint = it2.next();
                if (framePoint.mFramePosition == position) {
                    return true;
                }
            }
        }
        return false;
    }

    public void setKeyframe(View view, int position, String name, Object value) {
        Transition transition = this.mCurrentTransition;
        if (transition != null) {
            Iterator it = transition.mKeyFramesList.iterator();
            while (it.hasNext()) {
                KeyFrames keyFrames = (KeyFrames) it.next();
                ArrayList<Key> framePoints = keyFrames.getKeyFramesForView(view.getId());
                Iterator<Key> it2 = framePoints.iterator();
                while (it2.hasNext()) {
                    Key framePoint = it2.next();
                    if (framePoint.mFramePosition == position) {
                        float v = 0.0f;
                        if (value != null) {
                            v = ((Float) value).floatValue();
                        }
                        if (v == 0.0f) {
                        }
                        name.equalsIgnoreCase("app:PerpendicularPath_percent");
                    }
                }
            }
        }
    }

    public float getPathPercent(View view, int position) {
        return 0.0f;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean supportTouch() {
        Iterator<Transition> it = this.mTransitionList.iterator();
        while (it.hasNext()) {
            Transition transition = it.next();
            if (transition.mTouchResponse != null) {
                return true;
            }
        }
        Transition transition2 = this.mCurrentTransition;
        return (transition2 == null || transition2.mTouchResponse == null) ? false : true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    public void processTouchEvent(MotionEvent event, int currentState, MotionLayout motionLayout) {
        MotionLayout.MotionTracker motionTracker;
        MotionEvent motionEvent;
        RectF cache = new RectF();
        if (this.mVelocityTracker == null) {
            this.mVelocityTracker = this.mMotionLayout.obtainVelocityTracker();
        }
        this.mVelocityTracker.addMovement(event);
        if (currentState != -1) {
            boolean z = false;
            switch (event.getAction()) {
                case 0:
                    this.mLastTouchX = event.getRawX();
                    this.mLastTouchY = event.getRawY();
                    this.mLastTouchDown = event;
                    this.mIgnoreTouch = false;
                    if (this.mCurrentTransition.mTouchResponse != null) {
                        RectF region = this.mCurrentTransition.mTouchResponse.getLimitBoundsTo(this.mMotionLayout, cache);
                        if (region == null || region.contains(this.mLastTouchDown.getX(), this.mLastTouchDown.getY())) {
                            RectF region2 = this.mCurrentTransition.mTouchResponse.getTouchRegion(this.mMotionLayout, cache);
                            if (region2 != null && !region2.contains(this.mLastTouchDown.getX(), this.mLastTouchDown.getY())) {
                                this.mMotionOutsideRegion = true;
                            } else {
                                this.mMotionOutsideRegion = false;
                            }
                            this.mCurrentTransition.mTouchResponse.setDown(this.mLastTouchX, this.mLastTouchY);
                            return;
                        }
                        this.mLastTouchDown = null;
                        this.mIgnoreTouch = true;
                        return;
                    }
                    return;
                case 2:
                    if (!this.mIgnoreTouch) {
                        float dy = event.getRawY() - this.mLastTouchY;
                        float dx = event.getRawX() - this.mLastTouchX;
                        if ((dx == 0.0d && dy == 0.0d) || (motionEvent = this.mLastTouchDown) == null) {
                            return;
                        }
                        Transition transition = bestTransitionFor(currentState, dx, dy, motionEvent);
                        if (transition != null) {
                            motionLayout.setTransition(transition);
                            RectF region3 = this.mCurrentTransition.mTouchResponse.getTouchRegion(this.mMotionLayout, cache);
                            if (region3 != null && !region3.contains(this.mLastTouchDown.getX(), this.mLastTouchDown.getY())) {
                                z = true;
                            }
                            this.mMotionOutsideRegion = z;
                            this.mCurrentTransition.mTouchResponse.setUpTouchEvent(this.mLastTouchX, this.mLastTouchY);
                            break;
                        }
                    }
                    break;
            }
        }
        if (this.mIgnoreTouch) {
            return;
        }
        Transition transition2 = this.mCurrentTransition;
        if (transition2 != null && transition2.mTouchResponse != null && !this.mMotionOutsideRegion) {
            this.mCurrentTransition.mTouchResponse.processTouchEvent(event, this.mVelocityTracker, currentState, this);
        }
        this.mLastTouchX = event.getRawX();
        this.mLastTouchY = event.getRawY();
        if (event.getAction() == 1 && (motionTracker = this.mVelocityTracker) != null) {
            motionTracker.recycle();
            this.mVelocityTracker = null;
            if (motionLayout.mCurrentState != -1) {
                autoTransition(motionLayout, motionLayout.mCurrentState);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void processScrollMove(float dx, float dy) {
        Transition transition = this.mCurrentTransition;
        if (transition != null && transition.mTouchResponse != null) {
            this.mCurrentTransition.mTouchResponse.scrollMove(dx, dy);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void processScrollUp(float dx, float dy) {
        Transition transition = this.mCurrentTransition;
        if (transition != null && transition.mTouchResponse != null) {
            this.mCurrentTransition.mTouchResponse.scrollUp(dx, dy);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public float getProgressDirection(float dx, float dy) {
        Transition transition = this.mCurrentTransition;
        if (transition != null && transition.mTouchResponse != null) {
            return this.mCurrentTransition.mTouchResponse.getProgressDirection(dx, dy);
        }
        return 0.0f;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getStartId() {
        Transition transition = this.mCurrentTransition;
        if (transition != null) {
            return transition.mConstraintSetStart;
        }
        return -1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getEndId() {
        Transition transition = this.mCurrentTransition;
        if (transition != null) {
            return transition.mConstraintSetEnd;
        }
        return -1;
    }

    public Interpolator getInterpolator() {
        switch (this.mCurrentTransition.mDefaultInterpolator) {
            case -2:
                return AnimationUtils.loadInterpolator(this.mMotionLayout.getContext(), this.mCurrentTransition.mDefaultInterpolatorID);
            case -1:
                final Easing easing = Easing.getInterpolator(this.mCurrentTransition.mDefaultInterpolatorString);
                return new Interpolator(this) { // from class: androidx.constraintlayout.motion.widget.MotionScene.1
                    @Override // android.animation.TimeInterpolator
                    public float getInterpolation(float v) {
                        return (float) easing.get(v);
                    }
                };
            case 0:
                return new AccelerateDecelerateInterpolator();
            case 1:
                return new AccelerateInterpolator();
            case 2:
                return new DecelerateInterpolator();
            case 3:
                return null;
            case 4:
                return new BounceInterpolator();
            case 5:
                return new OvershootInterpolator();
            case 6:
                return new AnticipateInterpolator();
            default:
                return null;
        }
    }

    public int getDuration() {
        Transition transition = this.mCurrentTransition;
        if (transition != null) {
            return transition.mDuration;
        }
        return this.mDefaultDuration;
    }

    public void setDuration(int duration) {
        Transition transition = this.mCurrentTransition;
        if (transition != null) {
            transition.setDuration(duration);
        } else {
            this.mDefaultDuration = duration;
        }
    }

    public int gatPathMotionArc() {
        Transition transition = this.mCurrentTransition;
        if (transition != null) {
            return transition.mPathMotionArc;
        }
        return -1;
    }

    public float getStaggered() {
        Transition transition = this.mCurrentTransition;
        if (transition != null) {
            return transition.mStagger;
        }
        return 0.0f;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public float getMaxAcceleration() {
        Transition transition = this.mCurrentTransition;
        if (transition != null && transition.mTouchResponse != null) {
            return this.mCurrentTransition.mTouchResponse.getMaxAcceleration();
        }
        return 0.0f;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public float getMaxVelocity() {
        Transition transition = this.mCurrentTransition;
        if (transition != null && transition.mTouchResponse != null) {
            return this.mCurrentTransition.mTouchResponse.getMaxVelocity();
        }
        return 0.0f;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public float getSpringStiffiness() {
        Transition transition = this.mCurrentTransition;
        if (transition != null && transition.mTouchResponse != null) {
            return this.mCurrentTransition.mTouchResponse.getSpringStiffness();
        }
        return 0.0f;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public float getSpringMass() {
        Transition transition = this.mCurrentTransition;
        if (transition != null && transition.mTouchResponse != null) {
            return this.mCurrentTransition.mTouchResponse.getSpringMass();
        }
        return 0.0f;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public float getSpringDamping() {
        Transition transition = this.mCurrentTransition;
        if (transition != null && transition.mTouchResponse != null) {
            return this.mCurrentTransition.mTouchResponse.getSpringDamping();
        }
        return 0.0f;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public float getSpringStopThreshold() {
        Transition transition = this.mCurrentTransition;
        if (transition != null && transition.mTouchResponse != null) {
            return this.mCurrentTransition.mTouchResponse.getSpringStopThreshold();
        }
        return 0.0f;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getSpringBoundary() {
        Transition transition = this.mCurrentTransition;
        if (transition != null && transition.mTouchResponse != null) {
            return this.mCurrentTransition.mTouchResponse.getSpringBoundary();
        }
        return 0;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getAutoCompleteMode() {
        Transition transition = this.mCurrentTransition;
        if (transition != null && transition.mTouchResponse != null) {
            return this.mCurrentTransition.mTouchResponse.getAutoCompleteMode();
        }
        return 0;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setupTouch() {
        Transition transition = this.mCurrentTransition;
        if (transition != null && transition.mTouchResponse != null) {
            this.mCurrentTransition.mTouchResponse.setupTouch();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean getMoveWhenScrollAtTop() {
        Transition transition = this.mCurrentTransition;
        if (transition != null && transition.mTouchResponse != null) {
            return this.mCurrentTransition.mTouchResponse.getMoveWhenScrollAtTop();
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void readFallback(MotionLayout motionLayout) {
        for (int i = 0; i < this.mConstraintSetMap.size(); i++) {
            int key = this.mConstraintSetMap.keyAt(i);
            if (hasCycleDependency(key)) {
                Log.e(TypedValues.MotionScene.NAME, "Cannot be derived from yourself");
                return;
            }
            readConstraintChain(key, motionLayout);
        }
    }

    private boolean hasCycleDependency(int key) {
        int derived = this.mDeriveMap.get(key);
        int len = this.mDeriveMap.size();
        while (derived > 0) {
            if (derived == key) {
                return true;
            }
            int len2 = len - 1;
            if (len < 0) {
                return true;
            }
            derived = this.mDeriveMap.get(derived);
            len = len2;
        }
        return false;
    }

    private void readConstraintChain(int key, MotionLayout motionLayout) {
        ConstraintSet cs = this.mConstraintSetMap.get(key);
        cs.derivedState = cs.mIdString;
        int derivedFromId = this.mDeriveMap.get(key);
        if (derivedFromId > 0) {
            readConstraintChain(derivedFromId, motionLayout);
            ConstraintSet derivedFrom = this.mConstraintSetMap.get(derivedFromId);
            if (derivedFrom == null) {
                Log.e(TypedValues.MotionScene.NAME, "ERROR! invalid deriveConstraintsFrom: @id/" + Debug.getName(this.mMotionLayout.getContext(), derivedFromId));
                return;
            }
            cs.derivedState += "/" + derivedFrom.derivedState;
            cs.readFallback(derivedFrom);
        } else {
            cs.derivedState += "  layout";
            cs.readFallback(motionLayout);
        }
        cs.applyDeltaFrom(cs);
    }

    public static String stripID(String id) {
        if (id == null) {
            return "";
        }
        int index = id.indexOf(47);
        if (index < 0) {
            return id;
        }
        return id.substring(index + 1);
    }

    public int lookUpConstraintId(String id) {
        Integer boxed = this.mConstraintSetIdMap.get(id);
        if (boxed == null) {
            return 0;
        }
        return boxed.intValue();
    }

    public String lookUpConstraintName(int id) {
        for (Map.Entry<String, Integer> entry : this.mConstraintSetIdMap.entrySet()) {
            Integer boxed = entry.getValue();
            if (boxed != null && boxed.intValue() == id) {
                return entry.getKey();
            }
        }
        return null;
    }

    public void disableAutoTransition(boolean disable) {
        this.mDisableAutoTransition = disable;
    }

    static String getLine(Context context, int resourceId, XmlPullParser pullParser) {
        return ".(" + Debug.getName(context, resourceId) + ".xml:" + pullParser.getLineNumber() + ") \"" + pullParser.getName() + "\"";
    }
}
