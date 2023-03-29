package androidx.constraintlayout.motion.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.util.Log;
import android.util.TypedValue;
import android.util.Xml;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.AnimationUtils;
import android.view.animation.AnticipateInterpolator;
import android.view.animation.BounceInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.Interpolator;
import android.view.animation.OvershootInterpolator;
import androidx.constraintlayout.core.motion.utils.Easing;
import androidx.constraintlayout.core.motion.utils.KeyCache;
import androidx.constraintlayout.motion.widget.MotionScene;
import androidx.constraintlayout.widget.ConstraintAttribute;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.ConstraintSet;
import androidx.constraintlayout.widget.R;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
/* loaded from: classes.dex */
public class ViewTransition {
    static final int ANTICIPATE = 6;
    static final int BOUNCE = 4;
    public static final String CONSTRAINT_OVERRIDE = "ConstraintOverride";
    public static final String CUSTOM_ATTRIBUTE = "CustomAttribute";
    public static final String CUSTOM_METHOD = "CustomMethod";
    static final int EASE_IN = 1;
    static final int EASE_IN_OUT = 0;
    static final int EASE_OUT = 2;
    private static final int INTERPOLATOR_REFERENCE_ID = -2;
    public static final String KEY_FRAME_SET_TAG = "KeyFrameSet";
    static final int LINEAR = 3;
    public static final int ONSTATE_ACTION_DOWN = 1;
    public static final int ONSTATE_ACTION_DOWN_UP = 3;
    public static final int ONSTATE_ACTION_UP = 2;
    public static final int ONSTATE_SHARED_VALUE_SET = 4;
    public static final int ONSTATE_SHARED_VALUE_UNSET = 5;
    static final int OVERSHOOT = 5;
    private static final int SPLINE_STRING = -1;
    private static final int UNSET = -1;
    static final int VIEWTRANSITIONMODE_ALLSTATES = 1;
    static final int VIEWTRANSITIONMODE_CURRENTSTATE = 0;
    static final int VIEWTRANSITIONMODE_NOSTATE = 2;
    ConstraintSet.Constraint mConstraintDelta;
    Context mContext;
    private int mId;
    KeyFrames mKeyFrames;
    private int mTargetId;
    private String mTargetString;
    int mViewTransitionMode;
    ConstraintSet set;
    public static final String VIEW_TRANSITION_TAG = "ViewTransition";
    private static String TAG = VIEW_TRANSITION_TAG;
    private int mOnStateTransition = -1;
    private boolean mDisabled = false;
    private int mPathMotionArc = 0;
    private int mDuration = -1;
    private int mUpDuration = -1;
    private int mDefaultInterpolator = 0;
    private String mDefaultInterpolatorString = null;
    private int mDefaultInterpolatorID = -1;
    private int mSetsTag = -1;
    private int mClearsTag = -1;
    private int mIfTagSet = -1;
    private int mIfTagNotSet = -1;
    private int mSharedValueTarget = -1;
    private int mSharedValueID = -1;
    private int mSharedValueCurrent = -1;

    public int getSharedValueCurrent() {
        return this.mSharedValueCurrent;
    }

    public void setSharedValueCurrent(int sharedValueCurrent) {
        this.mSharedValueCurrent = sharedValueCurrent;
    }

    public int getStateTransition() {
        return this.mOnStateTransition;
    }

    public void setStateTransition(int stateTransition) {
        this.mOnStateTransition = stateTransition;
    }

    public int getSharedValue() {
        return this.mSharedValueTarget;
    }

    public void setSharedValue(int sharedValue) {
        this.mSharedValueTarget = sharedValue;
    }

    public int getSharedValueID() {
        return this.mSharedValueID;
    }

    public void setSharedValueID(int sharedValueID) {
        this.mSharedValueID = sharedValueID;
    }

    public String toString() {
        return "ViewTransition(" + Debug.getName(this.mContext, this.mId) + ")";
    }

    Interpolator getInterpolator(Context context) {
        switch (this.mDefaultInterpolator) {
            case -2:
                return AnimationUtils.loadInterpolator(context, this.mDefaultInterpolatorID);
            case -1:
                final Easing easing = Easing.getInterpolator(this.mDefaultInterpolatorString);
                return new Interpolator(this) { // from class: androidx.constraintlayout.motion.widget.ViewTransition.1
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

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    public ViewTransition(Context context, XmlPullParser parser) {
        this.mContext = context;
        try {
            int eventType = parser.getEventType();
            while (true) {
                char c = 1;
                if (eventType != 1) {
                    switch (eventType) {
                        case 2:
                            String tagName = parser.getName();
                            switch (tagName.hashCode()) {
                                case -1962203927:
                                    if (tagName.equals(CONSTRAINT_OVERRIDE)) {
                                        c = 2;
                                        break;
                                    }
                                    c = 65535;
                                    break;
                                case -1239391468:
                                    if (tagName.equals(KEY_FRAME_SET_TAG)) {
                                        break;
                                    }
                                    c = 65535;
                                    break;
                                case 61998586:
                                    if (tagName.equals(VIEW_TRANSITION_TAG)) {
                                        c = 0;
                                        break;
                                    }
                                    c = 65535;
                                    break;
                                case 366511058:
                                    if (tagName.equals(CUSTOM_METHOD)) {
                                        c = 4;
                                        break;
                                    }
                                    c = 65535;
                                    break;
                                case 1791837707:
                                    if (tagName.equals(CUSTOM_ATTRIBUTE)) {
                                        c = 3;
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
                                    parseViewTransitionTags(context, parser);
                                    break;
                                case 1:
                                    this.mKeyFrames = new KeyFrames(context, parser);
                                    break;
                                case 2:
                                    this.mConstraintDelta = ConstraintSet.buildDelta(context, parser);
                                    break;
                                case 3:
                                case 4:
                                    ConstraintAttribute.parse(context, parser, this.mConstraintDelta.mCustomConstraints);
                                    break;
                                default:
                                    String str = TAG;
                                    Log.e(str, Debug.getLoc() + " unknown tag " + tagName);
                                    String str2 = TAG;
                                    Log.e(str2, ".xml:" + parser.getLineNumber());
                                    break;
                            }
                            break;
                        case 3:
                            if (VIEW_TRANSITION_TAG.equals(parser.getName())) {
                                return;
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

    private void parseViewTransitionTags(Context context, XmlPullParser parser) {
        AttributeSet attrs = Xml.asAttributeSet(parser);
        TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.ViewTransition);
        int count = a.getIndexCount();
        for (int i = 0; i < count; i++) {
            int attr = a.getIndex(i);
            if (attr == R.styleable.ViewTransition_android_id) {
                this.mId = a.getResourceId(attr, this.mId);
            } else if (attr == R.styleable.ViewTransition_motionTarget) {
                if (MotionLayout.IS_IN_EDIT_MODE) {
                    int resourceId = a.getResourceId(attr, this.mTargetId);
                    this.mTargetId = resourceId;
                    if (resourceId == -1) {
                        this.mTargetString = a.getString(attr);
                    }
                } else if (a.peekValue(attr).type == 3) {
                    this.mTargetString = a.getString(attr);
                } else {
                    this.mTargetId = a.getResourceId(attr, this.mTargetId);
                }
            } else if (attr == R.styleable.ViewTransition_onStateTransition) {
                this.mOnStateTransition = a.getInt(attr, this.mOnStateTransition);
            } else if (attr == R.styleable.ViewTransition_transitionDisable) {
                this.mDisabled = a.getBoolean(attr, this.mDisabled);
            } else if (attr == R.styleable.ViewTransition_pathMotionArc) {
                this.mPathMotionArc = a.getInt(attr, this.mPathMotionArc);
            } else if (attr == R.styleable.ViewTransition_duration) {
                this.mDuration = a.getInt(attr, this.mDuration);
            } else if (attr == R.styleable.ViewTransition_upDuration) {
                this.mUpDuration = a.getInt(attr, this.mUpDuration);
            } else if (attr == R.styleable.ViewTransition_viewTransitionMode) {
                this.mViewTransitionMode = a.getInt(attr, this.mViewTransitionMode);
            } else if (attr == R.styleable.ViewTransition_motionInterpolator) {
                TypedValue type = a.peekValue(attr);
                if (type.type == 1) {
                    int resourceId2 = a.getResourceId(attr, -1);
                    this.mDefaultInterpolatorID = resourceId2;
                    if (resourceId2 != -1) {
                        this.mDefaultInterpolator = -2;
                    }
                } else if (type.type == 3) {
                    String string = a.getString(attr);
                    this.mDefaultInterpolatorString = string;
                    if (string != null && string.indexOf("/") > 0) {
                        this.mDefaultInterpolatorID = a.getResourceId(attr, -1);
                        this.mDefaultInterpolator = -2;
                    } else {
                        this.mDefaultInterpolator = -1;
                    }
                } else {
                    this.mDefaultInterpolator = a.getInteger(attr, this.mDefaultInterpolator);
                }
            } else if (attr == R.styleable.ViewTransition_setsTag) {
                this.mSetsTag = a.getResourceId(attr, this.mSetsTag);
            } else if (attr == R.styleable.ViewTransition_clearsTag) {
                this.mClearsTag = a.getResourceId(attr, this.mClearsTag);
            } else if (attr == R.styleable.ViewTransition_ifTagSet) {
                this.mIfTagSet = a.getResourceId(attr, this.mIfTagSet);
            } else if (attr == R.styleable.ViewTransition_ifTagNotSet) {
                this.mIfTagNotSet = a.getResourceId(attr, this.mIfTagNotSet);
            } else if (attr == R.styleable.ViewTransition_SharedValueId) {
                this.mSharedValueID = a.getResourceId(attr, this.mSharedValueID);
            } else if (attr == R.styleable.ViewTransition_SharedValue) {
                this.mSharedValueTarget = a.getInteger(attr, this.mSharedValueTarget);
            }
        }
        a.recycle();
    }

    void applyIndependentTransition(ViewTransitionController controller, MotionLayout motionLayout, View view) {
        MotionController motionController = new MotionController(view);
        motionController.setBothStates(view);
        this.mKeyFrames.addAllFrames(motionController);
        motionController.setup(motionLayout.getWidth(), motionLayout.getHeight(), this.mDuration, System.nanoTime());
        new Animate(controller, motionController, this.mDuration, this.mUpDuration, this.mOnStateTransition, getInterpolator(motionLayout.getContext()), this.mSetsTag, this.mClearsTag);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class Animate {
        boolean hold_at_100;
        private final int mClearsTag;
        float mDpositionDt;
        int mDuration;
        Interpolator mInterpolator;
        long mLastRender;
        MotionController mMC;
        float mPosition;
        private final int mSetsTag;
        long mStart;
        int mUpDuration;
        ViewTransitionController mVtController;
        KeyCache mCache = new KeyCache();
        boolean reverse = false;
        Rect mTempRec = new Rect();

        Animate(ViewTransitionController controller, MotionController motionController, int duration, int upDuration, int mode, Interpolator interpolator, int setTag, int clearTag) {
            this.hold_at_100 = false;
            this.mVtController = controller;
            this.mMC = motionController;
            this.mDuration = duration;
            this.mUpDuration = upDuration;
            long nanoTime = System.nanoTime();
            this.mStart = nanoTime;
            this.mLastRender = nanoTime;
            this.mVtController.addAnimation(this);
            this.mInterpolator = interpolator;
            this.mSetsTag = setTag;
            this.mClearsTag = clearTag;
            if (mode == 3) {
                this.hold_at_100 = true;
            }
            this.mDpositionDt = duration == 0 ? Float.MAX_VALUE : 1.0f / duration;
            mutate();
        }

        void reverse(boolean dir) {
            int i;
            this.reverse = dir;
            if (dir && (i = this.mUpDuration) != -1) {
                this.mDpositionDt = i == 0 ? Float.MAX_VALUE : 1.0f / i;
            }
            this.mVtController.invalidate();
            this.mLastRender = System.nanoTime();
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public void mutate() {
            if (this.reverse) {
                mutateReverse();
            } else {
                mutateForward();
            }
        }

        void mutateReverse() {
            long current = System.nanoTime();
            long elapse = current - this.mLastRender;
            this.mLastRender = current;
            float f = this.mPosition - (((float) (elapse * 1.0E-6d)) * this.mDpositionDt);
            this.mPosition = f;
            if (f < 0.0f) {
                this.mPosition = 0.0f;
            }
            Interpolator interpolator = this.mInterpolator;
            float ipos = interpolator == null ? this.mPosition : interpolator.getInterpolation(this.mPosition);
            MotionController motionController = this.mMC;
            boolean repaint = motionController.interpolate(motionController.mView, ipos, current, this.mCache);
            if (this.mPosition <= 0.0f) {
                if (this.mSetsTag != -1) {
                    this.mMC.getView().setTag(this.mSetsTag, Long.valueOf(System.nanoTime()));
                }
                if (this.mClearsTag != -1) {
                    this.mMC.getView().setTag(this.mClearsTag, null);
                }
                this.mVtController.removeAnimation(this);
            }
            if (this.mPosition > 0.0f || repaint) {
                this.mVtController.invalidate();
            }
        }

        void mutateForward() {
            long current = System.nanoTime();
            long elapse = current - this.mLastRender;
            this.mLastRender = current;
            float f = this.mPosition + (((float) (elapse * 1.0E-6d)) * this.mDpositionDt);
            this.mPosition = f;
            if (f >= 1.0f) {
                this.mPosition = 1.0f;
            }
            Interpolator interpolator = this.mInterpolator;
            float ipos = interpolator == null ? this.mPosition : interpolator.getInterpolation(this.mPosition);
            MotionController motionController = this.mMC;
            boolean repaint = motionController.interpolate(motionController.mView, ipos, current, this.mCache);
            if (this.mPosition >= 1.0f) {
                if (this.mSetsTag != -1) {
                    this.mMC.getView().setTag(this.mSetsTag, Long.valueOf(System.nanoTime()));
                }
                if (this.mClearsTag != -1) {
                    this.mMC.getView().setTag(this.mClearsTag, null);
                }
                if (!this.hold_at_100) {
                    this.mVtController.removeAnimation(this);
                }
            }
            if (this.mPosition < 1.0f || repaint) {
                this.mVtController.invalidate();
            }
        }

        public void reactTo(int action, float x, float y) {
            switch (action) {
                case 1:
                    if (!this.reverse) {
                        reverse(true);
                        return;
                    }
                    return;
                case 2:
                    View view = this.mMC.getView();
                    view.getHitRect(this.mTempRec);
                    if (!this.mTempRec.contains((int) x, (int) y) && !this.reverse) {
                        reverse(true);
                        return;
                    }
                    return;
                default:
                    return;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void applyTransition(ViewTransitionController controller, MotionLayout layout, int fromId, ConstraintSet current, final View... views) {
        if (this.mDisabled) {
            return;
        }
        int i = this.mViewTransitionMode;
        if (i == 2) {
            applyIndependentTransition(controller, layout, views[0]);
            return;
        }
        if (i == 1) {
            int[] ids = layout.getConstraintSetIds();
            for (int id : ids) {
                if (id != fromId) {
                    ConstraintSet cSet = layout.getConstraintSet(id);
                    for (View view : views) {
                        ConstraintSet.Constraint constraint = cSet.getConstraint(view.getId());
                        ConstraintSet.Constraint constraint2 = this.mConstraintDelta;
                        if (constraint2 != null) {
                            constraint2.applyDelta(constraint);
                            constraint.mCustomConstraints.putAll(this.mConstraintDelta.mCustomConstraints);
                        }
                    }
                }
            }
        }
        ConstraintSet transformedState = new ConstraintSet();
        transformedState.clone(current);
        for (View view2 : views) {
            ConstraintSet.Constraint constraint3 = transformedState.getConstraint(view2.getId());
            ConstraintSet.Constraint constraint4 = this.mConstraintDelta;
            if (constraint4 != null) {
                constraint4.applyDelta(constraint3);
                constraint3.mCustomConstraints.putAll(this.mConstraintDelta.mCustomConstraints);
            }
        }
        layout.updateState(fromId, transformedState);
        layout.updateState(R.id.view_transition, current);
        layout.setState(R.id.view_transition, -1, -1);
        MotionScene.Transition tmpTransition = new MotionScene.Transition(-1, layout.mScene, R.id.view_transition, fromId);
        for (View view3 : views) {
            updateTransition(tmpTransition, view3);
        }
        layout.setTransition(tmpTransition);
        layout.transitionToEnd(new Runnable() { // from class: androidx.constraintlayout.motion.widget.ViewTransition$$ExternalSyntheticLambda0
            @Override // java.lang.Runnable
            public final void run() {
                ViewTransition.this.m5x14d7500(views);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: lambda$applyTransition$0$androidx-constraintlayout-motion-widget-ViewTransition  reason: not valid java name */
    public /* synthetic */ void m5x14d7500(View[] views) {
        if (this.mSetsTag != -1) {
            for (View view : views) {
                view.setTag(this.mSetsTag, Long.valueOf(System.nanoTime()));
            }
        }
        if (this.mClearsTag != -1) {
            for (View view2 : views) {
                view2.setTag(this.mClearsTag, null);
            }
        }
    }

    private void updateTransition(MotionScene.Transition transition, View view) {
        int i = this.mDuration;
        if (i != -1) {
            transition.setDuration(i);
        }
        transition.setPathMotionArc(this.mPathMotionArc);
        transition.setInterpolatorInfo(this.mDefaultInterpolator, this.mDefaultInterpolatorString, this.mDefaultInterpolatorID);
        int id = view.getId();
        KeyFrames keyFrames = this.mKeyFrames;
        if (keyFrames != null) {
            ArrayList<Key> keys = keyFrames.getKeyFramesForView(-1);
            KeyFrames keyFrames2 = new KeyFrames();
            Iterator<Key> it = keys.iterator();
            while (it.hasNext()) {
                Key key = it.next();
                keyFrames2.addKey(key.mo4clone().setViewId(id));
            }
            transition.addKeyFrame(keyFrames2);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getId() {
        return this.mId;
    }

    void setId(int id) {
        this.mId = id;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean matchesView(View view) {
        String tag;
        if (view == null) {
            return false;
        }
        if ((this.mTargetId == -1 && this.mTargetString == null) || !checkTags(view)) {
            return false;
        }
        if (view.getId() == this.mTargetId) {
            return true;
        }
        if (this.mTargetString == null) {
            return false;
        }
        ViewGroup.LayoutParams lp = view.getLayoutParams();
        return (lp instanceof ConstraintLayout.LayoutParams) && (tag = ((ConstraintLayout.LayoutParams) view.getLayoutParams()).constraintTag) != null && tag.matches(this.mTargetString);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean supports(int action) {
        int i = this.mOnStateTransition;
        return i == 1 ? action == 0 : i == 2 ? action == 1 : i == 3 && action == 0;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isEnabled() {
        return !this.mDisabled;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setEnabled(boolean enable) {
        this.mDisabled = !enable;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean checkTags(View view) {
        int i = this.mIfTagSet;
        boolean set = i == -1 || view.getTag(i) != null;
        int i2 = this.mIfTagNotSet;
        boolean notSet = i2 == -1 || view.getTag(i2) == null;
        return set && notSet;
    }
}
