package androidx.constraintlayout.motion.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.util.Log;
import android.util.SparseIntArray;
import android.view.View;
import android.view.ViewGroup;
import androidx.constraintlayout.core.motion.utils.TypedValues;
import androidx.constraintlayout.motion.utils.ViewSpline;
import androidx.constraintlayout.widget.ConstraintAttribute;
import androidx.constraintlayout.widget.R;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
/* loaded from: classes.dex */
public class KeyTrigger extends Key {
    public static final String CROSS = "CROSS";
    public static final int KEY_TYPE = 5;
    static final String NAME = "KeyTrigger";
    public static final String NEGATIVE_CROSS = "negativeCross";
    public static final String POSITIVE_CROSS = "positiveCross";
    public static final String POST_LAYOUT = "postLayout";
    private static final String TAG = "KeyTrigger";
    public static final String TRIGGER_COLLISION_ID = "triggerCollisionId";
    public static final String TRIGGER_COLLISION_VIEW = "triggerCollisionView";
    public static final String TRIGGER_ID = "triggerID";
    public static final String TRIGGER_RECEIVER = "triggerReceiver";
    public static final String TRIGGER_SLACK = "triggerSlack";
    public static final String VIEW_TRANSITION_ON_CROSS = "viewTransitionOnCross";
    public static final String VIEW_TRANSITION_ON_NEGATIVE_CROSS = "viewTransitionOnNegativeCross";
    public static final String VIEW_TRANSITION_ON_POSITIVE_CROSS = "viewTransitionOnPositiveCross";
    private float mFireLastPos;
    private int mCurveFit = -1;
    private String mCross = null;
    private int mTriggerReceiver = UNSET;
    private String mNegativeCross = null;
    private String mPositiveCross = null;
    private int mTriggerID = UNSET;
    private int mTriggerCollisionId = UNSET;
    private View mTriggerCollisionView = null;
    float mTriggerSlack = 0.1f;
    private boolean mFireCrossReset = true;
    private boolean mFireNegativeReset = true;
    private boolean mFirePositiveReset = true;
    private float mFireThreshold = Float.NaN;
    private boolean mPostLayout = false;
    int mViewTransitionOnNegativeCross = UNSET;
    int mViewTransitionOnPositiveCross = UNSET;
    int mViewTransitionOnCross = UNSET;
    RectF mCollisionRect = new RectF();
    RectF mTargetRect = new RectF();
    HashMap<String, Method> mMethodHashMap = new HashMap<>();

    public KeyTrigger() {
        this.mType = 5;
        this.mCustomConstraints = new HashMap<>();
    }

    @Override // androidx.constraintlayout.motion.widget.Key
    public void load(Context context, AttributeSet attrs) {
        TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.KeyTrigger);
        Loader.read(this, a, context);
    }

    int getCurveFit() {
        return this.mCurveFit;
    }

    @Override // androidx.constraintlayout.motion.widget.Key
    public void getAttributeNames(HashSet<String> attributes) {
    }

    @Override // androidx.constraintlayout.motion.widget.Key
    public void addValues(HashMap<String, ViewSpline> splines) {
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    @Override // androidx.constraintlayout.motion.widget.Key
    public void setValue(String tag, Object value) {
        char c;
        switch (tag.hashCode()) {
            case -1594793529:
                if (tag.equals("positiveCross")) {
                    c = 3;
                    break;
                }
                c = 65535;
                break;
            case -966421266:
                if (tag.equals("viewTransitionOnPositiveCross")) {
                    c = '\n';
                    break;
                }
                c = 65535;
                break;
            case -786670827:
                if (tag.equals("triggerCollisionId")) {
                    c = 5;
                    break;
                }
                c = 65535;
                break;
            case -648752941:
                if (tag.equals("triggerID")) {
                    c = 4;
                    break;
                }
                c = 65535;
                break;
            case -638126837:
                if (tag.equals("negativeCross")) {
                    c = 2;
                    break;
                }
                c = 65535;
                break;
            case -76025313:
                if (tag.equals("triggerCollisionView")) {
                    c = 6;
                    break;
                }
                c = 65535;
                break;
            case -9754574:
                if (tag.equals("viewTransitionOnNegativeCross")) {
                    c = '\t';
                    break;
                }
                c = 65535;
                break;
            case 64397344:
                if (tag.equals("CROSS")) {
                    c = 0;
                    break;
                }
                c = 65535;
                break;
            case 364489912:
                if (tag.equals("triggerSlack")) {
                    c = 7;
                    break;
                }
                c = 65535;
                break;
            case 1301930599:
                if (tag.equals("viewTransitionOnCross")) {
                    c = 11;
                    break;
                }
                c = 65535;
                break;
            case 1401391082:
                if (tag.equals("postLayout")) {
                    c = '\b';
                    break;
                }
                c = 65535;
                break;
            case 1535404999:
                if (tag.equals("triggerReceiver")) {
                    c = 1;
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
                this.mCross = value.toString();
                return;
            case 1:
                this.mTriggerReceiver = toInt(value);
                return;
            case 2:
                this.mNegativeCross = value.toString();
                return;
            case 3:
                this.mPositiveCross = value.toString();
                return;
            case 4:
                this.mTriggerID = toInt(value);
                return;
            case 5:
                this.mTriggerCollisionId = toInt(value);
                return;
            case 6:
                this.mTriggerCollisionView = (View) value;
                return;
            case 7:
                this.mTriggerSlack = toFloat(value);
                return;
            case '\b':
                this.mPostLayout = toBoolean(value);
                return;
            case '\t':
                this.mViewTransitionOnNegativeCross = toInt(value);
                return;
            case '\n':
                this.mViewTransitionOnPositiveCross = toInt(value);
                return;
            case 11:
                this.mViewTransitionOnCross = toInt(value);
                return;
            default:
                return;
        }
    }

    private void setUpRect(RectF rect, View child, boolean postLayout) {
        rect.top = child.getTop();
        rect.bottom = child.getBottom();
        rect.left = child.getLeft();
        rect.right = child.getRight();
        if (postLayout) {
            child.getMatrix().mapRect(rect);
        }
    }

    public void conditionallyFire(float pos, View child) {
        boolean fireCross = false;
        boolean fireNegative = false;
        boolean firePositive = false;
        if (this.mTriggerCollisionId != UNSET) {
            if (this.mTriggerCollisionView == null) {
                this.mTriggerCollisionView = ((ViewGroup) child.getParent()).findViewById(this.mTriggerCollisionId);
            }
            setUpRect(this.mCollisionRect, this.mTriggerCollisionView, this.mPostLayout);
            setUpRect(this.mTargetRect, child, this.mPostLayout);
            boolean in = this.mCollisionRect.intersect(this.mTargetRect);
            if (in) {
                if (this.mFireCrossReset) {
                    fireCross = true;
                    this.mFireCrossReset = false;
                }
                if (this.mFirePositiveReset) {
                    firePositive = true;
                    this.mFirePositiveReset = false;
                }
                this.mFireNegativeReset = true;
            } else {
                if (!this.mFireCrossReset) {
                    fireCross = true;
                    this.mFireCrossReset = true;
                }
                if (this.mFireNegativeReset) {
                    fireNegative = true;
                    this.mFireNegativeReset = false;
                }
                this.mFirePositiveReset = true;
            }
        } else {
            if (this.mFireCrossReset) {
                float f = this.mFireThreshold;
                float lastOffset = this.mFireLastPos - f;
                if ((pos - f) * lastOffset < 0.0f) {
                    fireCross = true;
                    this.mFireCrossReset = false;
                }
            } else if (Math.abs(pos - this.mFireThreshold) > this.mTriggerSlack) {
                this.mFireCrossReset = true;
            }
            if (this.mFireNegativeReset) {
                float f2 = this.mFireThreshold;
                float offset = pos - f2;
                float lastOffset2 = this.mFireLastPos - f2;
                if (offset * lastOffset2 < 0.0f && offset < 0.0f) {
                    fireNegative = true;
                    this.mFireNegativeReset = false;
                }
            } else if (Math.abs(pos - this.mFireThreshold) > this.mTriggerSlack) {
                this.mFireNegativeReset = true;
            }
            if (this.mFirePositiveReset) {
                float f3 = this.mFireThreshold;
                float offset2 = pos - f3;
                float lastOffset3 = this.mFireLastPos - f3;
                if (offset2 * lastOffset3 < 0.0f && offset2 > 0.0f) {
                    firePositive = true;
                    this.mFirePositiveReset = false;
                }
            } else if (Math.abs(pos - this.mFireThreshold) > this.mTriggerSlack) {
                this.mFirePositiveReset = true;
            }
        }
        this.mFireLastPos = pos;
        if (fireNegative || fireCross || firePositive) {
            ((MotionLayout) child.getParent()).fireTrigger(this.mTriggerID, firePositive, pos);
        }
        View call = this.mTriggerReceiver == UNSET ? child : ((MotionLayout) child.getParent()).findViewById(this.mTriggerReceiver);
        if (fireNegative) {
            String str = this.mNegativeCross;
            if (str != null) {
                fire(str, call);
            }
            if (this.mViewTransitionOnNegativeCross != UNSET) {
                ((MotionLayout) child.getParent()).viewTransition(this.mViewTransitionOnNegativeCross, call);
            }
        }
        if (firePositive) {
            String str2 = this.mPositiveCross;
            if (str2 != null) {
                fire(str2, call);
            }
            if (this.mViewTransitionOnPositiveCross != UNSET) {
                ((MotionLayout) child.getParent()).viewTransition(this.mViewTransitionOnPositiveCross, call);
            }
        }
        if (fireCross) {
            String str3 = this.mCross;
            if (str3 != null) {
                fire(str3, call);
            }
            if (this.mViewTransitionOnCross != UNSET) {
                ((MotionLayout) child.getParent()).viewTransition(this.mViewTransitionOnCross, call);
            }
        }
    }

    private void fire(String str, View call) {
        if (str == null) {
            return;
        }
        if (str.startsWith(".")) {
            fireCustom(str, call);
            return;
        }
        Method method = null;
        if (this.mMethodHashMap.containsKey(str)) {
            Method method2 = this.mMethodHashMap.get(str);
            method = method2;
            if (method == null) {
                return;
            }
        }
        if (method == null) {
            try {
                method = call.getClass().getMethod(str, new Class[0]);
                this.mMethodHashMap.put(str, method);
            } catch (NoSuchMethodException e) {
                this.mMethodHashMap.put(str, null);
                Log.e(TypedValues.TriggerType.NAME, "Could not find method \"" + str + "\"on class " + call.getClass().getSimpleName() + " " + Debug.getName(call));
                return;
            }
        }
        try {
            method.invoke(call, new Object[0]);
        } catch (Exception e2) {
            Log.e(TypedValues.TriggerType.NAME, "Exception in call \"" + this.mCross + "\"on class " + call.getClass().getSimpleName() + " " + Debug.getName(call));
        }
    }

    private void fireCustom(String str, View view) {
        boolean callAll = str.length() == 1;
        if (!callAll) {
            str = str.substring(1).toLowerCase(Locale.ROOT);
        }
        for (String name : this.mCustomConstraints.keySet()) {
            String lowerCase = name.toLowerCase(Locale.ROOT);
            if (callAll || lowerCase.matches(str)) {
                ConstraintAttribute custom = this.mCustomConstraints.get(name);
                if (custom != null) {
                    custom.applyCustom(view);
                }
            }
        }
    }

    /* loaded from: classes.dex */
    private static class Loader {
        private static final int COLLISION = 9;
        private static final int CROSS = 4;
        private static final int FRAME_POS = 8;
        private static final int NEGATIVE_CROSS = 1;
        private static final int POSITIVE_CROSS = 2;
        private static final int POST_LAYOUT = 10;
        private static final int TARGET_ID = 7;
        private static final int TRIGGER_ID = 6;
        private static final int TRIGGER_RECEIVER = 11;
        private static final int TRIGGER_SLACK = 5;
        private static final int VT_CROSS = 12;
        private static final int VT_NEGATIVE_CROSS = 13;
        private static final int VT_POSITIVE_CROSS = 14;
        private static SparseIntArray mAttrMap;

        private Loader() {
        }

        static {
            SparseIntArray sparseIntArray = new SparseIntArray();
            mAttrMap = sparseIntArray;
            sparseIntArray.append(R.styleable.KeyTrigger_framePosition, 8);
            mAttrMap.append(R.styleable.KeyTrigger_onCross, 4);
            mAttrMap.append(R.styleable.KeyTrigger_onNegativeCross, 1);
            mAttrMap.append(R.styleable.KeyTrigger_onPositiveCross, 2);
            mAttrMap.append(R.styleable.KeyTrigger_motionTarget, 7);
            mAttrMap.append(R.styleable.KeyTrigger_triggerId, 6);
            mAttrMap.append(R.styleable.KeyTrigger_triggerSlack, 5);
            mAttrMap.append(R.styleable.KeyTrigger_motion_triggerOnCollision, 9);
            mAttrMap.append(R.styleable.KeyTrigger_motion_postLayoutCollision, 10);
            mAttrMap.append(R.styleable.KeyTrigger_triggerReceiver, 11);
            mAttrMap.append(R.styleable.KeyTrigger_viewTransitionOnCross, 12);
            mAttrMap.append(R.styleable.KeyTrigger_viewTransitionOnNegativeCross, 13);
            mAttrMap.append(R.styleable.KeyTrigger_viewTransitionOnPositiveCross, 14);
        }

        public static void read(KeyTrigger c, TypedArray a, Context context) {
            int N = a.getIndexCount();
            for (int i = 0; i < N; i++) {
                int attr = a.getIndex(i);
                switch (mAttrMap.get(attr)) {
                    case 1:
                        c.mNegativeCross = a.getString(attr);
                        break;
                    case 2:
                        c.mPositiveCross = a.getString(attr);
                        break;
                    case 3:
                    default:
                        Log.e(TypedValues.TriggerType.NAME, "unused attribute 0x" + Integer.toHexString(attr) + "   " + mAttrMap.get(attr));
                        break;
                    case 4:
                        c.mCross = a.getString(attr);
                        break;
                    case 5:
                        c.mTriggerSlack = a.getFloat(attr, c.mTriggerSlack);
                        break;
                    case 6:
                        c.mTriggerID = a.getResourceId(attr, c.mTriggerID);
                        break;
                    case 7:
                        if (MotionLayout.IS_IN_EDIT_MODE) {
                            c.mTargetId = a.getResourceId(attr, c.mTargetId);
                            if (c.mTargetId == -1) {
                                c.mTargetString = a.getString(attr);
                                break;
                            } else {
                                break;
                            }
                        } else if (a.peekValue(attr).type == 3) {
                            c.mTargetString = a.getString(attr);
                            break;
                        } else {
                            c.mTargetId = a.getResourceId(attr, c.mTargetId);
                            break;
                        }
                    case 8:
                        c.mFramePosition = a.getInteger(attr, c.mFramePosition);
                        c.mFireThreshold = (c.mFramePosition + 0.5f) / 100.0f;
                        break;
                    case 9:
                        c.mTriggerCollisionId = a.getResourceId(attr, c.mTriggerCollisionId);
                        break;
                    case 10:
                        c.mPostLayout = a.getBoolean(attr, c.mPostLayout);
                        break;
                    case 11:
                        c.mTriggerReceiver = a.getResourceId(attr, c.mTriggerReceiver);
                        break;
                    case 12:
                        c.mViewTransitionOnCross = a.getResourceId(attr, c.mViewTransitionOnCross);
                        break;
                    case 13:
                        c.mViewTransitionOnNegativeCross = a.getResourceId(attr, c.mViewTransitionOnNegativeCross);
                        break;
                    case 14:
                        c.mViewTransitionOnPositiveCross = a.getResourceId(attr, c.mViewTransitionOnPositiveCross);
                        break;
                }
            }
        }
    }

    @Override // androidx.constraintlayout.motion.widget.Key
    public Key copy(Key src) {
        super.copy(src);
        KeyTrigger k = (KeyTrigger) src;
        this.mCurveFit = k.mCurveFit;
        this.mCross = k.mCross;
        this.mTriggerReceiver = k.mTriggerReceiver;
        this.mNegativeCross = k.mNegativeCross;
        this.mPositiveCross = k.mPositiveCross;
        this.mTriggerID = k.mTriggerID;
        this.mTriggerCollisionId = k.mTriggerCollisionId;
        this.mTriggerCollisionView = k.mTriggerCollisionView;
        this.mTriggerSlack = k.mTriggerSlack;
        this.mFireCrossReset = k.mFireCrossReset;
        this.mFireNegativeReset = k.mFireNegativeReset;
        this.mFirePositiveReset = k.mFirePositiveReset;
        this.mFireThreshold = k.mFireThreshold;
        this.mFireLastPos = k.mFireLastPos;
        this.mPostLayout = k.mPostLayout;
        this.mCollisionRect = k.mCollisionRect;
        this.mTargetRect = k.mTargetRect;
        this.mMethodHashMap = k.mMethodHashMap;
        return this;
    }

    @Override // androidx.constraintlayout.motion.widget.Key
    /* renamed from: clone */
    public Key mo4clone() {
        return new KeyTrigger().copy(this);
    }
}
