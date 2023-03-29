package androidx.constraintlayout.motion.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.os.Build;
import android.util.AttributeSet;
import android.util.Log;
import android.util.SparseIntArray;
import android.util.TypedValue;
import androidx.constraintlayout.core.motion.utils.SplineSet;
import androidx.constraintlayout.core.motion.utils.TypedValues;
import androidx.constraintlayout.motion.utils.ViewOscillator;
import androidx.constraintlayout.motion.utils.ViewSpline;
import androidx.constraintlayout.widget.ConstraintAttribute;
import androidx.constraintlayout.widget.R;
import java.util.HashMap;
import java.util.HashSet;
/* loaded from: classes.dex */
public class KeyCycle extends Key {
    public static final int KEY_TYPE = 4;
    static final String NAME = "KeyCycle";
    public static final int SHAPE_BOUNCE = 6;
    public static final int SHAPE_COS_WAVE = 5;
    public static final int SHAPE_REVERSE_SAW_WAVE = 4;
    public static final int SHAPE_SAW_WAVE = 3;
    public static final int SHAPE_SIN_WAVE = 0;
    public static final int SHAPE_SQUARE_WAVE = 1;
    public static final int SHAPE_TRIANGLE_WAVE = 2;
    private static final String TAG = "KeyCycle";
    public static final String WAVE_OFFSET = "waveOffset";
    public static final String WAVE_PERIOD = "wavePeriod";
    public static final String WAVE_PHASE = "wavePhase";
    public static final String WAVE_SHAPE = "waveShape";
    private String mTransitionEasing = null;
    private int mCurveFit = 0;
    private int mWaveShape = -1;
    private String mCustomWaveShape = null;
    private float mWavePeriod = Float.NaN;
    private float mWaveOffset = 0.0f;
    private float mWavePhase = 0.0f;
    private float mProgress = Float.NaN;
    private int mWaveVariesBy = -1;
    private float mAlpha = Float.NaN;
    private float mElevation = Float.NaN;
    private float mRotation = Float.NaN;
    private float mTransitionPathRotate = Float.NaN;
    private float mRotationX = Float.NaN;
    private float mRotationY = Float.NaN;
    private float mScaleX = Float.NaN;
    private float mScaleY = Float.NaN;
    private float mTranslationX = Float.NaN;
    private float mTranslationY = Float.NaN;
    private float mTranslationZ = Float.NaN;

    public KeyCycle() {
        this.mType = 4;
        this.mCustomConstraints = new HashMap<>();
    }

    @Override // androidx.constraintlayout.motion.widget.Key
    public void load(Context context, AttributeSet attrs) {
        TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.KeyCycle);
        Loader.read(this, a);
    }

    @Override // androidx.constraintlayout.motion.widget.Key
    public void getAttributeNames(HashSet<String> attributes) {
        if (!Float.isNaN(this.mAlpha)) {
            attributes.add("alpha");
        }
        if (!Float.isNaN(this.mElevation)) {
            attributes.add("elevation");
        }
        if (!Float.isNaN(this.mRotation)) {
            attributes.add(Key.ROTATION);
        }
        if (!Float.isNaN(this.mRotationX)) {
            attributes.add("rotationX");
        }
        if (!Float.isNaN(this.mRotationY)) {
            attributes.add("rotationY");
        }
        if (!Float.isNaN(this.mScaleX)) {
            attributes.add("scaleX");
        }
        if (!Float.isNaN(this.mScaleY)) {
            attributes.add("scaleY");
        }
        if (!Float.isNaN(this.mTransitionPathRotate)) {
            attributes.add("transitionPathRotate");
        }
        if (!Float.isNaN(this.mTranslationX)) {
            attributes.add("translationX");
        }
        if (!Float.isNaN(this.mTranslationY)) {
            attributes.add("translationY");
        }
        if (!Float.isNaN(this.mTranslationZ)) {
            attributes.add("translationZ");
        }
        if (this.mCustomConstraints.size() > 0) {
            for (String s : this.mCustomConstraints.keySet()) {
                attributes.add("CUSTOM," + s);
            }
        }
    }

    public void addCycleValues(HashMap<String, ViewOscillator> oscSet) {
        ViewOscillator osc;
        ViewOscillator osc2;
        for (String key : oscSet.keySet()) {
            if (key.startsWith("CUSTOM")) {
                String customKey = key.substring("CUSTOM".length() + 1);
                ConstraintAttribute cValue = this.mCustomConstraints.get(customKey);
                if (cValue != null && cValue.getType() == ConstraintAttribute.AttributeType.FLOAT_TYPE && (osc = oscSet.get(key)) != null) {
                    osc.setPoint(this.mFramePosition, this.mWaveShape, this.mCustomWaveShape, this.mWaveVariesBy, this.mWavePeriod, this.mWaveOffset, this.mWavePhase, cValue.getValueToInterpolate(), cValue);
                }
            } else {
                float value = getValue(key);
                if (!Float.isNaN(value) && (osc2 = oscSet.get(key)) != null) {
                    osc2.setPoint(this.mFramePosition, this.mWaveShape, this.mCustomWaveShape, this.mWaveVariesBy, this.mWavePeriod, this.mWaveOffset, this.mWavePhase, value);
                }
            }
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    public float getValue(String key) {
        char c;
        switch (key.hashCode()) {
            case -1249320806:
                if (key.equals("rotationX")) {
                    c = 3;
                    break;
                }
                c = 65535;
                break;
            case -1249320805:
                if (key.equals("rotationY")) {
                    c = 4;
                    break;
                }
                c = 65535;
                break;
            case -1225497657:
                if (key.equals("translationX")) {
                    c = '\b';
                    break;
                }
                c = 65535;
                break;
            case -1225497656:
                if (key.equals("translationY")) {
                    c = '\t';
                    break;
                }
                c = 65535;
                break;
            case -1225497655:
                if (key.equals("translationZ")) {
                    c = '\n';
                    break;
                }
                c = 65535;
                break;
            case -1001078227:
                if (key.equals("progress")) {
                    c = '\r';
                    break;
                }
                c = 65535;
                break;
            case -908189618:
                if (key.equals("scaleX")) {
                    c = 6;
                    break;
                }
                c = 65535;
                break;
            case -908189617:
                if (key.equals("scaleY")) {
                    c = 7;
                    break;
                }
                c = 65535;
                break;
            case -40300674:
                if (key.equals(Key.ROTATION)) {
                    c = 2;
                    break;
                }
                c = 65535;
                break;
            case -4379043:
                if (key.equals("elevation")) {
                    c = 1;
                    break;
                }
                c = 65535;
                break;
            case 37232917:
                if (key.equals("transitionPathRotate")) {
                    c = 5;
                    break;
                }
                c = 65535;
                break;
            case 92909918:
                if (key.equals("alpha")) {
                    c = 0;
                    break;
                }
                c = 65535;
                break;
            case 156108012:
                if (key.equals("waveOffset")) {
                    c = 11;
                    break;
                }
                c = 65535;
                break;
            case 1530034690:
                if (key.equals("wavePhase")) {
                    c = '\f';
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
                return this.mAlpha;
            case 1:
                return this.mElevation;
            case 2:
                return this.mRotation;
            case 3:
                return this.mRotationX;
            case 4:
                return this.mRotationY;
            case 5:
                return this.mTransitionPathRotate;
            case 6:
                return this.mScaleX;
            case 7:
                return this.mScaleY;
            case '\b':
                return this.mTranslationX;
            case '\t':
                return this.mTranslationY;
            case '\n':
                return this.mTranslationZ;
            case 11:
                return this.mWaveOffset;
            case '\f':
                return this.mWavePhase;
            case '\r':
                return this.mProgress;
            default:
                if (!key.startsWith("CUSTOM")) {
                    Log.v("WARNING! KeyCycle", "  UNKNOWN  " + key);
                    return Float.NaN;
                }
                return Float.NaN;
        }
    }

    @Override // androidx.constraintlayout.motion.widget.Key
    public void addValues(HashMap<String, ViewSpline> splines) {
        Debug.logStack(TypedValues.CycleType.NAME, "add " + splines.size() + " values", 2);
        for (String s : splines.keySet()) {
            SplineSet splineSet = splines.get(s);
            if (splineSet != null) {
                char c = 65535;
                switch (s.hashCode()) {
                    case -1249320806:
                        if (s.equals("rotationX")) {
                            c = 3;
                            break;
                        }
                        break;
                    case -1249320805:
                        if (s.equals("rotationY")) {
                            c = 4;
                            break;
                        }
                        break;
                    case -1225497657:
                        if (s.equals("translationX")) {
                            c = '\b';
                            break;
                        }
                        break;
                    case -1225497656:
                        if (s.equals("translationY")) {
                            c = '\t';
                            break;
                        }
                        break;
                    case -1225497655:
                        if (s.equals("translationZ")) {
                            c = '\n';
                            break;
                        }
                        break;
                    case -1001078227:
                        if (s.equals("progress")) {
                            c = '\r';
                            break;
                        }
                        break;
                    case -908189618:
                        if (s.equals("scaleX")) {
                            c = 6;
                            break;
                        }
                        break;
                    case -908189617:
                        if (s.equals("scaleY")) {
                            c = 7;
                            break;
                        }
                        break;
                    case -40300674:
                        if (s.equals(Key.ROTATION)) {
                            c = 2;
                            break;
                        }
                        break;
                    case -4379043:
                        if (s.equals("elevation")) {
                            c = 1;
                            break;
                        }
                        break;
                    case 37232917:
                        if (s.equals("transitionPathRotate")) {
                            c = 5;
                            break;
                        }
                        break;
                    case 92909918:
                        if (s.equals("alpha")) {
                            c = 0;
                            break;
                        }
                        break;
                    case 156108012:
                        if (s.equals("waveOffset")) {
                            c = 11;
                            break;
                        }
                        break;
                    case 1530034690:
                        if (s.equals("wavePhase")) {
                            c = '\f';
                            break;
                        }
                        break;
                }
                switch (c) {
                    case 0:
                        splineSet.setPoint(this.mFramePosition, this.mAlpha);
                        continue;
                    case 1:
                        splineSet.setPoint(this.mFramePosition, this.mElevation);
                        continue;
                    case 2:
                        splineSet.setPoint(this.mFramePosition, this.mRotation);
                        continue;
                    case 3:
                        splineSet.setPoint(this.mFramePosition, this.mRotationX);
                        continue;
                    case 4:
                        splineSet.setPoint(this.mFramePosition, this.mRotationY);
                        continue;
                    case 5:
                        splineSet.setPoint(this.mFramePosition, this.mTransitionPathRotate);
                        continue;
                    case 6:
                        splineSet.setPoint(this.mFramePosition, this.mScaleX);
                        continue;
                    case 7:
                        splineSet.setPoint(this.mFramePosition, this.mScaleY);
                        continue;
                    case '\b':
                        splineSet.setPoint(this.mFramePosition, this.mTranslationX);
                        continue;
                    case '\t':
                        splineSet.setPoint(this.mFramePosition, this.mTranslationY);
                        continue;
                    case '\n':
                        splineSet.setPoint(this.mFramePosition, this.mTranslationZ);
                        continue;
                    case 11:
                        splineSet.setPoint(this.mFramePosition, this.mWaveOffset);
                        continue;
                    case '\f':
                        splineSet.setPoint(this.mFramePosition, this.mWavePhase);
                        continue;
                    case '\r':
                        splineSet.setPoint(this.mFramePosition, this.mProgress);
                        continue;
                    default:
                        if (!s.startsWith("CUSTOM")) {
                            Log.v("WARNING KeyCycle", "  UNKNOWN  " + s);
                            break;
                        } else {
                            continue;
                        }
                }
            }
        }
    }

    /* loaded from: classes.dex */
    private static class Loader {
        private static final int ANDROID_ALPHA = 9;
        private static final int ANDROID_ELEVATION = 10;
        private static final int ANDROID_ROTATION = 11;
        private static final int ANDROID_ROTATION_X = 12;
        private static final int ANDROID_ROTATION_Y = 13;
        private static final int ANDROID_SCALE_X = 15;
        private static final int ANDROID_SCALE_Y = 16;
        private static final int ANDROID_TRANSLATION_X = 17;
        private static final int ANDROID_TRANSLATION_Y = 18;
        private static final int ANDROID_TRANSLATION_Z = 19;
        private static final int CURVE_FIT = 4;
        private static final int FRAME_POSITION = 2;
        private static final int PROGRESS = 20;
        private static final int TARGET_ID = 1;
        private static final int TRANSITION_EASING = 3;
        private static final int TRANSITION_PATH_ROTATE = 14;
        private static final int WAVE_OFFSET = 7;
        private static final int WAVE_PERIOD = 6;
        private static final int WAVE_PHASE = 21;
        private static final int WAVE_SHAPE = 5;
        private static final int WAVE_VARIES_BY = 8;
        private static SparseIntArray mAttrMap;

        private Loader() {
        }

        static {
            SparseIntArray sparseIntArray = new SparseIntArray();
            mAttrMap = sparseIntArray;
            sparseIntArray.append(R.styleable.KeyCycle_motionTarget, 1);
            mAttrMap.append(R.styleable.KeyCycle_framePosition, 2);
            mAttrMap.append(R.styleable.KeyCycle_transitionEasing, 3);
            mAttrMap.append(R.styleable.KeyCycle_curveFit, 4);
            mAttrMap.append(R.styleable.KeyCycle_waveShape, 5);
            mAttrMap.append(R.styleable.KeyCycle_wavePeriod, 6);
            mAttrMap.append(R.styleable.KeyCycle_waveOffset, 7);
            mAttrMap.append(R.styleable.KeyCycle_waveVariesBy, 8);
            mAttrMap.append(R.styleable.KeyCycle_android_alpha, 9);
            mAttrMap.append(R.styleable.KeyCycle_android_elevation, 10);
            mAttrMap.append(R.styleable.KeyCycle_android_rotation, 11);
            mAttrMap.append(R.styleable.KeyCycle_android_rotationX, 12);
            mAttrMap.append(R.styleable.KeyCycle_android_rotationY, 13);
            mAttrMap.append(R.styleable.KeyCycle_transitionPathRotate, 14);
            mAttrMap.append(R.styleable.KeyCycle_android_scaleX, 15);
            mAttrMap.append(R.styleable.KeyCycle_android_scaleY, 16);
            mAttrMap.append(R.styleable.KeyCycle_android_translationX, 17);
            mAttrMap.append(R.styleable.KeyCycle_android_translationY, 18);
            mAttrMap.append(R.styleable.KeyCycle_android_translationZ, 19);
            mAttrMap.append(R.styleable.KeyCycle_motionProgress, 20);
            mAttrMap.append(R.styleable.KeyCycle_wavePhase, 21);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static void read(KeyCycle c, TypedArray a) {
            int N = a.getIndexCount();
            for (int i = 0; i < N; i++) {
                int attr = a.getIndex(i);
                switch (mAttrMap.get(attr)) {
                    case 1:
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
                    case 2:
                        c.mFramePosition = a.getInt(attr, c.mFramePosition);
                        break;
                    case 3:
                        c.mTransitionEasing = a.getString(attr);
                        break;
                    case 4:
                        c.mCurveFit = a.getInteger(attr, c.mCurveFit);
                        break;
                    case 5:
                        if (a.peekValue(attr).type == 3) {
                            c.mCustomWaveShape = a.getString(attr);
                            c.mWaveShape = 7;
                            break;
                        } else {
                            c.mWaveShape = a.getInt(attr, c.mWaveShape);
                            break;
                        }
                    case 6:
                        c.mWavePeriod = a.getFloat(attr, c.mWavePeriod);
                        break;
                    case 7:
                        TypedValue type = a.peekValue(attr);
                        if (type.type == 5) {
                            c.mWaveOffset = a.getDimension(attr, c.mWaveOffset);
                            break;
                        } else {
                            c.mWaveOffset = a.getFloat(attr, c.mWaveOffset);
                            break;
                        }
                    case 8:
                        c.mWaveVariesBy = a.getInt(attr, c.mWaveVariesBy);
                        break;
                    case 9:
                        c.mAlpha = a.getFloat(attr, c.mAlpha);
                        break;
                    case 10:
                        c.mElevation = a.getDimension(attr, c.mElevation);
                        break;
                    case 11:
                        c.mRotation = a.getFloat(attr, c.mRotation);
                        break;
                    case 12:
                        c.mRotationX = a.getFloat(attr, c.mRotationX);
                        break;
                    case 13:
                        c.mRotationY = a.getFloat(attr, c.mRotationY);
                        break;
                    case 14:
                        c.mTransitionPathRotate = a.getFloat(attr, c.mTransitionPathRotate);
                        break;
                    case 15:
                        c.mScaleX = a.getFloat(attr, c.mScaleX);
                        break;
                    case 16:
                        c.mScaleY = a.getFloat(attr, c.mScaleY);
                        break;
                    case 17:
                        c.mTranslationX = a.getDimension(attr, c.mTranslationX);
                        break;
                    case 18:
                        c.mTranslationY = a.getDimension(attr, c.mTranslationY);
                        break;
                    case 19:
                        if (Build.VERSION.SDK_INT >= 21) {
                            c.mTranslationZ = a.getDimension(attr, c.mTranslationZ);
                            break;
                        } else {
                            break;
                        }
                    case 20:
                        c.mProgress = a.getFloat(attr, c.mProgress);
                        break;
                    case 21:
                        c.mWavePhase = a.getFloat(attr, c.mWavePhase) / 360.0f;
                        break;
                    default:
                        Log.e(TypedValues.CycleType.NAME, "unused attribute 0x" + Integer.toHexString(attr) + "   " + mAttrMap.get(attr));
                        break;
                }
            }
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    @Override // androidx.constraintlayout.motion.widget.Key
    public void setValue(String tag, Object value) {
        char c;
        switch (tag.hashCode()) {
            case -1913008125:
                if (tag.equals(Key.MOTIONPROGRESS)) {
                    c = 3;
                    break;
                }
                c = 65535;
                break;
            case -1812823328:
                if (tag.equals("transitionEasing")) {
                    c = '\t';
                    break;
                }
                c = 65535;
                break;
            case -1249320806:
                if (tag.equals("rotationX")) {
                    c = 5;
                    break;
                }
                c = 65535;
                break;
            case -1249320805:
                if (tag.equals("rotationY")) {
                    c = 6;
                    break;
                }
                c = 65535;
                break;
            case -1225497657:
                if (tag.equals("translationX")) {
                    c = 11;
                    break;
                }
                c = 65535;
                break;
            case -1225497656:
                if (tag.equals("translationY")) {
                    c = '\f';
                    break;
                }
                c = 65535;
                break;
            case -1225497655:
                if (tag.equals("translationZ")) {
                    c = '\r';
                    break;
                }
                c = 65535;
                break;
            case -908189618:
                if (tag.equals("scaleX")) {
                    c = 7;
                    break;
                }
                c = 65535;
                break;
            case -908189617:
                if (tag.equals("scaleY")) {
                    c = '\b';
                    break;
                }
                c = 65535;
                break;
            case -40300674:
                if (tag.equals(Key.ROTATION)) {
                    c = 4;
                    break;
                }
                c = 65535;
                break;
            case -4379043:
                if (tag.equals("elevation")) {
                    c = 2;
                    break;
                }
                c = 65535;
                break;
            case 37232917:
                if (tag.equals("transitionPathRotate")) {
                    c = '\n';
                    break;
                }
                c = 65535;
                break;
            case 92909918:
                if (tag.equals("alpha")) {
                    c = 0;
                    break;
                }
                c = 65535;
                break;
            case 156108012:
                if (tag.equals("waveOffset")) {
                    c = 15;
                    break;
                }
                c = 65535;
                break;
            case 184161818:
                if (tag.equals("wavePeriod")) {
                    c = 14;
                    break;
                }
                c = 65535;
                break;
            case 579057826:
                if (tag.equals("curveFit")) {
                    c = 1;
                    break;
                }
                c = 65535;
                break;
            case 1530034690:
                if (tag.equals("wavePhase")) {
                    c = 16;
                    break;
                }
                c = 65535;
                break;
            case 1532805160:
                if (tag.equals("waveShape")) {
                    c = 17;
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
                this.mAlpha = toFloat(value);
                return;
            case 1:
                this.mCurveFit = toInt(value);
                return;
            case 2:
                this.mElevation = toFloat(value);
                return;
            case 3:
                this.mProgress = toFloat(value);
                return;
            case 4:
                this.mRotation = toFloat(value);
                return;
            case 5:
                this.mRotationX = toFloat(value);
                return;
            case 6:
                this.mRotationY = toFloat(value);
                return;
            case 7:
                this.mScaleX = toFloat(value);
                return;
            case '\b':
                this.mScaleY = toFloat(value);
                return;
            case '\t':
                this.mTransitionEasing = value.toString();
                return;
            case '\n':
                this.mTransitionPathRotate = toFloat(value);
                return;
            case 11:
                this.mTranslationX = toFloat(value);
                return;
            case '\f':
                this.mTranslationY = toFloat(value);
                return;
            case '\r':
                this.mTranslationZ = toFloat(value);
                return;
            case 14:
                this.mWavePeriod = toFloat(value);
                return;
            case 15:
                this.mWaveOffset = toFloat(value);
                return;
            case 16:
                this.mWavePhase = toFloat(value);
                return;
            case 17:
                if (value instanceof Integer) {
                    this.mWaveShape = toInt(value);
                    return;
                }
                this.mWaveShape = 7;
                this.mCustomWaveShape = value.toString();
                return;
            default:
                return;
        }
    }

    @Override // androidx.constraintlayout.motion.widget.Key
    public Key copy(Key src) {
        super.copy(src);
        KeyCycle k = (KeyCycle) src;
        this.mTransitionEasing = k.mTransitionEasing;
        this.mCurveFit = k.mCurveFit;
        this.mWaveShape = k.mWaveShape;
        this.mCustomWaveShape = k.mCustomWaveShape;
        this.mWavePeriod = k.mWavePeriod;
        this.mWaveOffset = k.mWaveOffset;
        this.mWavePhase = k.mWavePhase;
        this.mProgress = k.mProgress;
        this.mWaveVariesBy = k.mWaveVariesBy;
        this.mAlpha = k.mAlpha;
        this.mElevation = k.mElevation;
        this.mRotation = k.mRotation;
        this.mTransitionPathRotate = k.mTransitionPathRotate;
        this.mRotationX = k.mRotationX;
        this.mRotationY = k.mRotationY;
        this.mScaleX = k.mScaleX;
        this.mScaleY = k.mScaleY;
        this.mTranslationX = k.mTranslationX;
        this.mTranslationY = k.mTranslationY;
        this.mTranslationZ = k.mTranslationZ;
        return this;
    }

    @Override // androidx.constraintlayout.motion.widget.Key
    /* renamed from: clone */
    public Key mo4clone() {
        return new KeyCycle().copy(this);
    }
}
