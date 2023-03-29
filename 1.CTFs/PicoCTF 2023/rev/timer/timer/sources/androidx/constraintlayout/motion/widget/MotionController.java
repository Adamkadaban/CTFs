package androidx.constraintlayout.motion.widget;

import android.content.Context;
import android.graphics.Rect;
import android.graphics.RectF;
import android.util.Log;
import android.util.SparseArray;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.AnimationUtils;
import android.view.animation.BounceInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.Interpolator;
import android.view.animation.OvershootInterpolator;
import androidx.constraintlayout.core.motion.utils.CurveFit;
import androidx.constraintlayout.core.motion.utils.Easing;
import androidx.constraintlayout.core.motion.utils.SplineSet;
import androidx.constraintlayout.core.motion.utils.VelocityMatrix;
import androidx.constraintlayout.motion.utils.ViewOscillator;
import androidx.constraintlayout.motion.utils.ViewSpline;
import androidx.constraintlayout.motion.utils.ViewState;
import androidx.constraintlayout.motion.utils.ViewTimeCycle;
import androidx.constraintlayout.widget.ConstraintAttribute;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.ConstraintSet;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
/* loaded from: classes.dex */
public class MotionController {
    static final int BOUNCE = 4;
    private static final boolean DEBUG = false;
    public static final int DRAW_PATH_AS_CONFIGURED = 4;
    public static final int DRAW_PATH_BASIC = 1;
    public static final int DRAW_PATH_CARTESIAN = 3;
    public static final int DRAW_PATH_NONE = 0;
    public static final int DRAW_PATH_RECTANGLE = 5;
    public static final int DRAW_PATH_RELATIVE = 2;
    public static final int DRAW_PATH_SCREEN = 6;
    static final int EASE_IN = 1;
    static final int EASE_IN_OUT = 0;
    static final int EASE_OUT = 2;
    private static final boolean FAVOR_FIXED_SIZE_VIEWS = false;
    public static final int HORIZONTAL_PATH_X = 2;
    public static final int HORIZONTAL_PATH_Y = 3;
    private static final int INTERPOLATOR_REFERENCE_ID = -2;
    private static final int INTERPOLATOR_UNDEFINED = -3;
    static final int LINEAR = 3;
    static final int OVERSHOOT = 5;
    public static final int PATH_PERCENT = 0;
    public static final int PATH_PERPENDICULAR = 1;
    public static final int ROTATION_LEFT = 2;
    public static final int ROTATION_RIGHT = 1;
    private static final int SPLINE_STRING = -1;
    private static final String TAG = "MotionController";
    public static final int VERTICAL_PATH_X = 4;
    public static final int VERTICAL_PATH_Y = 5;
    String[] attributeTable;
    private CurveFit mArcSpline;
    private int[] mAttributeInterpolatorCount;
    private String[] mAttributeNames;
    private HashMap<String, ViewSpline> mAttributesMap;
    String mConstraintTag;
    float mCurrentCenterX;
    float mCurrentCenterY;
    private HashMap<String, ViewOscillator> mCycleMap;
    int mId;
    private double[] mInterpolateData;
    private int[] mInterpolateVariables;
    private double[] mInterpolateVelocity;
    private KeyTrigger[] mKeyTriggers;
    private CurveFit[] mSpline;
    private HashMap<String, ViewTimeCycle> mTimeCycleAttributesMap;
    View mView;
    Rect mTempRect = new Rect();
    boolean mForceMeasure = false;
    private int mCurveFitType = -1;
    private MotionPaths mStartMotionPath = new MotionPaths();
    private MotionPaths mEndMotionPath = new MotionPaths();
    private MotionConstrainedPoint mStartPoint = new MotionConstrainedPoint();
    private MotionConstrainedPoint mEndPoint = new MotionConstrainedPoint();
    float mMotionStagger = Float.NaN;
    float mStaggerOffset = 0.0f;
    float mStaggerScale = 1.0f;
    private int MAX_DIMENSION = 4;
    private float[] mValuesBuff = new float[4];
    private ArrayList<MotionPaths> mMotionPaths = new ArrayList<>();
    private float[] mVelocity = new float[1];
    private ArrayList<Key> mKeyList = new ArrayList<>();
    private int mPathMotionArc = Key.UNSET;
    private int mTransformPivotTarget = Key.UNSET;
    private View mTransformPivotView = null;
    private int mQuantizeMotionSteps = Key.UNSET;
    private float mQuantizeMotionPhase = Float.NaN;
    private Interpolator mQuantizeMotionInterpolator = null;
    private boolean mNoMovement = false;

    public int getTransformPivotTarget() {
        return this.mTransformPivotTarget;
    }

    public void setTransformPivotTarget(int transformPivotTarget) {
        this.mTransformPivotTarget = transformPivotTarget;
        this.mTransformPivotView = null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public MotionPaths getKeyFrame(int i) {
        return this.mMotionPaths.get(i);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public MotionController(View view) {
        setView(view);
    }

    public float getStartX() {
        return this.mStartMotionPath.x;
    }

    public float getStartY() {
        return this.mStartMotionPath.y;
    }

    public float getFinalX() {
        return this.mEndMotionPath.x;
    }

    public float getFinalY() {
        return this.mEndMotionPath.y;
    }

    public float getStartWidth() {
        return this.mStartMotionPath.width;
    }

    public float getStartHeight() {
        return this.mStartMotionPath.height;
    }

    public float getFinalWidth() {
        return this.mEndMotionPath.width;
    }

    public float getFinalHeight() {
        return this.mEndMotionPath.height;
    }

    public int getAnimateRelativeTo() {
        return this.mStartMotionPath.mAnimateRelativeTo;
    }

    public void setupRelative(MotionController motionController) {
        this.mStartMotionPath.setupRelative(motionController, motionController.mStartMotionPath);
        this.mEndMotionPath.setupRelative(motionController, motionController.mEndMotionPath);
    }

    public float getCenterX() {
        return this.mCurrentCenterX;
    }

    public float getCenterY() {
        return this.mCurrentCenterY;
    }

    public void getCenter(double p, float[] pos, float[] vel) {
        double[] position = new double[4];
        double[] velocity = new double[4];
        int[] iArr = new int[4];
        this.mSpline[0].getPos(p, position);
        this.mSpline[0].getSlope(p, velocity);
        Arrays.fill(vel, 0.0f);
        this.mStartMotionPath.getCenter(p, this.mInterpolateVariables, position, pos, velocity, vel);
    }

    public void remeasure() {
        this.mForceMeasure = true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void buildPath(float[] points, int pointCount) {
        float position;
        double p;
        MotionController motionController = this;
        float f = 1.0f;
        float mils = 1.0f / (pointCount - 1);
        HashMap<String, ViewSpline> hashMap = motionController.mAttributesMap;
        SplineSet trans_x = hashMap == null ? null : hashMap.get("translationX");
        HashMap<String, ViewSpline> hashMap2 = motionController.mAttributesMap;
        SplineSet trans_y = hashMap2 == null ? null : hashMap2.get("translationY");
        HashMap<String, ViewOscillator> hashMap3 = motionController.mCycleMap;
        ViewOscillator osc_x = hashMap3 == null ? null : hashMap3.get("translationX");
        HashMap<String, ViewOscillator> hashMap4 = motionController.mCycleMap;
        ViewOscillator osc_y = hashMap4 != null ? hashMap4.get("translationY") : null;
        int i = 0;
        while (i < pointCount) {
            float position2 = i * mils;
            float f2 = motionController.mStaggerScale;
            if (f2 == f) {
                position = position2;
            } else {
                float f3 = motionController.mStaggerOffset;
                if (position2 < f3) {
                    position2 = 0.0f;
                }
                if (position2 > f3 && position2 < 1.0d) {
                    position = Math.min((position2 - f3) * f2, f);
                } else {
                    position = position2;
                }
            }
            double p2 = position;
            Easing easing = motionController.mStartMotionPath.mKeyFrameEasing;
            Iterator<MotionPaths> it = motionController.mMotionPaths.iterator();
            float start = 0.0f;
            Easing easing2 = easing;
            float end = Float.NaN;
            while (it.hasNext()) {
                MotionPaths frame = it.next();
                if (frame.mKeyFrameEasing != null) {
                    if (frame.time < position) {
                        easing2 = frame.mKeyFrameEasing;
                        start = frame.time;
                    } else if (Float.isNaN(end)) {
                        end = frame.time;
                    }
                }
            }
            if (easing2 == null) {
                p = p2;
            } else {
                if (Float.isNaN(end)) {
                    end = 1.0f;
                }
                float offset = (position - start) / (end - start);
                double p3 = offset;
                float offset2 = (float) easing2.get(p3);
                p = ((end - start) * offset2) + start;
            }
            motionController.mSpline[0].getPos(p, motionController.mInterpolateData);
            CurveFit curveFit = motionController.mArcSpline;
            if (curveFit != null) {
                double[] dArr = motionController.mInterpolateData;
                if (dArr.length > 0) {
                    curveFit.getPos(p, dArr);
                }
            }
            float position3 = position;
            motionController.mStartMotionPath.getCenter(p, motionController.mInterpolateVariables, motionController.mInterpolateData, points, i * 2);
            if (osc_x != null) {
                int i2 = i * 2;
                points[i2] = points[i2] + osc_x.get(position3);
            } else if (trans_x != null) {
                int i3 = i * 2;
                points[i3] = points[i3] + trans_x.get(position3);
            }
            if (osc_y != null) {
                int i4 = (i * 2) + 1;
                points[i4] = points[i4] + osc_y.get(position3);
            } else if (trans_y != null) {
                int i5 = (i * 2) + 1;
                points[i5] = points[i5] + trans_y.get(position3);
            }
            i++;
            f = 1.0f;
            motionController = this;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public double[] getPos(double position) {
        this.mSpline[0].getPos(position, this.mInterpolateData);
        CurveFit curveFit = this.mArcSpline;
        if (curveFit != null) {
            double[] dArr = this.mInterpolateData;
            if (dArr.length > 0) {
                curveFit.getPos(position, dArr);
            }
        }
        return this.mInterpolateData;
    }

    void buildBounds(float[] bounds, int pointCount) {
        float mils;
        MotionController motionController = this;
        int i = pointCount;
        float f = 1.0f;
        float mils2 = 1.0f / (i - 1);
        HashMap<String, ViewSpline> hashMap = motionController.mAttributesMap;
        SplineSet trans_x = hashMap == null ? null : hashMap.get("translationX");
        HashMap<String, ViewSpline> hashMap2 = motionController.mAttributesMap;
        if (hashMap2 != null) {
            hashMap2.get("translationY");
        }
        HashMap<String, ViewOscillator> hashMap3 = motionController.mCycleMap;
        if (hashMap3 != null) {
            hashMap3.get("translationX");
        }
        HashMap<String, ViewOscillator> hashMap4 = motionController.mCycleMap;
        if (hashMap4 != null) {
            hashMap4.get("translationY");
        }
        int i2 = 0;
        while (i2 < i) {
            float position = i2 * mils2;
            float f2 = motionController.mStaggerScale;
            if (f2 != f) {
                float f3 = motionController.mStaggerOffset;
                if (position < f3) {
                    position = 0.0f;
                }
                if (position > f3 && position < 1.0d) {
                    position = Math.min((position - f3) * f2, f);
                }
            }
            double p = position;
            Easing easing = motionController.mStartMotionPath.mKeyFrameEasing;
            float start = 0.0f;
            float end = Float.NaN;
            Iterator<MotionPaths> it = motionController.mMotionPaths.iterator();
            while (it.hasNext()) {
                MotionPaths frame = it.next();
                if (frame.mKeyFrameEasing != null) {
                    if (frame.time < position) {
                        Easing easing2 = frame.mKeyFrameEasing;
                        start = frame.time;
                        easing = easing2;
                    } else if (Float.isNaN(end)) {
                        end = frame.time;
                    }
                }
            }
            if (easing == null) {
                mils = mils2;
            } else {
                if (Float.isNaN(end)) {
                    end = 1.0f;
                }
                float offset = (position - start) / (end - start);
                mils = mils2;
                p = ((end - start) * ((float) easing.get(offset))) + start;
            }
            motionController.mSpline[0].getPos(p, motionController.mInterpolateData);
            CurveFit curveFit = motionController.mArcSpline;
            if (curveFit != null) {
                double[] dArr = motionController.mInterpolateData;
                if (dArr.length > 0) {
                    curveFit.getPos(p, dArr);
                }
            }
            motionController.mStartMotionPath.getBounds(motionController.mInterpolateVariables, motionController.mInterpolateData, bounds, i2 * 2);
            i2++;
            motionController = this;
            i = pointCount;
            mils2 = mils;
            trans_x = trans_x;
            f = 1.0f;
        }
    }

    private float getPreCycleDistance() {
        float offset;
        double p;
        int pointCount = 100;
        float[] points = new float[2];
        float mils = 1.0f / (100 - 1);
        float sum = 0.0f;
        double x = 0.0d;
        double y = 0.0d;
        int i = 0;
        while (i < pointCount) {
            float position = i * mils;
            double p2 = position;
            Easing easing = this.mStartMotionPath.mKeyFrameEasing;
            int pointCount2 = pointCount;
            Iterator<MotionPaths> it = this.mMotionPaths.iterator();
            float start = 0.0f;
            Easing easing2 = easing;
            float end = Float.NaN;
            while (it.hasNext()) {
                MotionPaths frame = it.next();
                Iterator<MotionPaths> it2 = it;
                if (frame.mKeyFrameEasing != null) {
                    if (frame.time < position) {
                        Easing easing3 = frame.mKeyFrameEasing;
                        start = frame.time;
                        easing2 = easing3;
                    } else if (Float.isNaN(end)) {
                        end = frame.time;
                    }
                }
                it = it2;
            }
            if (easing2 == null) {
                offset = end;
                p = p2;
            } else {
                if (Float.isNaN(end)) {
                    end = 1.0f;
                }
                float offset2 = (position - start) / (end - start);
                double p3 = offset2;
                float offset3 = (float) easing2.get(p3);
                offset = end;
                p = ((end - start) * offset3) + start;
            }
            this.mSpline[0].getPos(p, this.mInterpolateData);
            int i2 = i;
            this.mStartMotionPath.getCenter(p, this.mInterpolateVariables, this.mInterpolateData, points, 0);
            if (i2 > 0) {
                sum = (float) (sum + Math.hypot(y - points[1], x - points[0]));
            }
            x = points[0];
            y = points[1];
            i = i2 + 1;
            pointCount = pointCount2;
        }
        return sum;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public KeyPositionBase getPositionKeyframe(int layoutWidth, int layoutHeight, float x, float y) {
        RectF start = new RectF();
        start.left = this.mStartMotionPath.x;
        start.top = this.mStartMotionPath.y;
        start.right = start.left + this.mStartMotionPath.width;
        start.bottom = start.top + this.mStartMotionPath.height;
        RectF end = new RectF();
        end.left = this.mEndMotionPath.x;
        end.top = this.mEndMotionPath.y;
        end.right = end.left + this.mEndMotionPath.width;
        end.bottom = end.top + this.mEndMotionPath.height;
        Iterator<Key> it = this.mKeyList.iterator();
        while (it.hasNext()) {
            Key key = it.next();
            if ((key instanceof KeyPositionBase) && ((KeyPositionBase) key).intersects(layoutWidth, layoutHeight, start, end, x, y)) {
                return (KeyPositionBase) key;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int buildKeyFrames(float[] keyFrames, int[] mode) {
        if (keyFrames == null) {
            return 0;
        }
        int count = 0;
        double[] time = this.mSpline[0].getTimePoints();
        if (mode != null) {
            Iterator<MotionPaths> it = this.mMotionPaths.iterator();
            while (it.hasNext()) {
                MotionPaths keyFrame = it.next();
                mode[count] = keyFrame.mMode;
                count++;
            }
            count = 0;
        }
        for (int i = 0; i < time.length; i++) {
            this.mSpline[0].getPos(time[i], this.mInterpolateData);
            this.mStartMotionPath.getCenter(time[i], this.mInterpolateVariables, this.mInterpolateData, keyFrames, count);
            count += 2;
        }
        return count / 2;
    }

    int buildKeyBounds(float[] keyBounds, int[] mode) {
        if (keyBounds == null) {
            return 0;
        }
        int count = 0;
        double[] time = this.mSpline[0].getTimePoints();
        if (mode != null) {
            Iterator<MotionPaths> it = this.mMotionPaths.iterator();
            while (it.hasNext()) {
                MotionPaths keyFrame = it.next();
                mode[count] = keyFrame.mMode;
                count++;
            }
            count = 0;
        }
        for (double d : time) {
            this.mSpline[0].getPos(d, this.mInterpolateData);
            this.mStartMotionPath.getBounds(this.mInterpolateVariables, this.mInterpolateData, keyBounds, count);
            count += 2;
        }
        return count / 2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getAttributeValues(String attributeType, float[] points, int pointCount) {
        float f = 1.0f / (pointCount - 1);
        SplineSet spline = this.mAttributesMap.get(attributeType);
        if (spline == null) {
            return -1;
        }
        for (int j = 0; j < points.length; j++) {
            points[j] = spline.get(j / (points.length - 1));
        }
        int j2 = points.length;
        return j2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void buildRect(float p, float[] path, int offset) {
        this.mSpline[0].getPos(getAdjustedPosition(p, null), this.mInterpolateData);
        this.mStartMotionPath.getRect(this.mInterpolateVariables, this.mInterpolateData, path, offset);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void buildRectangles(float[] path, int pointCount) {
        float mils = 1.0f / (pointCount - 1);
        for (int i = 0; i < pointCount; i++) {
            float position = i * mils;
            this.mSpline[0].getPos(getAdjustedPosition(position, null), this.mInterpolateData);
            this.mStartMotionPath.getRect(this.mInterpolateVariables, this.mInterpolateData, path, i * 8);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public float getKeyFrameParameter(int type, float x, float y) {
        float dx = this.mEndMotionPath.x - this.mStartMotionPath.x;
        float dy = this.mEndMotionPath.y - this.mStartMotionPath.y;
        float startCenterX = this.mStartMotionPath.x + (this.mStartMotionPath.width / 2.0f);
        float startCenterY = this.mStartMotionPath.y + (this.mStartMotionPath.height / 2.0f);
        float hypotenuse = (float) Math.hypot(dx, dy);
        if (hypotenuse < 1.0E-7d) {
            return Float.NaN;
        }
        float vx = x - startCenterX;
        float vy = y - startCenterY;
        float distFromStart = (float) Math.hypot(vx, vy);
        if (distFromStart == 0.0f) {
            return 0.0f;
        }
        float pathDistance = (vx * dx) + (vy * dy);
        switch (type) {
            case 0:
                return pathDistance / hypotenuse;
            case 1:
                return (float) Math.sqrt((hypotenuse * hypotenuse) - (pathDistance * pathDistance));
            case 2:
                return vx / dx;
            case 3:
                return vy / dx;
            case 4:
                return vx / dy;
            case 5:
                return vy / dy;
            default:
                return 0.0f;
        }
    }

    private void insertKey(MotionPaths point) {
        int pos = Collections.binarySearch(this.mMotionPaths, point);
        if (pos == 0) {
            Log.e(TAG, " KeyPath position \"" + point.position + "\" outside of range");
        }
        this.mMotionPaths.add((-pos) - 1, point);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void addKeys(ArrayList<Key> list) {
        this.mKeyList.addAll(list);
    }

    public void addKey(Key key) {
        this.mKeyList.add(key);
    }

    public void setPathMotionArc(int arc) {
        this.mPathMotionArc = arc;
    }

    public void setup(int parentWidth, int parentHeight, float transitionDuration, long currentTime) {
        HashSet<String> attributeNameSet;
        HashSet<String> timeCycleAttributes;
        ConstraintAttribute attribute;
        Iterator<String> it;
        ViewTimeCycle splineSets;
        Iterator<String> it2;
        Integer boxedCurve;
        ArrayList<KeyTrigger> triggerList;
        ViewSpline splineSets2;
        ArrayList<KeyTrigger> triggerList2;
        HashSet<String> springAttributes;
        HashSet<String> springAttributes2 = new HashSet<>();
        HashSet<String> timeCycleAttributes2 = new HashSet<>();
        HashSet<String> splineAttributes = new HashSet<>();
        HashSet<String> cycleAttributes = new HashSet<>();
        HashMap<String, Integer> interpolation = new HashMap<>();
        ArrayList<KeyTrigger> triggerList3 = null;
        if (this.mPathMotionArc != Key.UNSET) {
            this.mStartMotionPath.mPathMotionArc = this.mPathMotionArc;
        }
        this.mStartPoint.different(this.mEndPoint, splineAttributes);
        ArrayList<Key> arrayList = this.mKeyList;
        if (arrayList != null) {
            Iterator<Key> it3 = arrayList.iterator();
            while (it3.hasNext()) {
                Key key = it3.next();
                if (key instanceof KeyPosition) {
                    KeyPosition keyPath = (KeyPosition) key;
                    springAttributes = springAttributes2;
                    insertKey(new MotionPaths(parentWidth, parentHeight, keyPath, this.mStartMotionPath, this.mEndMotionPath));
                    if (keyPath.mCurveFit != Key.UNSET) {
                        this.mCurveFitType = keyPath.mCurveFit;
                    }
                } else {
                    springAttributes = springAttributes2;
                    if (key instanceof KeyCycle) {
                        key.getAttributeNames(cycleAttributes);
                    } else if (key instanceof KeyTimeCycle) {
                        key.getAttributeNames(timeCycleAttributes2);
                    } else if (key instanceof KeyTrigger) {
                        if (triggerList3 == null) {
                            triggerList3 = new ArrayList<>();
                        }
                        triggerList3.add((KeyTrigger) key);
                    } else {
                        key.setInterpolation(interpolation);
                        key.getAttributeNames(splineAttributes);
                    }
                }
                springAttributes2 = springAttributes;
            }
        }
        if (triggerList3 != null) {
            this.mKeyTriggers = (KeyTrigger[]) triggerList3.toArray(new KeyTrigger[0]);
        }
        char c = 1;
        if (!splineAttributes.isEmpty()) {
            this.mAttributesMap = new HashMap<>();
            Iterator<String> it4 = splineAttributes.iterator();
            while (it4.hasNext()) {
                String attribute2 = it4.next();
                if (attribute2.startsWith("CUSTOM,")) {
                    SparseArray<ConstraintAttribute> attrList = new SparseArray<>();
                    String customAttributeName = attribute2.split(",")[c];
                    Iterator<Key> it5 = this.mKeyList.iterator();
                    while (it5.hasNext()) {
                        Key key2 = it5.next();
                        if (key2.mCustomConstraints != null) {
                            ConstraintAttribute customAttribute = key2.mCustomConstraints.get(customAttributeName);
                            if (customAttribute == null) {
                                triggerList2 = triggerList3;
                            } else {
                                triggerList2 = triggerList3;
                                attrList.append(key2.mFramePosition, customAttribute);
                            }
                            triggerList3 = triggerList2;
                        }
                    }
                    triggerList = triggerList3;
                    splineSets2 = ViewSpline.makeCustomSpline(attribute2, attrList);
                } else {
                    triggerList = triggerList3;
                    splineSets2 = ViewSpline.makeSpline(attribute2);
                }
                if (splineSets2 == null) {
                    triggerList3 = triggerList;
                    c = 1;
                } else {
                    splineSets2.setType(attribute2);
                    this.mAttributesMap.put(attribute2, splineSets2);
                    triggerList3 = triggerList;
                    c = 1;
                }
            }
            ArrayList<Key> arrayList2 = this.mKeyList;
            if (arrayList2 != null) {
                Iterator<Key> it6 = arrayList2.iterator();
                while (it6.hasNext()) {
                    Key key3 = it6.next();
                    if (key3 instanceof KeyAttributes) {
                        key3.addValues(this.mAttributesMap);
                    }
                }
            }
            this.mStartPoint.addValues(this.mAttributesMap, 0);
            this.mEndPoint.addValues(this.mAttributesMap, 100);
            for (String spline : this.mAttributesMap.keySet()) {
                int curve = 0;
                if (interpolation.containsKey(spline) && (boxedCurve = interpolation.get(spline)) != null) {
                    curve = boxedCurve.intValue();
                }
                SplineSet splineSet = this.mAttributesMap.get(spline);
                if (splineSet != null) {
                    splineSet.setup(curve);
                }
            }
        }
        if (!timeCycleAttributes2.isEmpty()) {
            if (this.mTimeCycleAttributesMap == null) {
                this.mTimeCycleAttributesMap = new HashMap<>();
            }
            Iterator<String> it7 = timeCycleAttributes2.iterator();
            while (it7.hasNext()) {
                String attribute3 = it7.next();
                if (!this.mTimeCycleAttributesMap.containsKey(attribute3)) {
                    if (attribute3.startsWith("CUSTOM,")) {
                        SparseArray<ConstraintAttribute> attrList2 = new SparseArray<>();
                        String customAttributeName2 = attribute3.split(",")[1];
                        Iterator<Key> it8 = this.mKeyList.iterator();
                        while (it8.hasNext()) {
                            Key key4 = it8.next();
                            if (key4.mCustomConstraints != null) {
                                ConstraintAttribute customAttribute2 = key4.mCustomConstraints.get(customAttributeName2);
                                if (customAttribute2 == null) {
                                    it2 = it7;
                                } else {
                                    it2 = it7;
                                    attrList2.append(key4.mFramePosition, customAttribute2);
                                }
                                it7 = it2;
                            }
                        }
                        it = it7;
                        splineSets = ViewTimeCycle.makeCustomSpline(attribute3, attrList2);
                    } else {
                        it = it7;
                        splineSets = ViewTimeCycle.makeSpline(attribute3, currentTime);
                    }
                    if (splineSets == null) {
                        it7 = it;
                    } else {
                        splineSets.setType(attribute3);
                        this.mTimeCycleAttributesMap.put(attribute3, splineSets);
                        it7 = it;
                    }
                }
            }
            ArrayList<Key> arrayList3 = this.mKeyList;
            if (arrayList3 != null) {
                Iterator<Key> it9 = arrayList3.iterator();
                while (it9.hasNext()) {
                    Key key5 = it9.next();
                    if (key5 instanceof KeyTimeCycle) {
                        ((KeyTimeCycle) key5).addTimeValues(this.mTimeCycleAttributesMap);
                    }
                }
            }
            for (String spline2 : this.mTimeCycleAttributesMap.keySet()) {
                int curve2 = 0;
                if (interpolation.containsKey(spline2)) {
                    curve2 = interpolation.get(spline2).intValue();
                }
                this.mTimeCycleAttributesMap.get(spline2).setup(curve2);
            }
        }
        MotionPaths[] points = new MotionPaths[this.mMotionPaths.size() + 2];
        int count = 1;
        points[0] = this.mStartMotionPath;
        points[points.length - 1] = this.mEndMotionPath;
        if (this.mMotionPaths.size() > 0 && this.mCurveFitType == -1) {
            this.mCurveFitType = 0;
        }
        Iterator<MotionPaths> it10 = this.mMotionPaths.iterator();
        while (it10.hasNext()) {
            MotionPaths point = it10.next();
            points[count] = point;
            count++;
        }
        int variables = 18;
        HashSet<String> attributeNameSet2 = new HashSet<>();
        for (String s : this.mEndMotionPath.attributes.keySet()) {
            if (this.mStartMotionPath.attributes.containsKey(s)) {
                if (!splineAttributes.contains("CUSTOM," + s)) {
                    attributeNameSet2.add(s);
                }
            }
        }
        String[] strArr = (String[]) attributeNameSet2.toArray(new String[0]);
        this.mAttributeNames = strArr;
        this.mAttributeInterpolatorCount = new int[strArr.length];
        int i = 0;
        while (true) {
            String[] strArr2 = this.mAttributeNames;
            if (i >= strArr2.length) {
                break;
            }
            String attributeName = strArr2[i];
            this.mAttributeInterpolatorCount[i] = 0;
            int j = 0;
            while (true) {
                if (j < points.length) {
                    if (!points[j].attributes.containsKey(attributeName) || (attribute = points[j].attributes.get(attributeName)) == null) {
                        j++;
                        timeCycleAttributes2 = timeCycleAttributes2;
                    } else {
                        timeCycleAttributes = timeCycleAttributes2;
                        int[] iArr = this.mAttributeInterpolatorCount;
                        iArr[i] = iArr[i] + attribute.numberOfInterpolatedValues();
                        break;
                    }
                } else {
                    timeCycleAttributes = timeCycleAttributes2;
                    break;
                }
            }
            i++;
            timeCycleAttributes2 = timeCycleAttributes;
        }
        boolean arcMode = points[0].mPathMotionArc != Key.UNSET;
        boolean[] mask = new boolean[this.mAttributeNames.length + 18];
        int i2 = 1;
        while (i2 < points.length) {
            points[i2].different(points[i2 - 1], mask, this.mAttributeNames, arcMode);
            i2++;
            splineAttributes = splineAttributes;
        }
        int count2 = 0;
        for (int i3 = 1; i3 < mask.length; i3++) {
            if (mask[i3]) {
                count2++;
            }
        }
        this.mInterpolateVariables = new int[count2];
        int varLen = Math.max(2, count2);
        this.mInterpolateData = new double[varLen];
        this.mInterpolateVelocity = new double[varLen];
        int count3 = 0;
        for (int i4 = 1; i4 < mask.length; i4++) {
            if (mask[i4]) {
                this.mInterpolateVariables[count3] = i4;
                count3++;
            }
        }
        int i5 = points.length;
        double[][] splineData = (double[][]) Array.newInstance(double.class, i5, this.mInterpolateVariables.length);
        double[] timePoint = new double[points.length];
        int i6 = 0;
        while (i6 < points.length) {
            points[i6].fillStandard(splineData[i6], this.mInterpolateVariables);
            timePoint[i6] = points[i6].time;
            i6++;
            mask = mask;
            count3 = count3;
            interpolation = interpolation;
        }
        int j2 = 0;
        while (true) {
            int[] iArr2 = this.mInterpolateVariables;
            if (j2 >= iArr2.length) {
                break;
            }
            int interpolateVariable = iArr2[j2];
            if (interpolateVariable < MotionPaths.names.length) {
                String s2 = MotionPaths.names[this.mInterpolateVariables[j2]] + " [";
                int i7 = 0;
                while (i7 < points.length) {
                    s2 = s2 + splineData[i7][j2];
                    i7++;
                    variables = variables;
                    varLen = varLen;
                }
            }
            j2++;
            variables = variables;
            varLen = varLen;
        }
        this.mSpline = new CurveFit[this.mAttributeNames.length + 1];
        int i8 = 0;
        while (true) {
            String[] strArr3 = this.mAttributeNames;
            if (i8 >= strArr3.length) {
                break;
            }
            int pointCount = 0;
            double[][] splinePoints = null;
            double[] timePoints = null;
            String name = strArr3[i8];
            int j3 = 0;
            while (j3 < points.length) {
                if (!points[j3].hasCustomData(name)) {
                    attributeNameSet = attributeNameSet2;
                } else {
                    if (splinePoints != null) {
                        attributeNameSet = attributeNameSet2;
                    } else {
                        double[] timePoints2 = new double[points.length];
                        attributeNameSet = attributeNameSet2;
                        splinePoints = (double[][]) Array.newInstance(double.class, points.length, points[j3].getCustomDataCount(name));
                        timePoints = timePoints2;
                    }
                    timePoints[pointCount] = points[j3].time;
                    points[j3].getCustomData(name, splinePoints[pointCount], 0);
                    pointCount++;
                }
                j3++;
                attributeNameSet2 = attributeNameSet;
            }
            this.mSpline[i8 + 1] = CurveFit.get(this.mCurveFitType, Arrays.copyOf(timePoints, pointCount), (double[][]) Arrays.copyOf(splinePoints, pointCount));
            i8++;
            attributeNameSet2 = attributeNameSet2;
        }
        this.mSpline[0] = CurveFit.get(this.mCurveFitType, timePoint, splineData);
        if (points[0].mPathMotionArc != Key.UNSET) {
            int size = points.length;
            int[] mode = new int[size];
            double[] time = new double[size];
            double[][] values = (double[][]) Array.newInstance(double.class, size, 2);
            for (int i9 = 0; i9 < size; i9++) {
                mode[i9] = points[i9].mPathMotionArc;
                time[i9] = points[i9].time;
                values[i9][0] = points[i9].x;
                values[i9][1] = points[i9].y;
            }
            this.mArcSpline = CurveFit.getArc(mode, time, values);
        }
        float distance = Float.NaN;
        this.mCycleMap = new HashMap<>();
        if (this.mKeyList != null) {
            Iterator<String> it11 = cycleAttributes.iterator();
            while (it11.hasNext()) {
                String attribute4 = it11.next();
                ViewOscillator cycle = ViewOscillator.makeSpline(attribute4);
                if (cycle != null) {
                    if (cycle.variesByPath() && Float.isNaN(distance)) {
                        distance = getPreCycleDistance();
                    }
                    cycle.setType(attribute4);
                    this.mCycleMap.put(attribute4, cycle);
                }
            }
            Iterator<Key> it12 = this.mKeyList.iterator();
            while (it12.hasNext()) {
                Key key6 = it12.next();
                if (key6 instanceof KeyCycle) {
                    ((KeyCycle) key6).addCycleValues(this.mCycleMap);
                }
            }
            for (ViewOscillator cycle2 : this.mCycleMap.values()) {
                cycle2.setup(distance);
            }
        }
    }

    public String toString() {
        return " start: x: " + this.mStartMotionPath.x + " y: " + this.mStartMotionPath.y + " end: x: " + this.mEndMotionPath.x + " y: " + this.mEndMotionPath.y;
    }

    private void readView(MotionPaths motionPaths) {
        motionPaths.setBounds((int) this.mView.getX(), (int) this.mView.getY(), this.mView.getWidth(), this.mView.getHeight());
    }

    public void setView(View view) {
        this.mView = view;
        this.mId = view.getId();
        ViewGroup.LayoutParams lp = view.getLayoutParams();
        if (lp instanceof ConstraintLayout.LayoutParams) {
            this.mConstraintTag = ((ConstraintLayout.LayoutParams) lp).getConstraintTag();
        }
    }

    public View getView() {
        return this.mView;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setStartCurrentState(View v) {
        this.mStartMotionPath.time = 0.0f;
        this.mStartMotionPath.position = 0.0f;
        this.mStartMotionPath.setBounds(v.getX(), v.getY(), v.getWidth(), v.getHeight());
        this.mStartPoint.setState(v);
    }

    public void setStartState(ViewState rect, View v, int rotation, int preWidth, int preHeight) {
        this.mStartMotionPath.time = 0.0f;
        this.mStartMotionPath.position = 0.0f;
        Rect r = new Rect();
        switch (rotation) {
            case 1:
                int cx = rect.left;
                int cx2 = cx + rect.right;
                int cy = rect.top + rect.bottom;
                r.left = (cy - rect.width()) / 2;
                r.top = preWidth - ((rect.height() + cx2) / 2);
                r.right = r.left + rect.width();
                r.bottom = r.top + rect.height();
                break;
            case 2:
                int cx3 = rect.left + rect.right;
                int cy2 = rect.top + rect.bottom;
                r.left = preHeight - ((rect.width() + cy2) / 2);
                r.top = (cx3 - rect.height()) / 2;
                r.right = r.left + rect.width();
                r.bottom = r.top + rect.height();
                break;
        }
        this.mStartMotionPath.setBounds(r.left, r.top, r.width(), r.height());
        this.mStartPoint.setState(r, v, rotation, rect.rotation);
    }

    void rotate(Rect rect, Rect out, int rotation, int preHeight, int preWidth) {
        switch (rotation) {
            case 1:
                int cx = rect.left;
                int cx2 = cx + rect.right;
                int cy = rect.top + rect.bottom;
                out.left = (cy - rect.width()) / 2;
                out.top = preWidth - ((rect.height() + cx2) / 2);
                out.right = out.left + rect.width();
                out.bottom = out.top + rect.height();
                return;
            case 2:
                int cx3 = rect.left;
                int cx4 = cx3 + rect.right;
                int cy2 = rect.top + rect.bottom;
                out.left = preHeight - ((rect.width() + cy2) / 2);
                out.top = (cx4 - rect.height()) / 2;
                out.right = out.left + rect.width();
                out.bottom = out.top + rect.height();
                return;
            case 3:
                int cx5 = rect.left;
                int cx6 = cx5 + rect.right;
                int i = rect.top + rect.bottom;
                out.left = ((rect.height() / 2) + rect.top) - (cx6 / 2);
                out.top = preWidth - ((rect.height() + cx6) / 2);
                out.right = out.left + rect.width();
                out.bottom = out.top + rect.height();
                return;
            case 4:
                int cx7 = rect.left + rect.right;
                int cy3 = rect.bottom + rect.top;
                out.left = preHeight - ((rect.width() + cy3) / 2);
                out.top = (cx7 - rect.height()) / 2;
                out.right = out.left + rect.width();
                out.bottom = out.top + rect.height();
                return;
            default:
                return;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setStartState(Rect cw, ConstraintSet constraintSet, int parentWidth, int parentHeight) {
        int rotate = constraintSet.mRotate;
        if (rotate != 0) {
            rotate(cw, this.mTempRect, rotate, parentWidth, parentHeight);
        }
        this.mStartMotionPath.time = 0.0f;
        this.mStartMotionPath.position = 0.0f;
        readView(this.mStartMotionPath);
        this.mStartMotionPath.setBounds(cw.left, cw.top, cw.width(), cw.height());
        ConstraintSet.Constraint constraint = constraintSet.getParameters(this.mId);
        this.mStartMotionPath.applyParameters(constraint);
        this.mMotionStagger = constraint.motion.mMotionStagger;
        this.mStartPoint.setState(cw, constraintSet, rotate, this.mId);
        this.mTransformPivotTarget = constraint.transform.transformPivotTarget;
        this.mQuantizeMotionSteps = constraint.motion.mQuantizeMotionSteps;
        this.mQuantizeMotionPhase = constraint.motion.mQuantizeMotionPhase;
        this.mQuantizeMotionInterpolator = getInterpolator(this.mView.getContext(), constraint.motion.mQuantizeInterpolatorType, constraint.motion.mQuantizeInterpolatorString, constraint.motion.mQuantizeInterpolatorID);
    }

    private static Interpolator getInterpolator(Context context, int type, String interpolatorString, int id) {
        switch (type) {
            case -2:
                return AnimationUtils.loadInterpolator(context, id);
            case -1:
                final Easing easing = Easing.getInterpolator(interpolatorString);
                return new Interpolator() { // from class: androidx.constraintlayout.motion.widget.MotionController.1
                    @Override // android.animation.TimeInterpolator
                    public float getInterpolation(float v) {
                        return (float) Easing.this.get(v);
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
            default:
                return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setEndState(Rect cw, ConstraintSet constraintSet, int parentWidth, int parentHeight) {
        int rotate = constraintSet.mRotate;
        if (rotate != 0) {
            rotate(cw, this.mTempRect, rotate, parentWidth, parentHeight);
            cw = this.mTempRect;
        }
        this.mEndMotionPath.time = 1.0f;
        this.mEndMotionPath.position = 1.0f;
        readView(this.mEndMotionPath);
        this.mEndMotionPath.setBounds(cw.left, cw.top, cw.width(), cw.height());
        this.mEndMotionPath.applyParameters(constraintSet.getParameters(this.mId));
        this.mEndPoint.setState(cw, constraintSet, rotate, this.mId);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setBothStates(View v) {
        this.mStartMotionPath.time = 0.0f;
        this.mStartMotionPath.position = 0.0f;
        this.mNoMovement = true;
        this.mStartMotionPath.setBounds(v.getX(), v.getY(), v.getWidth(), v.getHeight());
        this.mEndMotionPath.setBounds(v.getX(), v.getY(), v.getWidth(), v.getHeight());
        this.mStartPoint.setState(v);
        this.mEndPoint.setState(v);
    }

    private float getAdjustedPosition(float position, float[] velocity) {
        if (velocity != null) {
            velocity[0] = 1.0f;
        } else {
            float f = this.mStaggerScale;
            if (f != 1.0d) {
                float f2 = this.mStaggerOffset;
                if (position < f2) {
                    position = 0.0f;
                }
                if (position > f2 && position < 1.0d) {
                    position = Math.min((position - f2) * f, 1.0f);
                }
            }
        }
        float adjusted = position;
        Easing easing = this.mStartMotionPath.mKeyFrameEasing;
        float start = 0.0f;
        float end = Float.NaN;
        Iterator<MotionPaths> it = this.mMotionPaths.iterator();
        while (it.hasNext()) {
            MotionPaths frame = it.next();
            if (frame.mKeyFrameEasing != null) {
                if (frame.time < position) {
                    easing = frame.mKeyFrameEasing;
                    start = frame.time;
                } else if (Float.isNaN(end)) {
                    end = frame.time;
                }
            }
        }
        if (easing != null) {
            if (Float.isNaN(end)) {
                end = 1.0f;
            }
            float offset = (position - start) / (end - start);
            float new_offset = (float) easing.get(offset);
            adjusted = ((end - start) * new_offset) + start;
            if (velocity != null) {
                velocity[0] = (float) easing.getDiff(offset);
            }
        }
        return adjusted;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void endTrigger(boolean start) {
        if ("button".equals(Debug.getName(this.mView)) && this.mKeyTriggers != null) {
            int i = 0;
            while (true) {
                KeyTrigger[] keyTriggerArr = this.mKeyTriggers;
                if (i < keyTriggerArr.length) {
                    keyTriggerArr[i].conditionallyFire(start ? -100.0f : 100.0f, this.mView);
                    i++;
                } else {
                    return;
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: Incorrect condition in loop: B:27:0x0080 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean interpolate(android.view.View r22, float r23, long r24, androidx.constraintlayout.core.motion.utils.KeyCache r26) {
        /*
            Method dump skipped, instructions count: 723
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.motion.widget.MotionController.interpolate(android.view.View, float, long, androidx.constraintlayout.core.motion.utils.KeyCache):boolean");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void getDpDt(float position, float locationX, float locationY, float[] mAnchorDpDt) {
        double[] dArr;
        float position2 = getAdjustedPosition(position, this.mVelocity);
        CurveFit[] curveFitArr = this.mSpline;
        if (curveFitArr != null) {
            curveFitArr[0].getSlope(position2, this.mInterpolateVelocity);
            this.mSpline[0].getPos(position2, this.mInterpolateData);
            float v = this.mVelocity[0];
            int i = 0;
            while (true) {
                dArr = this.mInterpolateVelocity;
                if (i >= dArr.length) {
                    break;
                }
                dArr[i] = dArr[i] * v;
                i++;
            }
            CurveFit curveFit = this.mArcSpline;
            if (curveFit == null) {
                this.mStartMotionPath.setDpDt(locationX, locationY, mAnchorDpDt, this.mInterpolateVariables, dArr, this.mInterpolateData);
                return;
            }
            double[] dArr2 = this.mInterpolateData;
            if (dArr2.length > 0) {
                curveFit.getPos(position2, dArr2);
                this.mArcSpline.getSlope(position2, this.mInterpolateVelocity);
                this.mStartMotionPath.setDpDt(locationX, locationY, mAnchorDpDt, this.mInterpolateVariables, this.mInterpolateVelocity, this.mInterpolateData);
                return;
            }
            return;
        }
        float dleft = this.mEndMotionPath.x - this.mStartMotionPath.x;
        float dTop = this.mEndMotionPath.y - this.mStartMotionPath.y;
        float dWidth = this.mEndMotionPath.width - this.mStartMotionPath.width;
        float dHeight = this.mEndMotionPath.height - this.mStartMotionPath.height;
        float dRight = dleft + dWidth;
        float dBottom = dTop + dHeight;
        mAnchorDpDt[0] = ((1.0f - locationX) * dleft) + (dRight * locationX);
        mAnchorDpDt[1] = ((1.0f - locationY) * dTop) + (dBottom * locationY);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void getPostLayoutDvDp(float position, int width, int height, float locationX, float locationY, float[] mAnchorDpDt) {
        VelocityMatrix vmat;
        float position2 = getAdjustedPosition(position, this.mVelocity);
        HashMap<String, ViewSpline> hashMap = this.mAttributesMap;
        SplineSet trans_x = hashMap == null ? null : hashMap.get("translationX");
        HashMap<String, ViewSpline> hashMap2 = this.mAttributesMap;
        SplineSet trans_y = hashMap2 == null ? null : hashMap2.get("translationY");
        HashMap<String, ViewSpline> hashMap3 = this.mAttributesMap;
        SplineSet rotation = hashMap3 == null ? null : hashMap3.get(Key.ROTATION);
        HashMap<String, ViewSpline> hashMap4 = this.mAttributesMap;
        SplineSet scale_x = hashMap4 == null ? null : hashMap4.get("scaleX");
        HashMap<String, ViewSpline> hashMap5 = this.mAttributesMap;
        SplineSet scale_y = hashMap5 == null ? null : hashMap5.get("scaleY");
        HashMap<String, ViewOscillator> hashMap6 = this.mCycleMap;
        ViewOscillator osc_x = hashMap6 == null ? null : hashMap6.get("translationX");
        HashMap<String, ViewOscillator> hashMap7 = this.mCycleMap;
        ViewOscillator osc_y = hashMap7 == null ? null : hashMap7.get("translationY");
        HashMap<String, ViewOscillator> hashMap8 = this.mCycleMap;
        ViewOscillator osc_r = hashMap8 == null ? null : hashMap8.get(Key.ROTATION);
        HashMap<String, ViewOscillator> hashMap9 = this.mCycleMap;
        ViewOscillator osc_sx = hashMap9 == null ? null : hashMap9.get("scaleX");
        HashMap<String, ViewOscillator> hashMap10 = this.mCycleMap;
        ViewOscillator osc_sy = hashMap10 != null ? hashMap10.get("scaleY") : null;
        VelocityMatrix vmat2 = new VelocityMatrix();
        vmat2.clear();
        vmat2.setRotationVelocity(rotation, position2);
        vmat2.setTranslationVelocity(trans_x, trans_y, position2);
        vmat2.setScaleVelocity(scale_x, scale_y, position2);
        vmat2.setRotationVelocity(osc_r, position2);
        vmat2.setTranslationVelocity(osc_x, osc_y, position2);
        vmat2.setScaleVelocity(osc_sx, osc_sy, position2);
        CurveFit curveFit = this.mArcSpline;
        if (curveFit == null) {
            if (this.mSpline != null) {
                float position3 = getAdjustedPosition(position2, this.mVelocity);
                this.mSpline[0].getSlope(position3, this.mInterpolateVelocity);
                this.mSpline[0].getPos(position3, this.mInterpolateData);
                float v = this.mVelocity[0];
                int i = 0;
                while (true) {
                    double[] dArr = this.mInterpolateVelocity;
                    if (i >= dArr.length) {
                        this.mStartMotionPath.setDpDt(locationX, locationY, mAnchorDpDt, this.mInterpolateVariables, dArr, this.mInterpolateData);
                        vmat2.applyTransform(locationX, locationY, width, height, mAnchorDpDt);
                        return;
                    }
                    dArr[i] = dArr[i] * v;
                    i++;
                }
            } else {
                float dleft = this.mEndMotionPath.x - this.mStartMotionPath.x;
                float dTop = this.mEndMotionPath.y - this.mStartMotionPath.y;
                float dWidth = this.mEndMotionPath.width - this.mStartMotionPath.width;
                float dHeight = this.mEndMotionPath.height - this.mStartMotionPath.height;
                float dRight = dleft + dWidth;
                float dBottom = dTop + dHeight;
                mAnchorDpDt[0] = ((1.0f - locationX) * dleft) + (dRight * locationX);
                mAnchorDpDt[1] = ((1.0f - locationY) * dTop) + (dBottom * locationY);
                vmat2.clear();
                vmat2.setRotationVelocity(rotation, position2);
                vmat2.setTranslationVelocity(trans_x, trans_y, position2);
                vmat2.setScaleVelocity(scale_x, scale_y, position2);
                vmat2.setRotationVelocity(osc_r, position2);
                vmat2.setTranslationVelocity(osc_x, osc_y, position2);
                vmat2.setScaleVelocity(osc_sx, osc_sy, position2);
                vmat2.applyTransform(locationX, locationY, width, height, mAnchorDpDt);
            }
        } else {
            double[] dArr2 = this.mInterpolateData;
            if (dArr2.length > 0) {
                curveFit.getPos(position2, dArr2);
                this.mArcSpline.getSlope(position2, this.mInterpolateVelocity);
                vmat = vmat2;
                this.mStartMotionPath.setDpDt(locationX, locationY, mAnchorDpDt, this.mInterpolateVariables, this.mInterpolateVelocity, this.mInterpolateData);
            } else {
                vmat = vmat2;
            }
            vmat.applyTransform(locationX, locationY, width, height, mAnchorDpDt);
        }
    }

    public int getDrawPath() {
        int mode = this.mStartMotionPath.mDrawPath;
        Iterator<MotionPaths> it = this.mMotionPaths.iterator();
        while (it.hasNext()) {
            MotionPaths keyFrame = it.next();
            mode = Math.max(mode, keyFrame.mDrawPath);
        }
        return Math.max(mode, this.mEndMotionPath.mDrawPath);
    }

    public void setDrawPath(int debugMode) {
        this.mStartMotionPath.mDrawPath = debugMode;
    }

    String name() {
        Context context = this.mView.getContext();
        return context.getResources().getResourceEntryName(this.mView.getId());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void positionKeyframe(View view, KeyPositionBase key, float x, float y, String[] attribute, float[] value) {
        RectF start = new RectF();
        start.left = this.mStartMotionPath.x;
        start.top = this.mStartMotionPath.y;
        start.right = start.left + this.mStartMotionPath.width;
        start.bottom = start.top + this.mStartMotionPath.height;
        RectF end = new RectF();
        end.left = this.mEndMotionPath.x;
        end.top = this.mEndMotionPath.y;
        end.right = end.left + this.mEndMotionPath.width;
        end.bottom = end.top + this.mEndMotionPath.height;
        key.positionAttributes(view, start, end, x, y, attribute, value);
    }

    public int getKeyFramePositions(int[] type, float[] pos) {
        int i = 0;
        int count = 0;
        Iterator<Key> it = this.mKeyList.iterator();
        while (it.hasNext()) {
            Key key = it.next();
            int i2 = i + 1;
            type[i] = key.mFramePosition + (key.mType * 1000);
            float time = key.mFramePosition / 100.0f;
            this.mSpline[0].getPos(time, this.mInterpolateData);
            this.mStartMotionPath.getCenter(time, this.mInterpolateVariables, this.mInterpolateData, pos, count);
            count += 2;
            i = i2;
        }
        return i;
    }

    public int getKeyFrameInfo(int type, int[] info) {
        int count = 0;
        int cursor = 0;
        float[] pos = new float[2];
        Iterator<Key> it = this.mKeyList.iterator();
        while (it.hasNext()) {
            Key key = it.next();
            if (key.mType == type || type != -1) {
                int len = cursor;
                info[cursor] = 0;
                int cursor2 = cursor + 1;
                info[cursor2] = key.mType;
                int cursor3 = cursor2 + 1;
                info[cursor3] = key.mFramePosition;
                float time = key.mFramePosition / 100.0f;
                this.mSpline[0].getPos(time, this.mInterpolateData);
                this.mStartMotionPath.getCenter(time, this.mInterpolateVariables, this.mInterpolateData, pos, 0);
                int cursor4 = cursor3 + 1;
                info[cursor4] = Float.floatToIntBits(pos[0]);
                int cursor5 = cursor4 + 1;
                info[cursor5] = Float.floatToIntBits(pos[1]);
                if (key instanceof KeyPosition) {
                    KeyPosition kp = (KeyPosition) key;
                    int cursor6 = cursor5 + 1;
                    info[cursor6] = kp.mPositionType;
                    int cursor7 = cursor6 + 1;
                    info[cursor7] = Float.floatToIntBits(kp.mPercentX);
                    cursor5 = cursor7 + 1;
                    info[cursor5] = Float.floatToIntBits(kp.mPercentY);
                }
                cursor = cursor5 + 1;
                info[len] = cursor - len;
                count++;
            }
        }
        return count;
    }
}
