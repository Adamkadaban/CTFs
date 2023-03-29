package androidx.constraintlayout.core.motion;

import androidx.constraintlayout.core.motion.utils.Easing;
import androidx.constraintlayout.core.motion.utils.Rect;
import androidx.constraintlayout.core.motion.utils.SplineSet;
import androidx.constraintlayout.core.motion.utils.Utils;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Set;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class MotionConstrainedPoint implements Comparable<MotionConstrainedPoint> {
    static final int CARTESIAN = 2;
    public static final boolean DEBUG = false;
    static final int PERPENDICULAR = 1;
    public static final String TAG = "MotionPaths";
    static String[] names = {"position", "x", "y", "width", "height", "pathRotate"};
    private float height;
    private Easing mKeyFrameEasing;
    private float position;
    int visibility;
    private float width;
    private float x;
    private float y;
    private float alpha = 1.0f;
    int mVisibilityMode = 0;
    private boolean applyElevation = false;
    private float elevation = 0.0f;
    private float rotation = 0.0f;
    private float rotationX = 0.0f;
    public float rotationY = 0.0f;
    private float scaleX = 1.0f;
    private float scaleY = 1.0f;
    private float mPivotX = Float.NaN;
    private float mPivotY = Float.NaN;
    private float translationX = 0.0f;
    private float translationY = 0.0f;
    private float translationZ = 0.0f;
    private int mDrawPath = 0;
    private float mPathRotate = Float.NaN;
    private float mProgress = Float.NaN;
    private int mAnimateRelativeTo = -1;
    LinkedHashMap<String, CustomVariable> mCustomVariable = new LinkedHashMap<>();
    int mMode = 0;
    double[] mTempValue = new double[18];
    double[] mTempDelta = new double[18];

    private boolean diff(float a, float b) {
        return (Float.isNaN(a) || Float.isNaN(b)) ? Float.isNaN(a) != Float.isNaN(b) : Math.abs(a - b) > 1.0E-6f;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void different(MotionConstrainedPoint points, HashSet<String> keySet) {
        if (diff(this.alpha, points.alpha)) {
            keySet.add("alpha");
        }
        if (diff(this.elevation, points.elevation)) {
            keySet.add("translationZ");
        }
        int i = this.visibility;
        int i2 = points.visibility;
        if (i != i2 && this.mVisibilityMode == 0 && (i == 4 || i2 == 4)) {
            keySet.add("alpha");
        }
        if (diff(this.rotation, points.rotation)) {
            keySet.add("rotationZ");
        }
        if (!Float.isNaN(this.mPathRotate) || !Float.isNaN(points.mPathRotate)) {
            keySet.add("pathRotate");
        }
        if (!Float.isNaN(this.mProgress) || !Float.isNaN(points.mProgress)) {
            keySet.add("progress");
        }
        if (diff(this.rotationX, points.rotationX)) {
            keySet.add("rotationX");
        }
        if (diff(this.rotationY, points.rotationY)) {
            keySet.add("rotationY");
        }
        if (diff(this.mPivotX, points.mPivotX)) {
            keySet.add("pivotX");
        }
        if (diff(this.mPivotY, points.mPivotY)) {
            keySet.add("pivotY");
        }
        if (diff(this.scaleX, points.scaleX)) {
            keySet.add("scaleX");
        }
        if (diff(this.scaleY, points.scaleY)) {
            keySet.add("scaleY");
        }
        if (diff(this.translationX, points.translationX)) {
            keySet.add("translationX");
        }
        if (diff(this.translationY, points.translationY)) {
            keySet.add("translationY");
        }
        if (diff(this.translationZ, points.translationZ)) {
            keySet.add("translationZ");
        }
        if (diff(this.elevation, points.elevation)) {
            keySet.add("elevation");
        }
    }

    void different(MotionConstrainedPoint points, boolean[] mask, String[] custom) {
        int c = 0 + 1;
        mask[0] = mask[0] | diff(this.position, points.position);
        int c2 = c + 1;
        mask[c] = mask[c] | diff(this.x, points.x);
        int c3 = c2 + 1;
        mask[c2] = mask[c2] | diff(this.y, points.y);
        int c4 = c3 + 1;
        mask[c3] = mask[c3] | diff(this.width, points.width);
        int i = c4 + 1;
        mask[c4] = mask[c4] | diff(this.height, points.height);
    }

    void fillStandard(double[] data, int[] toUse) {
        float[] set = {this.position, this.x, this.y, this.width, this.height, this.alpha, this.elevation, this.rotation, this.rotationX, this.rotationY, this.scaleX, this.scaleY, this.mPivotX, this.mPivotY, this.translationX, this.translationY, this.translationZ, this.mPathRotate};
        int c = 0;
        for (int i = 0; i < toUse.length; i++) {
            if (toUse[i] < set.length) {
                data[c] = set[toUse[i]];
                c++;
            }
        }
    }

    boolean hasCustomData(String name) {
        return this.mCustomVariable.containsKey(name);
    }

    int getCustomDataCount(String name) {
        return this.mCustomVariable.get(name).numberOfInterpolatedValues();
    }

    int getCustomData(String name, double[] value, int offset) {
        CustomVariable a = this.mCustomVariable.get(name);
        if (a.numberOfInterpolatedValues() == 1) {
            value[offset] = a.getValueToInterpolate();
            return 1;
        }
        int N = a.numberOfInterpolatedValues();
        float[] f = new float[N];
        a.getValuesToInterpolate(f);
        int i = 0;
        while (i < N) {
            value[offset] = f[i];
            i++;
            offset++;
        }
        return N;
    }

    void setBounds(float x, float y, float w, float h) {
        this.x = x;
        this.y = y;
        this.width = w;
        this.height = h;
    }

    @Override // java.lang.Comparable
    public int compareTo(MotionConstrainedPoint o) {
        return Float.compare(this.position, o.position);
    }

    public void applyParameters(MotionWidget view) {
        this.visibility = view.getVisibility();
        this.alpha = view.getVisibility() != 4 ? 0.0f : view.getAlpha();
        this.applyElevation = false;
        this.rotation = view.getRotationZ();
        this.rotationX = view.getRotationX();
        this.rotationY = view.getRotationY();
        this.scaleX = view.getScaleX();
        this.scaleY = view.getScaleY();
        this.mPivotX = view.getPivotX();
        this.mPivotY = view.getPivotY();
        this.translationX = view.getTranslationX();
        this.translationY = view.getTranslationY();
        this.translationZ = view.getTranslationZ();
        Set<String> at = view.getCustomAttributeNames();
        for (String s : at) {
            CustomVariable attr = view.getCustomAttribute(s);
            if (attr != null && attr.isContinuous()) {
                this.mCustomVariable.put(s, attr);
            }
        }
    }

    public void addValues(HashMap<String, SplineSet> splines, int mFramePosition) {
        for (String s : splines.keySet()) {
            SplineSet ViewSpline = splines.get(s);
            char c = 65535;
            switch (s.hashCode()) {
                case -1249320806:
                    if (s.equals("rotationX")) {
                        c = 2;
                        break;
                    }
                    break;
                case -1249320805:
                    if (s.equals("rotationY")) {
                        c = 3;
                        break;
                    }
                    break;
                case -1249320804:
                    if (s.equals("rotationZ")) {
                        c = 1;
                        break;
                    }
                    break;
                case -1225497657:
                    if (s.equals("translationX")) {
                        c = '\n';
                        break;
                    }
                    break;
                case -1225497656:
                    if (s.equals("translationY")) {
                        c = 11;
                        break;
                    }
                    break;
                case -1225497655:
                    if (s.equals("translationZ")) {
                        c = '\f';
                        break;
                    }
                    break;
                case -1001078227:
                    if (s.equals("progress")) {
                        c = 7;
                        break;
                    }
                    break;
                case -987906986:
                    if (s.equals("pivotX")) {
                        c = 4;
                        break;
                    }
                    break;
                case -987906985:
                    if (s.equals("pivotY")) {
                        c = 5;
                        break;
                    }
                    break;
                case -908189618:
                    if (s.equals("scaleX")) {
                        c = '\b';
                        break;
                    }
                    break;
                case -908189617:
                    if (s.equals("scaleY")) {
                        c = '\t';
                        break;
                    }
                    break;
                case 92909918:
                    if (s.equals("alpha")) {
                        c = 0;
                        break;
                    }
                    break;
                case 803192288:
                    if (s.equals("pathRotate")) {
                        c = 6;
                        break;
                    }
                    break;
            }
            switch (c) {
                case 0:
                    ViewSpline.setPoint(mFramePosition, Float.isNaN(this.alpha) ? 1.0f : this.alpha);
                    break;
                case 1:
                    ViewSpline.setPoint(mFramePosition, Float.isNaN(this.rotation) ? 0.0f : this.rotation);
                    break;
                case 2:
                    ViewSpline.setPoint(mFramePosition, Float.isNaN(this.rotationX) ? 0.0f : this.rotationX);
                    break;
                case 3:
                    ViewSpline.setPoint(mFramePosition, Float.isNaN(this.rotationY) ? 0.0f : this.rotationY);
                    break;
                case 4:
                    ViewSpline.setPoint(mFramePosition, Float.isNaN(this.mPivotX) ? 0.0f : this.mPivotX);
                    break;
                case 5:
                    ViewSpline.setPoint(mFramePosition, Float.isNaN(this.mPivotY) ? 0.0f : this.mPivotY);
                    break;
                case 6:
                    ViewSpline.setPoint(mFramePosition, Float.isNaN(this.mPathRotate) ? 0.0f : this.mPathRotate);
                    break;
                case 7:
                    ViewSpline.setPoint(mFramePosition, Float.isNaN(this.mProgress) ? 0.0f : this.mProgress);
                    break;
                case '\b':
                    ViewSpline.setPoint(mFramePosition, Float.isNaN(this.scaleX) ? 1.0f : this.scaleX);
                    break;
                case '\t':
                    ViewSpline.setPoint(mFramePosition, Float.isNaN(this.scaleY) ? 1.0f : this.scaleY);
                    break;
                case '\n':
                    ViewSpline.setPoint(mFramePosition, Float.isNaN(this.translationX) ? 0.0f : this.translationX);
                    break;
                case 11:
                    ViewSpline.setPoint(mFramePosition, Float.isNaN(this.translationY) ? 0.0f : this.translationY);
                    break;
                case '\f':
                    ViewSpline.setPoint(mFramePosition, Float.isNaN(this.translationZ) ? 0.0f : this.translationZ);
                    break;
                default:
                    if (!s.startsWith("CUSTOM")) {
                        Utils.loge("MotionPaths", "UNKNOWN spline " + s);
                        break;
                    } else {
                        String customName = s.split(",")[1];
                        if (this.mCustomVariable.containsKey(customName)) {
                            CustomVariable custom = this.mCustomVariable.get(customName);
                            if (ViewSpline instanceof SplineSet.CustomSpline) {
                                ((SplineSet.CustomSpline) ViewSpline).setPoint(mFramePosition, custom);
                                break;
                            } else {
                                Utils.loge("MotionPaths", s + " ViewSpline not a CustomSet frame = " + mFramePosition + ", value" + custom.getValueToInterpolate() + ViewSpline);
                                break;
                            }
                        } else {
                            break;
                        }
                    }
            }
        }
    }

    public void setState(MotionWidget view) {
        setBounds(view.getX(), view.getY(), view.getWidth(), view.getHeight());
        applyParameters(view);
    }

    public void setState(Rect rect, MotionWidget view, int rotation, float prevous) {
        setBounds(rect.left, rect.top, rect.width(), rect.height());
        applyParameters(view);
        this.mPivotX = Float.NaN;
        this.mPivotY = Float.NaN;
        switch (rotation) {
            case 1:
                this.rotation = prevous - 90.0f;
                return;
            case 2:
                this.rotation = 90.0f + prevous;
                return;
            default:
                return;
        }
    }
}
