package androidx.constraintlayout.core.motion.key;

import androidx.constraintlayout.core.motion.MotionWidget;
import androidx.constraintlayout.core.motion.utils.FloatRect;
import androidx.constraintlayout.core.motion.utils.SplineSet;
import androidx.constraintlayout.core.motion.utils.TypedValues;
import java.util.HashMap;
import java.util.HashSet;
/* loaded from: classes.dex */
public class MotionKeyPosition extends MotionKey {
    static final int KEY_TYPE = 2;
    static final String NAME = "KeyPosition";
    protected static final float SELECTION_SLOPE = 20.0f;
    public static final int TYPE_CARTESIAN = 0;
    public static final int TYPE_PATH = 1;
    public static final int TYPE_SCREEN = 2;
    public int mCurveFit = UNSET;
    public String mTransitionEasing = null;
    public int mPathMotionArc = UNSET;
    public int mDrawPath = 0;
    public float mPercentWidth = Float.NaN;
    public float mPercentHeight = Float.NaN;
    public float mPercentX = Float.NaN;
    public float mPercentY = Float.NaN;
    public float mAltPercentX = Float.NaN;
    public float mAltPercentY = Float.NaN;
    public int mPositionType = 0;
    private float mCalculatedPositionX = Float.NaN;
    private float mCalculatedPositionY = Float.NaN;

    public MotionKeyPosition() {
        this.mType = 2;
    }

    private void calcScreenPosition(int layoutWidth, int layoutHeight) {
        float f = this.mPercentX;
        this.mCalculatedPositionX = ((layoutWidth - 0) * f) + (0 / 2);
        this.mCalculatedPositionY = ((layoutHeight - 0) * f) + (0 / 2);
    }

    private void calcPathPosition(float start_x, float start_y, float end_x, float end_y) {
        float pathVectorX = end_x - start_x;
        float pathVectorY = end_y - start_y;
        float perpendicularX = -pathVectorY;
        float f = this.mPercentX;
        float f2 = this.mPercentY;
        this.mCalculatedPositionX = (pathVectorX * f) + start_x + (perpendicularX * f2);
        this.mCalculatedPositionY = (f * pathVectorY) + start_y + (f2 * pathVectorX);
    }

    private void calcCartesianPosition(float start_x, float start_y, float end_x, float end_y) {
        float pathVectorX = end_x - start_x;
        float pathVectorY = end_y - start_y;
        float dxdx = Float.isNaN(this.mPercentX) ? 0.0f : this.mPercentX;
        float dydx = Float.isNaN(this.mAltPercentY) ? 0.0f : this.mAltPercentY;
        float dydy = Float.isNaN(this.mPercentY) ? 0.0f : this.mPercentY;
        float dxdy = Float.isNaN(this.mAltPercentX) ? 0.0f : this.mAltPercentX;
        this.mCalculatedPositionX = (int) ((pathVectorX * dxdx) + start_x + (pathVectorY * dxdy));
        this.mCalculatedPositionY = (int) ((pathVectorX * dydx) + start_y + (pathVectorY * dydy));
    }

    float getPositionX() {
        return this.mCalculatedPositionX;
    }

    float getPositionY() {
        return this.mCalculatedPositionY;
    }

    public void positionAttributes(MotionWidget view, FloatRect start, FloatRect end, float x, float y, String[] attribute, float[] value) {
        switch (this.mPositionType) {
            case 1:
                positionPathAttributes(start, end, x, y, attribute, value);
                return;
            case 2:
                positionScreenAttributes(view, start, end, x, y, attribute, value);
                return;
            default:
                positionCartAttributes(start, end, x, y, attribute, value);
                return;
        }
    }

    void positionPathAttributes(FloatRect start, FloatRect end, float x, float y, String[] attribute, float[] value) {
        float startCenterX = start.centerX();
        float startCenterY = start.centerY();
        float endCenterX = end.centerX();
        float endCenterY = end.centerY();
        float pathVectorX = endCenterX - startCenterX;
        float pathVectorY = endCenterY - startCenterY;
        float distance = (float) Math.hypot(pathVectorX, pathVectorY);
        if (distance < 1.0E-4d) {
            System.out.println("distance ~ 0");
            value[0] = 0.0f;
            value[1] = 0.0f;
            return;
        }
        float dx = pathVectorX / distance;
        float dy = pathVectorY / distance;
        float perpendicular = (((y - startCenterY) * dx) - ((x - startCenterX) * dy)) / distance;
        float dist = (((x - startCenterX) * dx) + ((y - startCenterY) * dy)) / distance;
        if (attribute[0] != null) {
            if ("percentX".equals(attribute[0])) {
                value[0] = dist;
                value[1] = perpendicular;
                return;
            }
            return;
        }
        attribute[0] = "percentX";
        attribute[1] = "percentY";
        value[0] = dist;
        value[1] = perpendicular;
    }

    void positionScreenAttributes(MotionWidget view, FloatRect start, FloatRect end, float x, float y, String[] attribute, float[] value) {
        float startCenterX = start.centerX();
        float startCenterY = start.centerY();
        float endCenterX = end.centerX();
        float endCenterY = end.centerY();
        float f = endCenterX - startCenterX;
        float f2 = endCenterY - startCenterY;
        MotionWidget viewGroup = view.getParent();
        int width = viewGroup.getWidth();
        int height = viewGroup.getHeight();
        if (attribute[0] != null) {
            if ("percentX".equals(attribute[0])) {
                value[0] = x / width;
                value[1] = y / height;
                return;
            }
            value[1] = x / width;
            value[0] = y / height;
            return;
        }
        attribute[0] = "percentX";
        value[0] = x / width;
        attribute[1] = "percentY";
        value[1] = y / height;
    }

    void positionCartAttributes(FloatRect start, FloatRect end, float x, float y, String[] attribute, float[] value) {
        float startCenterX = start.centerX();
        float startCenterY = start.centerY();
        float endCenterX = end.centerX();
        float endCenterY = end.centerY();
        float pathVectorX = endCenterX - startCenterX;
        float pathVectorY = endCenterY - startCenterY;
        if (attribute[0] != null) {
            if ("percentX".equals(attribute[0])) {
                value[0] = (x - startCenterX) / pathVectorX;
                value[1] = (y - startCenterY) / pathVectorY;
                return;
            }
            value[1] = (x - startCenterX) / pathVectorX;
            value[0] = (y - startCenterY) / pathVectorY;
            return;
        }
        attribute[0] = "percentX";
        value[0] = (x - startCenterX) / pathVectorX;
        attribute[1] = "percentY";
        value[1] = (y - startCenterY) / pathVectorY;
    }

    public boolean intersects(int layoutWidth, int layoutHeight, FloatRect start, FloatRect end, float x, float y) {
        calcPosition(layoutWidth, layoutHeight, start.centerX(), start.centerY(), end.centerX(), end.centerY());
        if (Math.abs(x - this.mCalculatedPositionX) < SELECTION_SLOPE && Math.abs(y - this.mCalculatedPositionY) < SELECTION_SLOPE) {
            return true;
        }
        return false;
    }

    @Override // androidx.constraintlayout.core.motion.key.MotionKey
    public MotionKey copy(MotionKey src) {
        super.copy(src);
        MotionKeyPosition k = (MotionKeyPosition) src;
        this.mTransitionEasing = k.mTransitionEasing;
        this.mPathMotionArc = k.mPathMotionArc;
        this.mDrawPath = k.mDrawPath;
        this.mPercentWidth = k.mPercentWidth;
        this.mPercentHeight = Float.NaN;
        this.mPercentX = k.mPercentX;
        this.mPercentY = k.mPercentY;
        this.mAltPercentX = k.mAltPercentX;
        this.mAltPercentY = k.mAltPercentY;
        this.mCalculatedPositionX = k.mCalculatedPositionX;
        this.mCalculatedPositionY = k.mCalculatedPositionY;
        return this;
    }

    @Override // androidx.constraintlayout.core.motion.key.MotionKey
    /* renamed from: clone */
    public MotionKey mo2clone() {
        return new MotionKeyPosition().copy(this);
    }

    void calcPosition(int layoutWidth, int layoutHeight, float start_x, float start_y, float end_x, float end_y) {
        switch (this.mPositionType) {
            case 1:
                calcPathPosition(start_x, start_y, end_x, end_y);
                return;
            case 2:
                calcScreenPosition(layoutWidth, layoutHeight);
                return;
            default:
                calcCartesianPosition(start_x, start_y, end_x, end_y);
                return;
        }
    }

    @Override // androidx.constraintlayout.core.motion.key.MotionKey
    public void getAttributeNames(HashSet<String> attributes) {
    }

    @Override // androidx.constraintlayout.core.motion.key.MotionKey
    public void addValues(HashMap<String, SplineSet> splines) {
    }

    @Override // androidx.constraintlayout.core.motion.key.MotionKey, androidx.constraintlayout.core.motion.utils.TypedValues
    public boolean setValue(int type, int value) {
        switch (type) {
            case 100:
                this.mFramePosition = value;
                return true;
            case TypedValues.PositionType.TYPE_CURVE_FIT /* 508 */:
                this.mCurveFit = value;
                return true;
            case TypedValues.PositionType.TYPE_POSITION_TYPE /* 510 */:
                this.mPositionType = value;
                return true;
            default:
                return super.setValue(type, value);
        }
    }

    @Override // androidx.constraintlayout.core.motion.key.MotionKey, androidx.constraintlayout.core.motion.utils.TypedValues
    public boolean setValue(int type, float value) {
        switch (type) {
            case TypedValues.PositionType.TYPE_PERCENT_WIDTH /* 503 */:
                this.mPercentWidth = value;
                return true;
            case TypedValues.PositionType.TYPE_PERCENT_HEIGHT /* 504 */:
                this.mPercentHeight = value;
                return true;
            case TypedValues.PositionType.TYPE_SIZE_PERCENT /* 505 */:
                this.mPercentWidth = value;
                this.mPercentHeight = value;
                return true;
            case TypedValues.PositionType.TYPE_PERCENT_X /* 506 */:
                this.mPercentX = value;
                return true;
            case TypedValues.PositionType.TYPE_PERCENT_Y /* 507 */:
                this.mPercentY = value;
                return true;
            default:
                return super.setValue(type, value);
        }
    }

    @Override // androidx.constraintlayout.core.motion.key.MotionKey, androidx.constraintlayout.core.motion.utils.TypedValues
    public boolean setValue(int type, String value) {
        switch (type) {
            case TypedValues.PositionType.TYPE_TRANSITION_EASING /* 501 */:
                this.mTransitionEasing = value.toString();
                return true;
            default:
                return super.setValue(type, value);
        }
    }

    @Override // androidx.constraintlayout.core.motion.utils.TypedValues
    public int getId(String name) {
        return TypedValues.PositionType.CC.getId(name);
    }
}
