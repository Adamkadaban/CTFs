package androidx.constraintlayout.core.motion;

import androidx.constraintlayout.core.motion.utils.TypedValues;
import androidx.constraintlayout.core.state.WidgetFrame;
import androidx.constraintlayout.core.widgets.ConstraintWidget;
import java.util.Set;
/* loaded from: classes.dex */
public class MotionWidget implements TypedValues {
    public static final int FILL_PARENT = -1;
    public static final int GONE_UNSET = Integer.MIN_VALUE;
    private static final int INTERNAL_MATCH_CONSTRAINT = -3;
    private static final int INTERNAL_MATCH_PARENT = -1;
    private static final int INTERNAL_WRAP_CONTENT = -2;
    private static final int INTERNAL_WRAP_CONTENT_CONSTRAINED = -4;
    public static final int INVISIBLE = 0;
    public static final int MATCH_CONSTRAINT = 0;
    public static final int MATCH_CONSTRAINT_WRAP = 1;
    public static final int MATCH_PARENT = -1;
    public static final int PARENT_ID = 0;
    public static final int ROTATE_LEFT_OF_PORTRATE = 4;
    public static final int ROTATE_NONE = 0;
    public static final int ROTATE_PORTRATE_OF_LEFT = 2;
    public static final int ROTATE_PORTRATE_OF_RIGHT = 1;
    public static final int ROTATE_RIGHT_OF_PORTRATE = 3;
    public static final int UNSET = -1;
    public static final int VISIBILITY_MODE_IGNORE = 1;
    public static final int VISIBILITY_MODE_NORMAL = 0;
    public static final int VISIBLE = 4;
    public static final int WRAP_CONTENT = -2;
    private float mProgress;
    float mTransitionPathRotate;
    Motion motion;
    PropertySet propertySet;
    WidgetFrame widgetFrame;

    /* loaded from: classes.dex */
    public static class Motion {
        private static final int INTERPOLATOR_REFERENCE_ID = -2;
        private static final int INTERPOLATOR_UNDEFINED = -3;
        private static final int SPLINE_STRING = -1;
        public int mAnimateRelativeTo = -1;
        public int mAnimateCircleAngleTo = 0;
        public String mTransitionEasing = null;
        public int mPathMotionArc = -1;
        public int mDrawPath = 0;
        public float mMotionStagger = Float.NaN;
        public int mPolarRelativeTo = -1;
        public float mPathRotate = Float.NaN;
        public float mQuantizeMotionPhase = Float.NaN;
        public int mQuantizeMotionSteps = -1;
        public String mQuantizeInterpolatorString = null;
        public int mQuantizeInterpolatorType = -3;
        public int mQuantizeInterpolatorID = -1;
    }

    /* loaded from: classes.dex */
    public static class PropertySet {
        public int visibility = 4;
        public int mVisibilityMode = 0;
        public float alpha = 1.0f;
        public float mProgress = Float.NaN;
    }

    public MotionWidget() {
        this.widgetFrame = new WidgetFrame();
        this.motion = new Motion();
        this.propertySet = new PropertySet();
    }

    public MotionWidget getParent() {
        return null;
    }

    public MotionWidget findViewById(int mTransformPivotTarget) {
        return null;
    }

    public void setVisibility(int visibility) {
        this.propertySet.visibility = visibility;
    }

    public String getName() {
        return this.widgetFrame.getId();
    }

    public void layout(int l, int t, int r, int b) {
        setBounds(l, t, r, b);
    }

    public String toString() {
        return this.widgetFrame.left + ", " + this.widgetFrame.top + ", " + this.widgetFrame.right + ", " + this.widgetFrame.bottom;
    }

    public void setBounds(int left, int top, int right, int bottom) {
        if (this.widgetFrame == null) {
            this.widgetFrame = new WidgetFrame((ConstraintWidget) null);
        }
        this.widgetFrame.top = top;
        this.widgetFrame.left = left;
        this.widgetFrame.right = right;
        this.widgetFrame.bottom = bottom;
    }

    public MotionWidget(WidgetFrame f) {
        this.widgetFrame = new WidgetFrame();
        this.motion = new Motion();
        this.propertySet = new PropertySet();
        this.widgetFrame = f;
    }

    @Override // androidx.constraintlayout.core.motion.utils.TypedValues
    public boolean setValue(int id, int value) {
        return setValueAttributes(id, value);
    }

    @Override // androidx.constraintlayout.core.motion.utils.TypedValues
    public boolean setValue(int id, float value) {
        boolean set = setValueAttributes(id, value);
        if (set) {
            return true;
        }
        return setValueMotion(id, value);
    }

    @Override // androidx.constraintlayout.core.motion.utils.TypedValues
    public boolean setValue(int id, String value) {
        return setValueMotion(id, value);
    }

    @Override // androidx.constraintlayout.core.motion.utils.TypedValues
    public boolean setValue(int id, boolean value) {
        return false;
    }

    public boolean setValueMotion(int id, int value) {
        switch (id) {
            case TypedValues.MotionType.TYPE_ANIMATE_RELATIVE_TO /* 605 */:
                this.motion.mAnimateRelativeTo = value;
                return true;
            case TypedValues.MotionType.TYPE_ANIMATE_CIRCLEANGLE_TO /* 606 */:
                this.motion.mAnimateCircleAngleTo = value;
                return true;
            case TypedValues.MotionType.TYPE_PATHMOTION_ARC /* 607 */:
                this.motion.mPathMotionArc = value;
                return true;
            case TypedValues.MotionType.TYPE_DRAW_PATH /* 608 */:
                this.motion.mDrawPath = value;
                return true;
            case TypedValues.MotionType.TYPE_POLAR_RELATIVETO /* 609 */:
                this.motion.mPolarRelativeTo = value;
                return true;
            case TypedValues.MotionType.TYPE_QUANTIZE_MOTIONSTEPS /* 610 */:
                this.motion.mQuantizeMotionSteps = value;
                return true;
            case TypedValues.MotionType.TYPE_QUANTIZE_INTERPOLATOR_TYPE /* 611 */:
                this.motion.mQuantizeInterpolatorType = value;
                return true;
            case TypedValues.MotionType.TYPE_QUANTIZE_INTERPOLATOR_ID /* 612 */:
                this.motion.mQuantizeInterpolatorID = value;
                return true;
            default:
                return false;
        }
    }

    public boolean setValueMotion(int id, String value) {
        switch (id) {
            case TypedValues.MotionType.TYPE_EASING /* 603 */:
                this.motion.mTransitionEasing = value;
                return true;
            case TypedValues.MotionType.TYPE_QUANTIZE_INTERPOLATOR /* 604 */:
                this.motion.mQuantizeInterpolatorString = value;
                return true;
            default:
                return false;
        }
    }

    public boolean setValueMotion(int id, float value) {
        switch (id) {
            case 600:
                this.motion.mMotionStagger = value;
                return true;
            case 601:
                this.motion.mPathRotate = value;
                return true;
            case TypedValues.MotionType.TYPE_QUANTIZE_MOTION_PHASE /* 602 */:
                this.motion.mQuantizeMotionPhase = value;
                return true;
            default:
                return false;
        }
    }

    public boolean setValueAttributes(int id, float value) {
        switch (id) {
            case 303:
                this.widgetFrame.alpha = value;
                return true;
            case 304:
                this.widgetFrame.translationX = value;
                return true;
            case 305:
                this.widgetFrame.translationY = value;
                return true;
            case 306:
                this.widgetFrame.translationZ = value;
                return true;
            case 307:
            default:
                return false;
            case 308:
                this.widgetFrame.rotationX = value;
                return true;
            case 309:
                this.widgetFrame.rotationY = value;
                return true;
            case 310:
                this.widgetFrame.rotationZ = value;
                return true;
            case 311:
                this.widgetFrame.scaleX = value;
                return true;
            case 312:
                this.widgetFrame.scaleY = value;
                return true;
            case 313:
                this.widgetFrame.pivotX = value;
                return true;
            case 314:
                this.widgetFrame.pivotY = value;
                return true;
            case 315:
                this.mProgress = value;
                return true;
            case TypedValues.AttributesType.TYPE_PATH_ROTATE /* 316 */:
                this.mTransitionPathRotate = value;
                return true;
        }
    }

    public float getValueAttributes(int id) {
        switch (id) {
            case 303:
                return this.widgetFrame.alpha;
            case 304:
                return this.widgetFrame.translationX;
            case 305:
                return this.widgetFrame.translationY;
            case 306:
                return this.widgetFrame.translationZ;
            case 307:
            default:
                return Float.NaN;
            case 308:
                return this.widgetFrame.rotationX;
            case 309:
                return this.widgetFrame.rotationY;
            case 310:
                return this.widgetFrame.rotationZ;
            case 311:
                return this.widgetFrame.scaleX;
            case 312:
                return this.widgetFrame.scaleY;
            case 313:
                return this.widgetFrame.pivotX;
            case 314:
                return this.widgetFrame.pivotY;
            case 315:
                return this.mProgress;
            case TypedValues.AttributesType.TYPE_PATH_ROTATE /* 316 */:
                return this.mTransitionPathRotate;
        }
    }

    @Override // androidx.constraintlayout.core.motion.utils.TypedValues
    public int getId(String name) {
        int ret = TypedValues.AttributesType.CC.getId(name);
        if (ret != -1) {
            return ret;
        }
        return TypedValues.MotionType.CC.getId(name);
    }

    public int getTop() {
        return this.widgetFrame.top;
    }

    public int getLeft() {
        return this.widgetFrame.left;
    }

    public int getBottom() {
        return this.widgetFrame.bottom;
    }

    public int getRight() {
        return this.widgetFrame.right;
    }

    public void setPivotX(float px) {
        this.widgetFrame.pivotX = px;
    }

    public void setPivotY(float py) {
        this.widgetFrame.pivotY = py;
    }

    public float getRotationX() {
        return this.widgetFrame.rotationX;
    }

    public void setRotationX(float rotationX) {
        this.widgetFrame.rotationX = rotationX;
    }

    public float getRotationY() {
        return this.widgetFrame.rotationY;
    }

    public void setRotationY(float rotationY) {
        this.widgetFrame.rotationY = rotationY;
    }

    public float getRotationZ() {
        return this.widgetFrame.rotationZ;
    }

    public void setRotationZ(float rotationZ) {
        this.widgetFrame.rotationZ = rotationZ;
    }

    public float getTranslationX() {
        return this.widgetFrame.translationX;
    }

    public void setTranslationX(float translationX) {
        this.widgetFrame.translationX = translationX;
    }

    public float getTranslationY() {
        return this.widgetFrame.translationY;
    }

    public void setTranslationY(float translationY) {
        this.widgetFrame.translationY = translationY;
    }

    public void setTranslationZ(float tz) {
        this.widgetFrame.translationZ = tz;
    }

    public float getTranslationZ() {
        return this.widgetFrame.translationZ;
    }

    public float getScaleX() {
        return this.widgetFrame.scaleX;
    }

    public void setScaleX(float scaleX) {
        this.widgetFrame.scaleX = scaleX;
    }

    public float getScaleY() {
        return this.widgetFrame.scaleY;
    }

    public void setScaleY(float scaleY) {
        this.widgetFrame.scaleY = scaleY;
    }

    public int getVisibility() {
        return this.propertySet.visibility;
    }

    public float getPivotX() {
        return this.widgetFrame.pivotX;
    }

    public float getPivotY() {
        return this.widgetFrame.pivotY;
    }

    public float getAlpha() {
        return this.propertySet.alpha;
    }

    public int getX() {
        return this.widgetFrame.left;
    }

    public int getY() {
        return this.widgetFrame.top;
    }

    public int getWidth() {
        return this.widgetFrame.right - this.widgetFrame.left;
    }

    public int getHeight() {
        return this.widgetFrame.bottom - this.widgetFrame.top;
    }

    public WidgetFrame getWidgetFrame() {
        return this.widgetFrame;
    }

    public Set<String> getCustomAttributeNames() {
        return this.widgetFrame.getCustomAttributeNames();
    }

    public void setCustomAttribute(String name, int type, float value) {
        this.widgetFrame.setCustomAttribute(name, type, value);
    }

    public void setCustomAttribute(String name, int type, int value) {
        this.widgetFrame.setCustomAttribute(name, type, value);
    }

    public void setCustomAttribute(String name, int type, boolean value) {
        this.widgetFrame.setCustomAttribute(name, type, value);
    }

    public void setCustomAttribute(String name, int type, String value) {
        this.widgetFrame.setCustomAttribute(name, type, value);
    }

    public CustomVariable getCustomAttribute(String name) {
        return this.widgetFrame.getCustomAttribute(name);
    }

    public void setInterpolatedValue(CustomAttribute attribute, float[] mCache) {
        this.widgetFrame.setCustomAttribute(attribute.mName, TypedValues.Custom.TYPE_FLOAT, mCache[0]);
    }
}
