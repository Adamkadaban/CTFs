package androidx.transition;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Path;
import android.util.AttributeSet;
import androidx.core.content.res.TypedArrayUtils;
import org.xmlpull.v1.XmlPullParser;
/* loaded from: classes.dex */
public class ArcMotion extends PathMotion {
    private static final float DEFAULT_MAX_ANGLE_DEGREES = 70.0f;
    private static final float DEFAULT_MAX_TANGENT = (float) Math.tan(Math.toRadians(35.0d));
    private static final float DEFAULT_MIN_ANGLE_DEGREES = 0.0f;
    private float mMaximumAngle;
    private float mMaximumTangent;
    private float mMinimumHorizontalAngle;
    private float mMinimumHorizontalTangent;
    private float mMinimumVerticalAngle;
    private float mMinimumVerticalTangent;

    public ArcMotion() {
        this.mMinimumHorizontalAngle = 0.0f;
        this.mMinimumVerticalAngle = 0.0f;
        this.mMaximumAngle = DEFAULT_MAX_ANGLE_DEGREES;
        this.mMinimumHorizontalTangent = 0.0f;
        this.mMinimumVerticalTangent = 0.0f;
        this.mMaximumTangent = DEFAULT_MAX_TANGENT;
    }

    public ArcMotion(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.mMinimumHorizontalAngle = 0.0f;
        this.mMinimumVerticalAngle = 0.0f;
        this.mMaximumAngle = DEFAULT_MAX_ANGLE_DEGREES;
        this.mMinimumHorizontalTangent = 0.0f;
        this.mMinimumVerticalTangent = 0.0f;
        this.mMaximumTangent = DEFAULT_MAX_TANGENT;
        TypedArray a = context.obtainStyledAttributes(attrs, Styleable.ARC_MOTION);
        XmlPullParser parser = (XmlPullParser) attrs;
        float minimumVerticalAngle = TypedArrayUtils.getNamedFloat(a, parser, "minimumVerticalAngle", 1, 0.0f);
        setMinimumVerticalAngle(minimumVerticalAngle);
        float minimumHorizontalAngle = TypedArrayUtils.getNamedFloat(a, parser, "minimumHorizontalAngle", 0, 0.0f);
        setMinimumHorizontalAngle(minimumHorizontalAngle);
        float maximumAngle = TypedArrayUtils.getNamedFloat(a, parser, "maximumAngle", 2, DEFAULT_MAX_ANGLE_DEGREES);
        setMaximumAngle(maximumAngle);
        a.recycle();
    }

    public void setMinimumHorizontalAngle(float angleInDegrees) {
        this.mMinimumHorizontalAngle = angleInDegrees;
        this.mMinimumHorizontalTangent = toTangent(angleInDegrees);
    }

    public float getMinimumHorizontalAngle() {
        return this.mMinimumHorizontalAngle;
    }

    public void setMinimumVerticalAngle(float angleInDegrees) {
        this.mMinimumVerticalAngle = angleInDegrees;
        this.mMinimumVerticalTangent = toTangent(angleInDegrees);
    }

    public float getMinimumVerticalAngle() {
        return this.mMinimumVerticalAngle;
    }

    public void setMaximumAngle(float angleInDegrees) {
        this.mMaximumAngle = angleInDegrees;
        this.mMaximumTangent = toTangent(angleInDegrees);
    }

    public float getMaximumAngle() {
        return this.mMaximumAngle;
    }

    private static float toTangent(float arcInDegrees) {
        if (arcInDegrees < 0.0f || arcInDegrees > 90.0f) {
            throw new IllegalArgumentException("Arc must be between 0 and 90 degrees");
        }
        return (float) Math.tan(Math.toRadians(arcInDegrees / 2.0f));
    }

    @Override // androidx.transition.PathMotion
    public Path getPath(float startX, float startY, float endX, float endY) {
        float ex;
        float ey;
        float minimumArcDist2;
        float newArcDistance2;
        float ey2;
        float ex2;
        Path path = new Path();
        path.moveTo(startX, startY);
        float deltaX = endX - startX;
        float deltaY = endY - startY;
        float h2 = (deltaX * deltaX) + (deltaY * deltaY);
        float dx = (startX + endX) / 2.0f;
        float dy = (startY + endY) / 2.0f;
        float midDist2 = h2 * 0.25f;
        boolean isMovingUpwards = startY > endY;
        if (Math.abs(deltaX) < Math.abs(deltaY)) {
            float eDistY = Math.abs(h2 / (deltaY * 2.0f));
            if (isMovingUpwards) {
                ey = endY + eDistY;
                ex = endX;
            } else {
                ey = startY + eDistY;
                ex = startX;
            }
            float f = this.mMinimumVerticalTangent;
            float minimumArcDist22 = midDist2 * f * f;
            minimumArcDist2 = minimumArcDist22;
        } else {
            float eDistX = h2 / (deltaX * 2.0f);
            if (isMovingUpwards) {
                float ex3 = startX + eDistX;
                ex = ex3;
                ey = startY;
            } else {
                float ex4 = endX - eDistX;
                ex = ex4;
                ey = endY;
            }
            float f2 = this.mMinimumHorizontalTangent;
            minimumArcDist2 = midDist2 * f2 * f2;
        }
        float arcDistX = dx - ex;
        float arcDistY = dy - ey;
        float arcDist2 = (arcDistX * arcDistX) + (arcDistY * arcDistY);
        float f3 = this.mMaximumTangent;
        float maximumArcDist2 = midDist2 * f3 * f3;
        if (arcDist2 < minimumArcDist2) {
            float newArcDistance22 = minimumArcDist2;
            newArcDistance2 = newArcDistance22;
        } else if (arcDist2 <= maximumArcDist2) {
            newArcDistance2 = 0.0f;
        } else {
            newArcDistance2 = maximumArcDist2;
        }
        if (newArcDistance2 == 0.0f) {
            ey2 = ey;
            ex2 = ex;
        } else {
            float ratio2 = newArcDistance2 / arcDist2;
            float ratio = (float) Math.sqrt(ratio2);
            ey2 = dy + ((ey - dy) * ratio);
            ex2 = dx + ((ex - dx) * ratio);
        }
        float control1X = (startX + ex2) / 2.0f;
        float control1Y = (startY + ey2) / 2.0f;
        float control2X = (ex2 + endX) / 2.0f;
        float control2Y = (ey2 + endY) / 2.0f;
        path.cubicTo(control1X, control1Y, control2X, control2Y, endX, endY);
        return path;
    }
}
