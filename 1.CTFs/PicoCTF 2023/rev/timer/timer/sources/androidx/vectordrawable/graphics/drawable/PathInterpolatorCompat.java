package androidx.vectordrawable.graphics.drawable;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Path;
import android.graphics.PathMeasure;
import android.util.AttributeSet;
import android.view.InflateException;
import android.view.animation.Interpolator;
import androidx.core.content.res.TypedArrayUtils;
import androidx.core.graphics.PathParser;
import org.xmlpull.v1.XmlPullParser;
/* loaded from: classes.dex */
public class PathInterpolatorCompat implements Interpolator {
    public static final double EPSILON = 1.0E-5d;
    public static final int MAX_NUM_POINTS = 3000;
    private static final float PRECISION = 0.002f;
    private float[] mX;
    private float[] mY;

    public PathInterpolatorCompat(Context context, AttributeSet attrs, XmlPullParser parser) {
        this(context.getResources(), context.getTheme(), attrs, parser);
    }

    public PathInterpolatorCompat(Resources res, Resources.Theme theme, AttributeSet attrs, XmlPullParser parser) {
        TypedArray a = TypedArrayUtils.obtainAttributes(res, theme, attrs, AndroidResources.STYLEABLE_PATH_INTERPOLATOR);
        parseInterpolatorFromTypeArray(a, parser);
        a.recycle();
    }

    private void parseInterpolatorFromTypeArray(TypedArray a, XmlPullParser parser) {
        if (TypedArrayUtils.hasAttribute(parser, "pathData")) {
            String pathData = TypedArrayUtils.getNamedString(a, parser, "pathData", 4);
            Path path = PathParser.createPathFromPathData(pathData);
            if (path == null) {
                throw new InflateException("The path is null, which is created from " + pathData);
            }
            initPath(path);
        } else if (!TypedArrayUtils.hasAttribute(parser, "controlX1")) {
            throw new InflateException("pathInterpolator requires the controlX1 attribute");
        } else {
            if (TypedArrayUtils.hasAttribute(parser, "controlY1")) {
                float x1 = TypedArrayUtils.getNamedFloat(a, parser, "controlX1", 0, 0.0f);
                float y1 = TypedArrayUtils.getNamedFloat(a, parser, "controlY1", 1, 0.0f);
                boolean hasX2 = TypedArrayUtils.hasAttribute(parser, "controlX2");
                boolean hasY2 = TypedArrayUtils.hasAttribute(parser, "controlY2");
                if (hasX2 != hasY2) {
                    throw new InflateException("pathInterpolator requires both controlX2 and controlY2 for cubic Beziers.");
                }
                if (hasX2) {
                    float x2 = TypedArrayUtils.getNamedFloat(a, parser, "controlX2", 2, 0.0f);
                    float y2 = TypedArrayUtils.getNamedFloat(a, parser, "controlY2", 3, 0.0f);
                    initCubic(x1, y1, x2, y2);
                    return;
                }
                initQuad(x1, y1);
                return;
            }
            throw new InflateException("pathInterpolator requires the controlY1 attribute");
        }
    }

    private void initQuad(float controlX, float controlY) {
        Path path = new Path();
        path.moveTo(0.0f, 0.0f);
        path.quadTo(controlX, controlY, 1.0f, 1.0f);
        initPath(path);
    }

    private void initCubic(float x1, float y1, float x2, float y2) {
        Path path = new Path();
        path.moveTo(0.0f, 0.0f);
        path.cubicTo(x1, y1, x2, y2, 1.0f, 1.0f);
        initPath(path);
    }

    private void initPath(Path path) {
        PathMeasure pathMeasure = new PathMeasure(path, false);
        float pathLength = pathMeasure.getLength();
        int numPoints = Math.min((int) MAX_NUM_POINTS, ((int) (pathLength / 0.002f)) + 1);
        if (numPoints <= 0) {
            throw new IllegalArgumentException("The Path has a invalid length " + pathLength);
        }
        this.mX = new float[numPoints];
        this.mY = new float[numPoints];
        float[] position = new float[2];
        for (int i = 0; i < numPoints; i++) {
            float distance = (i * pathLength) / (numPoints - 1);
            pathMeasure.getPosTan(distance, position, null);
            this.mX[i] = position[0];
            this.mY[i] = position[1];
        }
        if (Math.abs(this.mX[0]) > 1.0E-5d || Math.abs(this.mY[0]) > 1.0E-5d || Math.abs(this.mX[numPoints - 1] - 1.0f) > 1.0E-5d || Math.abs(this.mY[numPoints - 1] - 1.0f) > 1.0E-5d) {
            throw new IllegalArgumentException("The Path must start at (0,0) and end at (1,1) start: " + this.mX[0] + "," + this.mY[0] + " end:" + this.mX[numPoints - 1] + "," + this.mY[numPoints - 1]);
        }
        float prevX = 0.0f;
        int componentIndex = 0;
        int i2 = 0;
        while (i2 < numPoints) {
            float[] fArr = this.mX;
            int componentIndex2 = componentIndex + 1;
            float x = fArr[componentIndex];
            if (x < prevX) {
                throw new IllegalArgumentException("The Path cannot loop back on itself, x :" + x);
            }
            fArr[i2] = x;
            prevX = x;
            i2++;
            componentIndex = componentIndex2;
        }
        if (pathMeasure.nextContour()) {
            throw new IllegalArgumentException("The Path should be continuous, can't have 2+ contours");
        }
    }

    @Override // android.animation.TimeInterpolator
    public float getInterpolation(float t) {
        if (t <= 0.0f) {
            return 0.0f;
        }
        if (t >= 1.0f) {
            return 1.0f;
        }
        int startIndex = 0;
        int endIndex = this.mX.length - 1;
        while (endIndex - startIndex > 1) {
            int midIndex = (startIndex + endIndex) / 2;
            if (t < this.mX[midIndex]) {
                endIndex = midIndex;
            } else {
                startIndex = midIndex;
            }
        }
        float[] fArr = this.mX;
        float xRange = fArr[endIndex] - fArr[startIndex];
        if (xRange == 0.0f) {
            return this.mY[startIndex];
        }
        float tInRange = t - fArr[startIndex];
        float fraction = tInRange / xRange;
        float[] fArr2 = this.mY;
        float startY = fArr2[startIndex];
        float endY = fArr2[endIndex];
        return ((endY - startY) * fraction) + startY;
    }
}
