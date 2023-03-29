package androidx.constraintlayout.motion.widget;

import android.content.Context;
import android.util.AttributeSet;
import androidx.constraintlayout.motion.utils.ViewSpline;
import androidx.constraintlayout.widget.ConstraintAttribute;
import java.util.HashMap;
import java.util.HashSet;
/* loaded from: classes.dex */
public abstract class Key {
    public static final String ALPHA = "alpha";
    public static final String CURVEFIT = "curveFit";
    public static final String CUSTOM = "CUSTOM";
    public static final String ELEVATION = "elevation";
    public static final String MOTIONPROGRESS = "motionProgress";
    public static final String PIVOT_X = "transformPivotX";
    public static final String PIVOT_Y = "transformPivotY";
    public static final String PROGRESS = "progress";
    public static final String ROTATION = "rotation";
    public static final String ROTATION_X = "rotationX";
    public static final String ROTATION_Y = "rotationY";
    public static final String SCALE_X = "scaleX";
    public static final String SCALE_Y = "scaleY";
    public static final String TRANSITIONEASING = "transitionEasing";
    public static final String TRANSITION_PATH_ROTATE = "transitionPathRotate";
    public static final String TRANSLATION_X = "translationX";
    public static final String TRANSLATION_Y = "translationY";
    public static final String TRANSLATION_Z = "translationZ";
    public static int UNSET = -1;
    public static final String VISIBILITY = "visibility";
    public static final String WAVE_OFFSET = "waveOffset";
    public static final String WAVE_PERIOD = "wavePeriod";
    public static final String WAVE_PHASE = "wavePhase";
    public static final String WAVE_VARIES_BY = "waveVariesBy";
    HashMap<String, ConstraintAttribute> mCustomConstraints;
    int mFramePosition;
    int mTargetId;
    String mTargetString;
    protected int mType;

    public abstract void addValues(HashMap<String, ViewSpline> splines);

    @Override // 
    /* renamed from: clone */
    public abstract Key mo4clone();

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract void getAttributeNames(HashSet<String> attributes);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract void load(Context context, AttributeSet attrs);

    public abstract void setValue(String tag, Object value);

    public Key() {
        int i = UNSET;
        this.mFramePosition = i;
        this.mTargetId = i;
        this.mTargetString = null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean matches(String constraintTag) {
        String str = this.mTargetString;
        if (str == null || constraintTag == null) {
            return false;
        }
        return constraintTag.matches(str);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public float toFloat(Object value) {
        return value instanceof Float ? ((Float) value).floatValue() : Float.parseFloat(value.toString());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int toInt(Object value) {
        return value instanceof Integer ? ((Integer) value).intValue() : Integer.parseInt(value.toString());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean toBoolean(Object value) {
        return value instanceof Boolean ? ((Boolean) value).booleanValue() : Boolean.parseBoolean(value.toString());
    }

    public void setInterpolation(HashMap<String, Integer> interpolation) {
    }

    public Key copy(Key src) {
        this.mFramePosition = src.mFramePosition;
        this.mTargetId = src.mTargetId;
        this.mTargetString = src.mTargetString;
        this.mType = src.mType;
        this.mCustomConstraints = src.mCustomConstraints;
        return this;
    }

    public Key setViewId(int id) {
        this.mTargetId = id;
        return this;
    }

    public void setFramePosition(int pos) {
        this.mFramePosition = pos;
    }

    public int getFramePosition() {
        return this.mFramePosition;
    }
}
