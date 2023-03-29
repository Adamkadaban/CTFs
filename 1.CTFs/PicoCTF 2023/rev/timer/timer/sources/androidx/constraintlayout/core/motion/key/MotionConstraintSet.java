package androidx.constraintlayout.core.motion.key;
/* loaded from: classes.dex */
public class MotionConstraintSet {
    private static final String ERROR_MESSAGE = "XML parser error must be within a Constraint ";
    private static final int INTERNAL_MATCH_CONSTRAINT = -3;
    private static final int INTERNAL_MATCH_PARENT = -1;
    private static final int INTERNAL_WRAP_CONTENT = -2;
    private static final int INTERNAL_WRAP_CONTENT_CONSTRAINED = -4;
    public static final int ROTATE_LEFT_OF_PORTRATE = 4;
    public static final int ROTATE_NONE = 0;
    public static final int ROTATE_PORTRATE_OF_LEFT = 2;
    public static final int ROTATE_PORTRATE_OF_RIGHT = 1;
    public static final int ROTATE_RIGHT_OF_PORTRATE = 3;
    public String mIdString;
    public int mRotate = 0;
    private boolean mValidate;
}
