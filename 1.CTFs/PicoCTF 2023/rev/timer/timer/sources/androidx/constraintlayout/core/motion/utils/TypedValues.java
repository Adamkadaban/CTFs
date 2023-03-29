package androidx.constraintlayout.core.motion.utils;
/* loaded from: classes.dex */
public interface TypedValues {
    public static final int BOOLEAN_MASK = 1;
    public static final int FLOAT_MASK = 4;
    public static final int INT_MASK = 2;
    public static final int STRING_MASK = 8;
    public static final String S_CUSTOM = "CUSTOM";
    public static final int TYPE_FRAME_POSITION = 100;
    public static final int TYPE_TARGET = 101;

    /* loaded from: classes.dex */
    public interface OnSwipe {
        public static final String AUTOCOMPLETE_MODE = "autocompletemode";
        public static final String DRAG_DIRECTION = "dragdirection";
        public static final String DRAG_SCALE = "dragscale";
        public static final String DRAG_THRESHOLD = "dragthreshold";
        public static final String LIMIT_BOUNDS_TO = "limitboundsto";
        public static final String MAX_ACCELERATION = "maxacceleration";
        public static final String MAX_VELOCITY = "maxvelocity";
        public static final String MOVE_WHEN_SCROLLAT_TOP = "movewhenscrollattop";
        public static final String NESTED_SCROLL_FLAGS = "nestedscrollflags";
        public static final String ON_TOUCH_UP = "ontouchup";
        public static final String ROTATION_CENTER_ID = "rotationcenterid";
        public static final String SPRINGS_TOP_THRESHOLD = "springstopthreshold";
        public static final String SPRING_BOUNDARY = "springboundary";
        public static final String SPRING_DAMPING = "springdamping";
        public static final String SPRING_MASS = "springmass";
        public static final String SPRING_STIFFNESS = "springstiffness";
        public static final String TOUCH_ANCHOR_ID = "touchanchorid";
        public static final String TOUCH_ANCHOR_SIDE = "touchanchorside";
        public static final String TOUCH_REGION_ID = "touchregionid";
        public static final String[] ON_TOUCH_UP_ENUM = {"autoComplete", "autoCompleteToStart", "autoCompleteToEnd", "stop", "decelerate", "decelerateAndComplete", "neverCompleteToStart", "neverCompleteToEnd"};
        public static final String[] SPRING_BOUNDARY_ENUM = {"overshoot", "bounceStart", "bounceEnd", "bounceBoth"};
        public static final String[] AUTOCOMPLETE_MODE_ENUM = {"continuousVelocity", "spring"};
        public static final String[] NESTED_SCROLL_FLAGS_ENUM = {"none", "disablePostScroll", "disableScroll", "supportScrollUp"};
    }

    int getId(String str);

    boolean setValue(int i, float f);

    boolean setValue(int i, int i2);

    boolean setValue(int i, String str);

    boolean setValue(int i, boolean z);

    /* loaded from: classes.dex */
    public interface AttributesType {
        public static final String NAME = "KeyAttributes";
        public static final String S_ALPHA = "alpha";
        public static final String S_CURVE_FIT = "curveFit";
        public static final String S_CUSTOM = "CUSTOM";
        public static final String S_EASING = "easing";
        public static final String S_ELEVATION = "elevation";
        public static final String S_PATH_ROTATE = "pathRotate";
        public static final String S_PIVOT_X = "pivotX";
        public static final String S_PIVOT_Y = "pivotY";
        public static final String S_PROGRESS = "progress";
        public static final String S_ROTATION_X = "rotationX";
        public static final String S_ROTATION_Y = "rotationY";
        public static final String S_ROTATION_Z = "rotationZ";
        public static final String S_SCALE_X = "scaleX";
        public static final String S_SCALE_Y = "scaleY";
        public static final String S_TRANSLATION_X = "translationX";
        public static final String S_TRANSLATION_Y = "translationY";
        public static final String S_TRANSLATION_Z = "translationZ";
        public static final String S_VISIBILITY = "visibility";
        public static final int TYPE_ALPHA = 303;
        public static final int TYPE_CURVE_FIT = 301;
        public static final int TYPE_EASING = 317;
        public static final int TYPE_ELEVATION = 307;
        public static final int TYPE_PATH_ROTATE = 316;
        public static final int TYPE_PIVOT_TARGET = 318;
        public static final int TYPE_PIVOT_X = 313;
        public static final int TYPE_PIVOT_Y = 314;
        public static final int TYPE_PROGRESS = 315;
        public static final int TYPE_ROTATION_X = 308;
        public static final int TYPE_ROTATION_Y = 309;
        public static final int TYPE_ROTATION_Z = 310;
        public static final int TYPE_SCALE_X = 311;
        public static final int TYPE_SCALE_Y = 312;
        public static final int TYPE_TRANSLATION_X = 304;
        public static final int TYPE_TRANSLATION_Y = 305;
        public static final int TYPE_TRANSLATION_Z = 306;
        public static final int TYPE_VISIBILITY = 302;
        public static final String S_FRAME = "frame";
        public static final String S_TARGET = "target";
        public static final String S_PIVOT_TARGET = "pivotTarget";
        public static final String[] KEY_WORDS = {"curveFit", "visibility", "alpha", "translationX", "translationY", "translationZ", "elevation", "rotationX", "rotationY", "rotationZ", "scaleX", "scaleY", "pivotX", "pivotY", "progress", "pathRotate", "easing", "CUSTOM", S_FRAME, S_TARGET, S_PIVOT_TARGET};

        /* renamed from: androidx.constraintlayout.core.motion.utils.TypedValues$AttributesType$-CC  reason: invalid class name */
        /* loaded from: classes.dex */
        public final /* synthetic */ class CC {
            static {
                String str = AttributesType.NAME;
            }

            /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
            public static int getId(String name) {
                char c;
                switch (name.hashCode()) {
                    case -1310311125:
                        if (name.equals("easing")) {
                            c = 16;
                            break;
                        }
                        c = 65535;
                        break;
                    case -1249320806:
                        if (name.equals("rotationX")) {
                            c = 7;
                            break;
                        }
                        c = 65535;
                        break;
                    case -1249320805:
                        if (name.equals("rotationY")) {
                            c = '\b';
                            break;
                        }
                        c = 65535;
                        break;
                    case -1249320804:
                        if (name.equals("rotationZ")) {
                            c = '\t';
                            break;
                        }
                        c = 65535;
                        break;
                    case -1225497657:
                        if (name.equals("translationX")) {
                            c = 3;
                            break;
                        }
                        c = 65535;
                        break;
                    case -1225497656:
                        if (name.equals("translationY")) {
                            c = 4;
                            break;
                        }
                        c = 65535;
                        break;
                    case -1225497655:
                        if (name.equals("translationZ")) {
                            c = 5;
                            break;
                        }
                        c = 65535;
                        break;
                    case -1001078227:
                        if (name.equals("progress")) {
                            c = 14;
                            break;
                        }
                        c = 65535;
                        break;
                    case -987906986:
                        if (name.equals("pivotX")) {
                            c = '\f';
                            break;
                        }
                        c = 65535;
                        break;
                    case -987906985:
                        if (name.equals("pivotY")) {
                            c = '\r';
                            break;
                        }
                        c = 65535;
                        break;
                    case -908189618:
                        if (name.equals("scaleX")) {
                            c = '\n';
                            break;
                        }
                        c = 65535;
                        break;
                    case -908189617:
                        if (name.equals("scaleY")) {
                            c = 11;
                            break;
                        }
                        c = 65535;
                        break;
                    case -880905839:
                        if (name.equals(AttributesType.S_TARGET)) {
                            c = 18;
                            break;
                        }
                        c = 65535;
                        break;
                    case -4379043:
                        if (name.equals("elevation")) {
                            c = 6;
                            break;
                        }
                        c = 65535;
                        break;
                    case 92909918:
                        if (name.equals("alpha")) {
                            c = 2;
                            break;
                        }
                        c = 65535;
                        break;
                    case 97692013:
                        if (name.equals(AttributesType.S_FRAME)) {
                            c = 17;
                            break;
                        }
                        c = 65535;
                        break;
                    case 579057826:
                        if (name.equals("curveFit")) {
                            c = 0;
                            break;
                        }
                        c = 65535;
                        break;
                    case 803192288:
                        if (name.equals("pathRotate")) {
                            c = 15;
                            break;
                        }
                        c = 65535;
                        break;
                    case 1167159411:
                        if (name.equals(AttributesType.S_PIVOT_TARGET)) {
                            c = 19;
                            break;
                        }
                        c = 65535;
                        break;
                    case 1941332754:
                        if (name.equals("visibility")) {
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
                        return 301;
                    case 1:
                        return 302;
                    case 2:
                        return 303;
                    case 3:
                        return 304;
                    case 4:
                        return 305;
                    case 5:
                        return 306;
                    case 6:
                        return 307;
                    case 7:
                        return 308;
                    case '\b':
                        return 309;
                    case '\t':
                        return 310;
                    case '\n':
                        return 311;
                    case 11:
                        return 312;
                    case '\f':
                        return 313;
                    case '\r':
                        return 314;
                    case 14:
                        return 315;
                    case 15:
                        return AttributesType.TYPE_PATH_ROTATE;
                    case 16:
                        return AttributesType.TYPE_EASING;
                    case 17:
                        return 100;
                    case 18:
                        return 101;
                    case 19:
                        return AttributesType.TYPE_PIVOT_TARGET;
                    default:
                        return -1;
                }
            }

            public static int getType(int name) {
                switch (name) {
                    case 100:
                    case 301:
                    case 302:
                        return 2;
                    case 101:
                    case AttributesType.TYPE_EASING /* 317 */:
                    case AttributesType.TYPE_PIVOT_TARGET /* 318 */:
                        return 8;
                    case 303:
                    case 304:
                    case 305:
                    case 306:
                    case 307:
                    case 308:
                    case 309:
                    case 310:
                    case 311:
                    case 312:
                    case 313:
                    case 314:
                    case 315:
                    case AttributesType.TYPE_PATH_ROTATE /* 316 */:
                        return 4;
                    default:
                        return -1;
                }
            }
        }
    }

    /* loaded from: classes.dex */
    public interface CycleType {
        public static final String NAME = "KeyCycle";
        public static final String S_ALPHA = "alpha";
        public static final String S_CURVE_FIT = "curveFit";
        public static final String S_EASING = "easing";
        public static final String S_ELEVATION = "elevation";
        public static final String S_PATH_ROTATE = "pathRotate";
        public static final String S_PIVOT_X = "pivotX";
        public static final String S_PIVOT_Y = "pivotY";
        public static final String S_PROGRESS = "progress";
        public static final String S_ROTATION_X = "rotationX";
        public static final String S_ROTATION_Y = "rotationY";
        public static final String S_ROTATION_Z = "rotationZ";
        public static final String S_SCALE_X = "scaleX";
        public static final String S_SCALE_Y = "scaleY";
        public static final String S_TRANSLATION_X = "translationX";
        public static final String S_TRANSLATION_Y = "translationY";
        public static final String S_TRANSLATION_Z = "translationZ";
        public static final String S_VISIBILITY = "visibility";
        public static final String S_WAVE_SHAPE = "waveShape";
        public static final int TYPE_ALPHA = 403;
        public static final int TYPE_CURVE_FIT = 401;
        public static final int TYPE_CUSTOM_WAVE_SHAPE = 422;
        public static final int TYPE_EASING = 420;
        public static final int TYPE_ELEVATION = 307;
        public static final int TYPE_PATH_ROTATE = 416;
        public static final int TYPE_PIVOT_X = 313;
        public static final int TYPE_PIVOT_Y = 314;
        public static final int TYPE_PROGRESS = 315;
        public static final int TYPE_ROTATION_X = 308;
        public static final int TYPE_ROTATION_Y = 309;
        public static final int TYPE_ROTATION_Z = 310;
        public static final int TYPE_SCALE_X = 311;
        public static final int TYPE_SCALE_Y = 312;
        public static final int TYPE_TRANSLATION_X = 304;
        public static final int TYPE_TRANSLATION_Y = 305;
        public static final int TYPE_TRANSLATION_Z = 306;
        public static final int TYPE_VISIBILITY = 402;
        public static final int TYPE_WAVE_OFFSET = 424;
        public static final int TYPE_WAVE_PERIOD = 423;
        public static final int TYPE_WAVE_PHASE = 425;
        public static final int TYPE_WAVE_SHAPE = 421;
        public static final String S_CUSTOM_WAVE_SHAPE = "customWave";
        public static final String S_WAVE_PERIOD = "period";
        public static final String S_WAVE_OFFSET = "offset";
        public static final String S_WAVE_PHASE = "phase";
        public static final String[] KEY_WORDS = {"curveFit", "visibility", "alpha", "translationX", "translationY", "translationZ", "elevation", "rotationX", "rotationY", "rotationZ", "scaleX", "scaleY", "pivotX", "pivotY", "progress", "pathRotate", "easing", "waveShape", S_CUSTOM_WAVE_SHAPE, S_WAVE_PERIOD, S_WAVE_OFFSET, S_WAVE_PHASE};

        /* renamed from: androidx.constraintlayout.core.motion.utils.TypedValues$CycleType$-CC  reason: invalid class name */
        /* loaded from: classes.dex */
        public final /* synthetic */ class CC {
            static {
                String str = CycleType.NAME;
            }

            /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
            public static int getId(String name) {
                char c;
                switch (name.hashCode()) {
                    case -1310311125:
                        if (name.equals("easing")) {
                            c = 15;
                            break;
                        }
                        c = 65535;
                        break;
                    case -1249320806:
                        if (name.equals("rotationX")) {
                            c = 6;
                            break;
                        }
                        c = 65535;
                        break;
                    case -1249320805:
                        if (name.equals("rotationY")) {
                            c = 7;
                            break;
                        }
                        c = 65535;
                        break;
                    case -1249320804:
                        if (name.equals("rotationZ")) {
                            c = '\b';
                            break;
                        }
                        c = 65535;
                        break;
                    case -1225497657:
                        if (name.equals("translationX")) {
                            c = 3;
                            break;
                        }
                        c = 65535;
                        break;
                    case -1225497656:
                        if (name.equals("translationY")) {
                            c = 4;
                            break;
                        }
                        c = 65535;
                        break;
                    case -1225497655:
                        if (name.equals("translationZ")) {
                            c = 5;
                            break;
                        }
                        c = 65535;
                        break;
                    case -1001078227:
                        if (name.equals("progress")) {
                            c = '\r';
                            break;
                        }
                        c = 65535;
                        break;
                    case -987906986:
                        if (name.equals("pivotX")) {
                            c = 11;
                            break;
                        }
                        c = 65535;
                        break;
                    case -987906985:
                        if (name.equals("pivotY")) {
                            c = '\f';
                            break;
                        }
                        c = 65535;
                        break;
                    case -908189618:
                        if (name.equals("scaleX")) {
                            c = '\t';
                            break;
                        }
                        c = 65535;
                        break;
                    case -908189617:
                        if (name.equals("scaleY")) {
                            c = '\n';
                            break;
                        }
                        c = 65535;
                        break;
                    case 92909918:
                        if (name.equals("alpha")) {
                            c = 2;
                            break;
                        }
                        c = 65535;
                        break;
                    case 579057826:
                        if (name.equals("curveFit")) {
                            c = 0;
                            break;
                        }
                        c = 65535;
                        break;
                    case 803192288:
                        if (name.equals("pathRotate")) {
                            c = 14;
                            break;
                        }
                        c = 65535;
                        break;
                    case 1941332754:
                        if (name.equals("visibility")) {
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
                        return CycleType.TYPE_CURVE_FIT;
                    case 1:
                        return CycleType.TYPE_VISIBILITY;
                    case 2:
                        return CycleType.TYPE_ALPHA;
                    case 3:
                        return 304;
                    case 4:
                        return 305;
                    case 5:
                        return 306;
                    case 6:
                        return 308;
                    case 7:
                        return 309;
                    case '\b':
                        return 310;
                    case '\t':
                        return 311;
                    case '\n':
                        return 312;
                    case 11:
                        return 313;
                    case '\f':
                        return 314;
                    case '\r':
                        return 315;
                    case 14:
                        return CycleType.TYPE_PATH_ROTATE;
                    case 15:
                        return CycleType.TYPE_EASING;
                    default:
                        return -1;
                }
            }

            public static int getType(int name) {
                switch (name) {
                    case 100:
                    case CycleType.TYPE_CURVE_FIT /* 401 */:
                    case CycleType.TYPE_VISIBILITY /* 402 */:
                        return 2;
                    case 101:
                    case CycleType.TYPE_EASING /* 420 */:
                    case CycleType.TYPE_WAVE_SHAPE /* 421 */:
                        return 8;
                    case 304:
                    case 305:
                    case 306:
                    case 307:
                    case 308:
                    case 309:
                    case 310:
                    case 311:
                    case 312:
                    case 313:
                    case 314:
                    case 315:
                    case CycleType.TYPE_ALPHA /* 403 */:
                    case CycleType.TYPE_PATH_ROTATE /* 416 */:
                    case CycleType.TYPE_WAVE_PERIOD /* 423 */:
                    case CycleType.TYPE_WAVE_OFFSET /* 424 */:
                    case CycleType.TYPE_WAVE_PHASE /* 425 */:
                        return 4;
                    default:
                        return -1;
                }
            }
        }
    }

    /* loaded from: classes.dex */
    public interface TriggerType {
        public static final String CROSS = "CROSS";
        public static final String[] KEY_WORDS = {"viewTransitionOnCross", "viewTransitionOnPositiveCross", "viewTransitionOnNegativeCross", "postLayout", "triggerSlack", "triggerCollisionView", "triggerCollisionId", "triggerID", "positiveCross", "negativeCross", "triggerReceiver", "CROSS"};
        public static final String NAME = "KeyTrigger";
        public static final String NEGATIVE_CROSS = "negativeCross";
        public static final String POSITIVE_CROSS = "positiveCross";
        public static final String POST_LAYOUT = "postLayout";
        public static final String TRIGGER_COLLISION_ID = "triggerCollisionId";
        public static final String TRIGGER_COLLISION_VIEW = "triggerCollisionView";
        public static final String TRIGGER_ID = "triggerID";
        public static final String TRIGGER_RECEIVER = "triggerReceiver";
        public static final String TRIGGER_SLACK = "triggerSlack";
        public static final int TYPE_CROSS = 312;
        public static final int TYPE_NEGATIVE_CROSS = 310;
        public static final int TYPE_POSITIVE_CROSS = 309;
        public static final int TYPE_POST_LAYOUT = 304;
        public static final int TYPE_TRIGGER_COLLISION_ID = 307;
        public static final int TYPE_TRIGGER_COLLISION_VIEW = 306;
        public static final int TYPE_TRIGGER_ID = 308;
        public static final int TYPE_TRIGGER_RECEIVER = 311;
        public static final int TYPE_TRIGGER_SLACK = 305;
        public static final int TYPE_VIEW_TRANSITION_ON_CROSS = 301;
        public static final int TYPE_VIEW_TRANSITION_ON_NEGATIVE_CROSS = 303;
        public static final int TYPE_VIEW_TRANSITION_ON_POSITIVE_CROSS = 302;
        public static final String VIEW_TRANSITION_ON_CROSS = "viewTransitionOnCross";
        public static final String VIEW_TRANSITION_ON_NEGATIVE_CROSS = "viewTransitionOnNegativeCross";
        public static final String VIEW_TRANSITION_ON_POSITIVE_CROSS = "viewTransitionOnPositiveCross";

        /* renamed from: androidx.constraintlayout.core.motion.utils.TypedValues$TriggerType$-CC  reason: invalid class name */
        /* loaded from: classes.dex */
        public final /* synthetic */ class CC {
            static {
                String str = TriggerType.NAME;
            }

            /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
            public static int getId(String name) {
                char c;
                switch (name.hashCode()) {
                    case -1594793529:
                        if (name.equals("positiveCross")) {
                            c = '\b';
                            break;
                        }
                        c = 65535;
                        break;
                    case -966421266:
                        if (name.equals("viewTransitionOnPositiveCross")) {
                            c = 1;
                            break;
                        }
                        c = 65535;
                        break;
                    case -786670827:
                        if (name.equals("triggerCollisionId")) {
                            c = 6;
                            break;
                        }
                        c = 65535;
                        break;
                    case -648752941:
                        if (name.equals("triggerID")) {
                            c = 7;
                            break;
                        }
                        c = 65535;
                        break;
                    case -638126837:
                        if (name.equals("negativeCross")) {
                            c = '\t';
                            break;
                        }
                        c = 65535;
                        break;
                    case -76025313:
                        if (name.equals("triggerCollisionView")) {
                            c = 5;
                            break;
                        }
                        c = 65535;
                        break;
                    case -9754574:
                        if (name.equals("viewTransitionOnNegativeCross")) {
                            c = 2;
                            break;
                        }
                        c = 65535;
                        break;
                    case 64397344:
                        if (name.equals("CROSS")) {
                            c = 11;
                            break;
                        }
                        c = 65535;
                        break;
                    case 364489912:
                        if (name.equals("triggerSlack")) {
                            c = 4;
                            break;
                        }
                        c = 65535;
                        break;
                    case 1301930599:
                        if (name.equals("viewTransitionOnCross")) {
                            c = 0;
                            break;
                        }
                        c = 65535;
                        break;
                    case 1401391082:
                        if (name.equals("postLayout")) {
                            c = 3;
                            break;
                        }
                        c = 65535;
                        break;
                    case 1535404999:
                        if (name.equals("triggerReceiver")) {
                            c = '\n';
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
                        return 301;
                    case 1:
                        return 302;
                    case 2:
                        return 303;
                    case 3:
                        return 304;
                    case 4:
                        return 305;
                    case 5:
                        return 306;
                    case 6:
                        return 307;
                    case 7:
                        return 308;
                    case '\b':
                        return 309;
                    case '\t':
                        return 310;
                    case '\n':
                        return 311;
                    case 11:
                        return 312;
                    default:
                        return -1;
                }
            }
        }
    }

    /* loaded from: classes.dex */
    public interface PositionType {
        public static final String[] KEY_WORDS = {"transitionEasing", "drawPath", "percentWidth", "percentHeight", "sizePercent", "percentX", "percentY"};
        public static final String NAME = "KeyPosition";
        public static final String S_DRAWPATH = "drawPath";
        public static final String S_PERCENT_HEIGHT = "percentHeight";
        public static final String S_PERCENT_WIDTH = "percentWidth";
        public static final String S_PERCENT_X = "percentX";
        public static final String S_PERCENT_Y = "percentY";
        public static final String S_SIZE_PERCENT = "sizePercent";
        public static final String S_TRANSITION_EASING = "transitionEasing";
        public static final int TYPE_CURVE_FIT = 508;
        public static final int TYPE_DRAWPATH = 502;
        public static final int TYPE_PATH_MOTION_ARC = 509;
        public static final int TYPE_PERCENT_HEIGHT = 504;
        public static final int TYPE_PERCENT_WIDTH = 503;
        public static final int TYPE_PERCENT_X = 506;
        public static final int TYPE_PERCENT_Y = 507;
        public static final int TYPE_POSITION_TYPE = 510;
        public static final int TYPE_SIZE_PERCENT = 505;
        public static final int TYPE_TRANSITION_EASING = 501;

        /* renamed from: androidx.constraintlayout.core.motion.utils.TypedValues$PositionType$-CC  reason: invalid class name */
        /* loaded from: classes.dex */
        public final /* synthetic */ class CC {
            static {
                String str = PositionType.NAME;
            }

            /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
            public static int getId(String name) {
                char c;
                switch (name.hashCode()) {
                    case -1812823328:
                        if (name.equals("transitionEasing")) {
                            c = 0;
                            break;
                        }
                        c = 65535;
                        break;
                    case -1127236479:
                        if (name.equals("percentWidth")) {
                            c = 2;
                            break;
                        }
                        c = 65535;
                        break;
                    case -1017587252:
                        if (name.equals("percentHeight")) {
                            c = 3;
                            break;
                        }
                        c = 65535;
                        break;
                    case -827014263:
                        if (name.equals("drawPath")) {
                            c = 1;
                            break;
                        }
                        c = 65535;
                        break;
                    case -200259324:
                        if (name.equals("sizePercent")) {
                            c = 4;
                            break;
                        }
                        c = 65535;
                        break;
                    case 428090547:
                        if (name.equals("percentX")) {
                            c = 5;
                            break;
                        }
                        c = 65535;
                        break;
                    case 428090548:
                        if (name.equals("percentY")) {
                            c = 6;
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
                        return PositionType.TYPE_TRANSITION_EASING;
                    case 1:
                        return PositionType.TYPE_DRAWPATH;
                    case 2:
                        return PositionType.TYPE_PERCENT_WIDTH;
                    case 3:
                        return PositionType.TYPE_PERCENT_HEIGHT;
                    case 4:
                        return PositionType.TYPE_SIZE_PERCENT;
                    case 5:
                        return PositionType.TYPE_PERCENT_X;
                    case 6:
                        return PositionType.TYPE_PERCENT_Y;
                    default:
                        return -1;
                }
            }

            public static int getType(int name) {
                switch (name) {
                    case 100:
                    case PositionType.TYPE_CURVE_FIT /* 508 */:
                        return 2;
                    case 101:
                    case PositionType.TYPE_TRANSITION_EASING /* 501 */:
                    case PositionType.TYPE_DRAWPATH /* 502 */:
                        return 8;
                    case PositionType.TYPE_PERCENT_WIDTH /* 503 */:
                    case PositionType.TYPE_PERCENT_HEIGHT /* 504 */:
                    case PositionType.TYPE_SIZE_PERCENT /* 505 */:
                    case PositionType.TYPE_PERCENT_X /* 506 */:
                    case PositionType.TYPE_PERCENT_Y /* 507 */:
                        return 4;
                    default:
                        return -1;
                }
            }
        }
    }

    /* loaded from: classes.dex */
    public interface MotionType {
        public static final String NAME = "Motion";
        public static final int TYPE_ANIMATE_CIRCLEANGLE_TO = 606;
        public static final int TYPE_ANIMATE_RELATIVE_TO = 605;
        public static final int TYPE_DRAW_PATH = 608;
        public static final int TYPE_EASING = 603;
        public static final int TYPE_PATHMOTION_ARC = 607;
        public static final int TYPE_PATH_ROTATE = 601;
        public static final int TYPE_POLAR_RELATIVETO = 609;
        public static final int TYPE_QUANTIZE_INTERPOLATOR = 604;
        public static final int TYPE_QUANTIZE_INTERPOLATOR_ID = 612;
        public static final int TYPE_QUANTIZE_INTERPOLATOR_TYPE = 611;
        public static final int TYPE_QUANTIZE_MOTIONSTEPS = 610;
        public static final int TYPE_QUANTIZE_MOTION_PHASE = 602;
        public static final int TYPE_STAGGER = 600;
        public static final String S_STAGGER = "Stagger";
        public static final String S_PATH_ROTATE = "PathRotate";
        public static final String S_QUANTIZE_MOTION_PHASE = "QuantizeMotionPhase";
        public static final String S_EASING = "TransitionEasing";
        public static final String S_QUANTIZE_INTERPOLATOR = "QuantizeInterpolator";
        public static final String S_ANIMATE_RELATIVE_TO = "AnimateRelativeTo";
        public static final String S_ANIMATE_CIRCLEANGLE_TO = "AnimateCircleAngleTo";
        public static final String S_PATHMOTION_ARC = "PathMotionArc";
        public static final String S_DRAW_PATH = "DrawPath";
        public static final String S_POLAR_RELATIVETO = "PolarRelativeTo";
        public static final String S_QUANTIZE_MOTIONSTEPS = "QuantizeMotionSteps";
        public static final String S_QUANTIZE_INTERPOLATOR_TYPE = "QuantizeInterpolatorType";
        public static final String S_QUANTIZE_INTERPOLATOR_ID = "QuantizeInterpolatorID";
        public static final String[] KEY_WORDS = {S_STAGGER, S_PATH_ROTATE, S_QUANTIZE_MOTION_PHASE, S_EASING, S_QUANTIZE_INTERPOLATOR, S_ANIMATE_RELATIVE_TO, S_ANIMATE_CIRCLEANGLE_TO, S_PATHMOTION_ARC, S_DRAW_PATH, S_POLAR_RELATIVETO, S_QUANTIZE_MOTIONSTEPS, S_QUANTIZE_INTERPOLATOR_TYPE, S_QUANTIZE_INTERPOLATOR_ID};

        /* renamed from: androidx.constraintlayout.core.motion.utils.TypedValues$MotionType$-CC  reason: invalid class name */
        /* loaded from: classes.dex */
        public final /* synthetic */ class CC {
            static {
                String str = MotionType.NAME;
            }

            /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
            public static int getId(String name) {
                char c;
                switch (name.hashCode()) {
                    case -2033446275:
                        if (name.equals(MotionType.S_ANIMATE_CIRCLEANGLE_TO)) {
                            c = 6;
                            break;
                        }
                        c = 65535;
                        break;
                    case -1532277420:
                        if (name.equals(MotionType.S_QUANTIZE_MOTION_PHASE)) {
                            c = 2;
                            break;
                        }
                        c = 65535;
                        break;
                    case -1529145600:
                        if (name.equals(MotionType.S_QUANTIZE_MOTIONSTEPS)) {
                            c = '\n';
                            break;
                        }
                        c = 65535;
                        break;
                    case -1498310144:
                        if (name.equals(MotionType.S_PATH_ROTATE)) {
                            c = 1;
                            break;
                        }
                        c = 65535;
                        break;
                    case -1030753096:
                        if (name.equals(MotionType.S_QUANTIZE_INTERPOLATOR)) {
                            c = 4;
                            break;
                        }
                        c = 65535;
                        break;
                    case -762370135:
                        if (name.equals(MotionType.S_DRAW_PATH)) {
                            c = '\b';
                            break;
                        }
                        c = 65535;
                        break;
                    case -232872051:
                        if (name.equals(MotionType.S_STAGGER)) {
                            c = 0;
                            break;
                        }
                        c = 65535;
                        break;
                    case 1138491429:
                        if (name.equals(MotionType.S_POLAR_RELATIVETO)) {
                            c = '\t';
                            break;
                        }
                        c = 65535;
                        break;
                    case 1539234834:
                        if (name.equals(MotionType.S_QUANTIZE_INTERPOLATOR_TYPE)) {
                            c = 11;
                            break;
                        }
                        c = 65535;
                        break;
                    case 1583722451:
                        if (name.equals(MotionType.S_QUANTIZE_INTERPOLATOR_ID)) {
                            c = '\f';
                            break;
                        }
                        c = 65535;
                        break;
                    case 1639368448:
                        if (name.equals(MotionType.S_EASING)) {
                            c = 3;
                            break;
                        }
                        c = 65535;
                        break;
                    case 1900899336:
                        if (name.equals(MotionType.S_ANIMATE_RELATIVE_TO)) {
                            c = 5;
                            break;
                        }
                        c = 65535;
                        break;
                    case 2109694967:
                        if (name.equals(MotionType.S_PATHMOTION_ARC)) {
                            c = 7;
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
                        return 600;
                    case 1:
                        return 601;
                    case 2:
                        return MotionType.TYPE_QUANTIZE_MOTION_PHASE;
                    case 3:
                        return MotionType.TYPE_EASING;
                    case 4:
                        return MotionType.TYPE_QUANTIZE_INTERPOLATOR;
                    case 5:
                        return MotionType.TYPE_ANIMATE_RELATIVE_TO;
                    case 6:
                        return MotionType.TYPE_ANIMATE_CIRCLEANGLE_TO;
                    case 7:
                        return MotionType.TYPE_PATHMOTION_ARC;
                    case '\b':
                        return MotionType.TYPE_DRAW_PATH;
                    case '\t':
                        return MotionType.TYPE_POLAR_RELATIVETO;
                    case '\n':
                        return MotionType.TYPE_QUANTIZE_MOTIONSTEPS;
                    case 11:
                        return MotionType.TYPE_QUANTIZE_INTERPOLATOR_TYPE;
                    case '\f':
                        return MotionType.TYPE_QUANTIZE_INTERPOLATOR_ID;
                    default:
                        return -1;
                }
            }
        }
    }

    /* loaded from: classes.dex */
    public interface Custom {
        public static final String NAME = "Custom";
        public static final String S_INT = "integer";
        public static final int TYPE_BOOLEAN = 904;
        public static final int TYPE_COLOR = 902;
        public static final int TYPE_DIMENSION = 905;
        public static final int TYPE_FLOAT = 901;
        public static final int TYPE_INT = 900;
        public static final int TYPE_REFERENCE = 906;
        public static final int TYPE_STRING = 903;
        public static final String S_FLOAT = "float";
        public static final String S_COLOR = "color";
        public static final String S_STRING = "string";
        public static final String S_BOOLEAN = "boolean";
        public static final String S_DIMENSION = "dimension";
        public static final String S_REFERENCE = "refrence";
        public static final String[] KEY_WORDS = {S_FLOAT, S_COLOR, S_STRING, S_BOOLEAN, S_DIMENSION, S_REFERENCE};

        /* renamed from: androidx.constraintlayout.core.motion.utils.TypedValues$Custom$-CC  reason: invalid class name */
        /* loaded from: classes.dex */
        public final /* synthetic */ class CC {
            static {
                String str = Custom.NAME;
            }

            /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
            public static int getId(String name) {
                char c;
                switch (name.hashCode()) {
                    case -1095013018:
                        if (name.equals(Custom.S_DIMENSION)) {
                            c = 5;
                            break;
                        }
                        c = 65535;
                        break;
                    case -891985903:
                        if (name.equals(Custom.S_STRING)) {
                            c = 3;
                            break;
                        }
                        c = 65535;
                        break;
                    case -710953590:
                        if (name.equals(Custom.S_REFERENCE)) {
                            c = 6;
                            break;
                        }
                        c = 65535;
                        break;
                    case 64711720:
                        if (name.equals(Custom.S_BOOLEAN)) {
                            c = 4;
                            break;
                        }
                        c = 65535;
                        break;
                    case 94842723:
                        if (name.equals(Custom.S_COLOR)) {
                            c = 2;
                            break;
                        }
                        c = 65535;
                        break;
                    case 97526364:
                        if (name.equals(Custom.S_FLOAT)) {
                            c = 1;
                            break;
                        }
                        c = 65535;
                        break;
                    case 1958052158:
                        if (name.equals(Custom.S_INT)) {
                            c = 0;
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
                        return Custom.TYPE_INT;
                    case 1:
                        return Custom.TYPE_FLOAT;
                    case 2:
                        return Custom.TYPE_COLOR;
                    case 3:
                        return Custom.TYPE_STRING;
                    case 4:
                        return Custom.TYPE_BOOLEAN;
                    case 5:
                        return Custom.TYPE_DIMENSION;
                    case 6:
                        return Custom.TYPE_REFERENCE;
                    default:
                        return -1;
                }
            }
        }
    }

    /* loaded from: classes.dex */
    public interface MotionScene {
        public static final String NAME = "MotionScene";
        public static final int TYPE_DEFAULT_DURATION = 600;
        public static final int TYPE_LAYOUT_DURING_TRANSITION = 601;
        public static final String S_DEFAULT_DURATION = "defaultDuration";
        public static final String S_LAYOUT_DURING_TRANSITION = "layoutDuringTransition";
        public static final String[] KEY_WORDS = {S_DEFAULT_DURATION, S_LAYOUT_DURING_TRANSITION};

        /* renamed from: androidx.constraintlayout.core.motion.utils.TypedValues$MotionScene$-CC  reason: invalid class name */
        /* loaded from: classes.dex */
        public final /* synthetic */ class CC {
            static {
                String str = MotionScene.NAME;
            }

            public static int getType(int name) {
                switch (name) {
                    case 600:
                        return 2;
                    case 601:
                        return 1;
                    default:
                        return -1;
                }
            }

            /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
            public static int getId(String name) {
                char c;
                switch (name.hashCode()) {
                    case 6076149:
                        if (name.equals(MotionScene.S_DEFAULT_DURATION)) {
                            c = 0;
                            break;
                        }
                        c = 65535;
                        break;
                    case 1028758976:
                        if (name.equals(MotionScene.S_LAYOUT_DURING_TRANSITION)) {
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
                        return 600;
                    case 1:
                        return 601;
                    default:
                        return -1;
                }
            }
        }
    }

    /* loaded from: classes.dex */
    public interface TransitionType {
        public static final String NAME = "Transitions";
        public static final int TYPE_AUTO_TRANSITION = 704;
        public static final int TYPE_DURATION = 700;
        public static final int TYPE_FROM = 701;
        public static final int TYPE_INTERPOLATOR = 705;
        public static final int TYPE_PATH_MOTION_ARC = 509;
        public static final int TYPE_STAGGERED = 706;
        public static final int TYPE_TO = 702;
        public static final int TYPE_TRANSITION_FLAGS = 707;
        public static final String S_DURATION = "duration";
        public static final String S_FROM = "from";
        public static final String S_TO = "to";
        public static final String S_PATH_MOTION_ARC = "pathMotionArc";
        public static final String S_AUTO_TRANSITION = "autoTransition";
        public static final String S_INTERPOLATOR = "motionInterpolator";
        public static final String S_STAGGERED = "staggered";
        public static final String S_TRANSITION_FLAGS = "transitionFlags";
        public static final String[] KEY_WORDS = {S_DURATION, S_FROM, S_TO, S_PATH_MOTION_ARC, S_AUTO_TRANSITION, S_INTERPOLATOR, S_STAGGERED, S_FROM, S_TRANSITION_FLAGS};

        /* renamed from: androidx.constraintlayout.core.motion.utils.TypedValues$TransitionType$-CC  reason: invalid class name */
        /* loaded from: classes.dex */
        public final /* synthetic */ class CC {
            static {
                String str = TransitionType.NAME;
            }

            public static int getType(int name) {
                switch (name) {
                    case 509:
                    case TransitionType.TYPE_DURATION /* 700 */:
                        return 2;
                    case TransitionType.TYPE_FROM /* 701 */:
                    case TransitionType.TYPE_TO /* 702 */:
                    case TransitionType.TYPE_INTERPOLATOR /* 705 */:
                    case TransitionType.TYPE_TRANSITION_FLAGS /* 707 */:
                        return 8;
                    case TransitionType.TYPE_STAGGERED /* 706 */:
                        return 4;
                    default:
                        return -1;
                }
            }

            /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
            public static int getId(String name) {
                char c;
                switch (name.hashCode()) {
                    case -1996906958:
                        if (name.equals(TransitionType.S_TRANSITION_FLAGS)) {
                            c = 7;
                            break;
                        }
                        c = 65535;
                        break;
                    case -1992012396:
                        if (name.equals(TransitionType.S_DURATION)) {
                            c = 0;
                            break;
                        }
                        c = 65535;
                        break;
                    case -1357874275:
                        if (name.equals(TransitionType.S_INTERPOLATOR)) {
                            c = 5;
                            break;
                        }
                        c = 65535;
                        break;
                    case -1298065308:
                        if (name.equals(TransitionType.S_AUTO_TRANSITION)) {
                            c = 4;
                            break;
                        }
                        c = 65535;
                        break;
                    case 3707:
                        if (name.equals(TransitionType.S_TO)) {
                            c = 2;
                            break;
                        }
                        c = 65535;
                        break;
                    case 3151786:
                        if (name.equals(TransitionType.S_FROM)) {
                            c = 1;
                            break;
                        }
                        c = 65535;
                        break;
                    case 1310733335:
                        if (name.equals(TransitionType.S_PATH_MOTION_ARC)) {
                            c = 3;
                            break;
                        }
                        c = 65535;
                        break;
                    case 1839260940:
                        if (name.equals(TransitionType.S_STAGGERED)) {
                            c = 6;
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
                        return TransitionType.TYPE_DURATION;
                    case 1:
                        return TransitionType.TYPE_FROM;
                    case 2:
                        return TransitionType.TYPE_TO;
                    case 3:
                        return 509;
                    case 4:
                        return TransitionType.TYPE_AUTO_TRANSITION;
                    case 5:
                        return TransitionType.TYPE_INTERPOLATOR;
                    case 6:
                        return TransitionType.TYPE_STAGGERED;
                    case 7:
                        return TransitionType.TYPE_TRANSITION_FLAGS;
                    default:
                        return -1;
                }
            }
        }
    }
}
